use super::*;
#[cfg(feature = "app_api")]
use crate::tests_runtime_handlers::{
    bind_account_alias_for_test, bind_contract_alias_for_test,
    configure_multiple_dataspace_routes_for_test, configure_private_ingress_routes_for_test,
    mk_app_state_for_tests_with_world, world_with_account, world_with_account_bound_to_dataspace,
};
#[cfg(feature = "app_api")]
use iroha_data_model::nexus::UniversalAccountId;
async fn response_json(response: Response) -> Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    norito::json::from_slice(&body).expect("response body should decode as JSON")
}
#[cfg(feature = "app_api")]
const ROUTED_READ_TEST_BODY_BYTES: usize = 1024 * 1024;
#[cfg(feature = "app_api")]
fn routed_read_test_working_set_bytes() -> usize {
    routed_read_working_set_for_phase(ROUTED_READ_TEST_BODY_BYTES)
}
#[cfg(feature = "app_api")]
fn routed_read_test_budget() -> ToriiRoutedReadMemoryBudget {
    ToriiRoutedReadMemoryBudget::new(
        routed_read_test_working_set_bytes(),
        ROUTED_READ_TEST_BODY_BYTES,
    )
    .expect("routed-read test memory envelope should fit")
}
#[cfg(feature = "app_api")]
async fn response_error(response: Response) -> ErrorEnvelope {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    norito::decode_from_bytes(&body).expect("response body should decode as an error envelope")
}
pub fn configure_corrupt_inactive_autoscale_range_route_for_test(
    app: &mut SharedAppState,
) -> (LaneId, DataSpaceId) {
    let inactive_dataspace = DataSpaceId::new(1);
    let inactive_lane = LaneId::new(1);
    let lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
        NonZeroU32::new(2).expect("nonzero lane count"),
        vec![
            iroha_data_model::nexus::LaneConfig::default(),
            iroha_data_model::nexus::LaneConfig {
                id: inactive_lane,
                dataspace_id: inactive_dataspace,
                alias: "manual-elastic-slot".to_owned(),
                visibility: iroha_data_model::nexus::LaneVisibility::Public,
                ..iroha_data_model::nexus::LaneConfig::default()
            },
        ],
    )
    .expect("corrupt lane catalog");
    let dataspace_catalog = iroha_data_model::nexus::DataSpaceCatalog::new(vec![
        iroha_data_model::nexus::DataSpaceMetadata::default(),
        iroha_data_model::nexus::DataSpaceMetadata {
            id: inactive_dataspace,
            alias: "inactive".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    let mut nexus = iroha_config::parameters::actual::Nexus {
        lane_catalog,
        dataspace_catalog,
        ..iroha_config::parameters::actual::Nexus::default()
    };
    nexus.autoscale.enabled = true;
    nexus.autoscale.min_lane_id = NonZeroU32::new(1).expect("nonzero min lanes");
    nexus.autoscale.max_lane_id_exclusive = NonZeroU32::new(3).expect("nonzero max lanes");
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    let app_state = Arc::get_mut(app).expect("unique app state");
    let state = Arc::get_mut(&mut app_state.state).expect("unique state");
    state.install_synthetic_routing_snapshot_for_testing(nexus);
    (inactive_lane, inactive_dataspace)
}
#[test]
fn torii_route_resolution_rejects_inactive_autoscale_range_lane() {
    let authority = routed_read_test_account(0x7c);
    let mut app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let (inactive_lane, inactive_dataspace) =
        configure_corrupt_inactive_autoscale_range_route_for_test(&mut app);
    assert!(
        !app.state.is_lane_active_for_authority(inactive_lane),
        "fixture lane must be inactive for route authority"
    );
    let err = resolve_torii_route_for_dataspace_id(app.as_ref(), inactive_dataspace)
        .expect_err("inactive autoscale-range lane must not resolve as a Torii route");
    assert!(
        matches!(
            err,
            queue::RoutingResolveError::NoLaneForDataspace { .. }
                | queue::RoutingResolveError::LaneDataspaceMismatch { .. }
        ),
        "inactive lane routing should fail closed, got {err:?}"
    );
}
#[test]
fn torii_explicit_lane_route_rejects_inactive_autoscale_range_lane() {
    let authority = routed_read_test_account(0x7e);
    let mut app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let (inactive_lane, _) = configure_corrupt_inactive_autoscale_range_route_for_test(&mut app);
    let err = torii_route_for_lane_id(app.as_ref(), inactive_lane)
        .expect_err("explicit lane routing must not expose inactive autoscale-range lanes");
    let Error::PushIntoQueue { source, .. } = err else {
        panic!("inactive explicit lane routing should report route unavailability");
    };
    assert!(
        matches!(
            source.as_ref(),
            queue::Error::UnresolvedRoute { reason }
                if reason.contains("inactive at the current authority height")
        ),
        "unexpected inactive lane route error: {source:?}"
    );
}
#[test]
fn public_lane_route_rejects_restricted_selector_like_absent() {
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        iroha_core::state::World::default(),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    let (restricted_lane, _) = configure_private_ingress_routes_for_test(&mut app);
    let restricted_error = torii_route_for_public_lane_id(app.as_ref(), restricted_lane)
        .expect_err("public-lane route must hide a restricted lane");
    let absent_error = torii_route_for_public_lane_id(app.as_ref(), LaneId::new(999))
        .expect_err("public-lane route must reject an absent lane");
    assert!(matches!(
        restricted_error,
        Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::NotFound
        ))
    ));
    assert!(matches!(
        absent_error,
        Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::NotFound
        ))
    ));
    assert!(
        torii_route_for_public_lane_id(app.as_ref(), LaneId::SINGLE).is_ok(),
        "the active public lane remains addressable",
    );
}
#[test]
fn torii_fanout_route_discovery_excludes_inactive_autoscale_range_lane() {
    let authority = routed_read_test_account(0x7d);
    let mut app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let (inactive_lane, inactive_dataspace) =
        configure_corrupt_inactive_autoscale_range_route_for_test(&mut app);
    let routes = torii_all_dataspace_routes(app.as_ref());
    assert!(
            routes
                .iter()
                .all(|route| route.lane_id != inactive_lane
                    && route.dataspace_id != inactive_dataspace),
            "fanout route discovery must not expose inactive autoscale-range lanes: {routes:?}"
        );
    assert_eq!(
        routes,
        vec![RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)]
    );
    let public_dataspaces = torii_public_dataspace_ids(app.as_ref());
    assert!(
        !public_dataspaces.contains(&inactive_dataspace),
        "public visibility must not include dataspaces whose only public lane is inactive"
    );
}
#[test]
fn collection_ingress_and_routed_decoders_preserve_controls_and_reject_offset() {
    for (endpoint, route) in [
        (
            ToriiReadEndpointV1::AccountPermissionsGet,
            route_catalog::application_api::ACCOUNTS_BY_ACCOUNT_ID_PERMISSIONS_GET,
        ),
        (
            ToriiReadEndpointV1::AccountHistoryGet,
            route_catalog::application_api::ACCOUNTS_BY_ACCOUNT_ID_HISTORY_GET,
        ),
        (
            ToriiReadEndpointV1::AccountAssetsGet,
            route_catalog::application_api::ACCOUNTS_BY_ACCOUNT_ID_ASSETS_GET,
        ),
    ] {
        let entry =
            app_routed_read_http_endpoint(route.stable_route_id()).expect("collection admission");
        assert_eq!(entry.endpoint, AppReadHttpIdentity::Routed(endpoint));
        assert_eq!(entry.decoder, AppRoutedReadHttpDecoder::Query("ListQuery"));
        let plan = routed_read_test_budget()
            .request_decode_plan()
            .expect("decode plan");
        let query = "filter=name%20%3D%20%27permission%27&select=name&limit=17";
        let outer = list_query_from_query_string(Some(query)).expect("ingress query");
        let inner =
            decode_routed_collection_query(plan, endpoint, Some(query), &[]).expect("routed query");
        assert_eq!(outer, inner);
        assert_eq!(inner.limit, Some(17));
        for retired in ["offset=0", "count_mode=exact"] {
            assert!(list_query_from_query_string(Some(retired)).is_err());
            assert!(decode_routed_collection_query(plan, endpoint, Some(retired), &[]).is_err());
        }
    }
}
#[test]
fn collection_get_and_post_accept_the_same_control_character_literals() {
    for codepoint in [0x7f, 0x80, 0x85, 0x9f] {
        let literal = char::from_u32(codepoint).unwrap();
        let text = format!("metadata.label = \"a{literal}b\"");
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("filter", &text)
            .finish();
        let get = list_query_from_query_string(Some(&encoded)).expect("GET text literal");
        let post =
            list_query_from_json(norito::json!({"filter": text})).expect("POST text literal");
        assert_eq!(get, post);
    }
    for text in ["metadata.label = \"a\0b\"", "metadata.label = \"a\u{1f}b\""] {
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("filter", text)
            .finish();
        assert!(list_query_from_query_string(Some(&encoded)).is_err());
        assert!(list_query_from_json(norito::json!({"filter": text})).is_err());
    }
}
#[test]
fn torii_proxy_pipeline_status_query_preserves_decimal_hash_and_whitespace() {
    let hash = "11".repeat(32);
    let params = PipelineStatusQuery {
        hash: Some(format!(" {hash} ")),
        scope: Some(" local ".to_owned()),
    };
    let encoded = encode_torii_proxy_query(&params)
        .expect("pipeline-status query encoding should succeed")
        .expect("non-empty pipeline-status params should produce a query string");
    let plan = routed_read_test_budget()
        .request_decode_plan()
        .expect("request decode plan");
    let decoded = decode_torii_proxy_string_query::<PipelineStatusQuery>(plan, Some(&encoded))
        .expect("pipeline-status string query decoding should succeed");
    assert_eq!(decoded.hash, params.hash);
    assert_eq!(decoded.scope, params.scope);
}
fn checked_routed_read_test_keypair(seed: Vec<u8>, algorithm: iroha_crypto::Algorithm) -> KeyPair {
    KeyPair::try_from_seed(seed, algorithm).expect("derive routed-read fixture key")
}
fn routed_read_ed25519_test_keypair(seed: u8) -> KeyPair {
    checked_routed_read_test_keypair(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
}
fn routed_read_test_account(seed: u8) -> AccountId {
    AccountId::new(routed_read_ed25519_test_keypair(seed).public_key().clone())
}
#[test]
fn routed_read_fixture_keypair_rejects_all_zero_seed() {
    assert!(
        KeyPair::try_from_seed(vec![0; 32], iroha_crypto::Algorithm::Ed25519).is_err(),
        "checked routed-read fixtures must reject invalid Ed25519 seed material"
    );
}
#[test]
fn routed_read_test_account_uses_stable_checked_seed_material() {
    assert_eq!(
        routed_read_test_account(0x61),
        routed_read_test_account(0x61),
        "routed-read account fixtures must be stable for a fixed seed"
    );
    assert_ne!(
        routed_read_test_account(0x61),
        routed_read_test_account(0x62),
        "routed-read account fixture seeds must produce distinct accounts"
    );
}
#[test]
fn unsupported_routed_query_response_is_conflict_not_not_implemented() {
    let response = unsupported_routed_query_response("unsupported routed query shape");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("query_unsupported")
    );
}
#[cfg(not(feature = "connect"))]
#[test]
fn app_api_without_proxy_transport_fails_nonlocal_queries_closed() {
    let response = torii_proxy_transport_disabled_response(RoutingDecision::default());
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("route_unavailable")
    );
}
#[cfg(all(not(feature = "app_api"), feature = "connect"))]
#[test]
fn app_api_required_torii_proxy_response_is_route_unavailable() {
    let response = app_api_required_torii_proxy_response("Torii read proxying");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("route_unavailable")
    );
}
#[test]
fn singleton_routed_query_skips_not_found_and_route_unavailable_errors() {
    assert!(should_skip_singleton_routed_query_route_error(
        &torii_proxy_error_response(StatusCode::NOT_FOUND, "not_found", "missing")
    ));
    assert!(should_skip_singleton_routed_query_route_error(
        &torii_proxy_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "route_unavailable",
            "offline",
        )
    ));
    assert!(!should_skip_singleton_routed_query_route_error(
        &torii_proxy_error_response(StatusCode::BAD_REQUEST, "invalid", "bad request")
    ));
    let mut duplicate = torii_proxy_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "route_unavailable",
        "offline",
    );
    duplicate.headers_mut().append(
        "x-iroha-reject-code",
        axum::http::HeaderValue::from_static("route_unavailable"),
    );
    assert!(
        !should_skip_singleton_routed_query_route_error(&duplicate),
        "ambiguous duplicate reject codes must not suppress a route error"
    );
    let success_with_reject = Response::builder()
        .status(StatusCode::OK)
        .header("x-iroha-reject-code", "route_unavailable")
        .body(Body::empty())
        .expect("response");
    assert!(
        !should_skip_singleton_routed_query_route_error(&success_with_reject),
        "success responses cannot advertise a trusted reject code"
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn collect_torii_singleton_json_payloads_skips_route_unavailable_until_success() {
    let unavailable_route = RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1));
    let healthy_route = RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2));
    let expected = norito::json!({"status": {"kind": "Committed"}});
    let expected_for_closure = expected.clone();
    let collected = collect_torii_singleton_json_payloads(
        &[unavailable_route, healthy_route],
        routed_read_test_working_set_bytes(),
        ROUTED_READ_TEST_BODY_BYTES,
        move |route| {
            let expected = expected_for_closure.clone();
            async move {
                if route == unavailable_route {
                    torii_proxy_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "route_unavailable",
                        "authoritative peers offline",
                    )
                } else {
                    crate::utils::respond_value_with_format(expected, ResponseFormat::Json)
                }
            }
        },
    )
    .await
    .expect("healthy singleton payload should survive route_unavailable on another route");
    assert_eq!(collected.payloads, vec![expected]);
    assert_eq!(collected.diagnostics.attempted_routes, 2);
    assert_eq!(collected.diagnostics.succeeded_routes, 1);
    assert_eq!(collected.diagnostics.unavailable_routes, 1);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn collect_torii_singleton_json_payloads_prefers_not_found_when_no_route_succeeds() {
    let routes = [
        RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1)),
        RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2)),
    ];
    let response = collect_torii_singleton_json_payloads(
        &routes,
        routed_read_test_working_set_bytes(),
        ROUTED_READ_TEST_BODY_BYTES,
        move |route| async move {
            if route == routes[0] {
                torii_proxy_error_response(StatusCode::NOT_FOUND, "not_found", "missing")
            } else {
                torii_proxy_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "route_unavailable",
                    "authoritative peers offline",
                )
            }
        },
    )
    .await
    .expect_err("all singleton routes failing should surface a definitive not_found");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("not_found")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-attempted")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-first-failure")
            .and_then(|value| value.to_str().ok()),
        Some("not_found")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn collect_torii_singleton_json_payloads_returns_route_unavailable_when_only_unavailable() {
    let routes = [
        RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1)),
        RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2)),
    ];
    let response = collect_torii_singleton_json_payloads(
        &routes,
        routed_read_test_working_set_bytes(),
        ROUTED_READ_TEST_BODY_BYTES,
        move |_route| async move {
            torii_proxy_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "route_unavailable",
                "authoritative peers offline",
            )
        },
    )
    .await
    .expect_err("all unavailable singleton routes should surface route_unavailable");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("route_unavailable")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-unavailable")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn collect_torii_singleton_json_payloads_keeps_one_route_body_live_at_a_time() {
    let routes = [
        RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1)),
        RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2)),
    ];
    let route_count = routes.len();
    let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let collected = collect_torii_singleton_json_payloads(
        &routes,
        routed_read_test_working_set_bytes(),
        ROUTED_READ_TEST_BODY_BYTES,
        {
            let active = std::sync::Arc::clone(&active);
            move |route| {
                let active = std::sync::Arc::clone(&active);
                async move {
                    assert_eq!(
                        active.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                        0,
                        "a second route began while the prior response body was live"
                    );
                    tokio::task::yield_now().await;
                    active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    let payload =
                        crate::json_object(vec![crate::json_entry("route", route.dataspace_id)]);
                    crate::utils::respond_value_with_format(payload, ResponseFormat::Json)
                }
            }
        },
    )
    .await
    .expect("all singleton routes should succeed");
    assert_eq!(collected.payloads.len(), route_count);
    assert_eq!(collected.diagnostics.succeeded_routes, route_count);
    assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 0);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn collection_coordinator_counts_global_rows_once_across_routes() {
    use iroha_torii_shared::list_query::{AggregateFn, AggregateMetric, AggregateSpec, field};
    let authority = routed_read_test_account(0x90);
    let app = crate::tests_runtime_handlers::native_ingress_with_offline_foreign_app_for_test(
        world_with_account(&authority),
    );
    let routes = torii_all_dataspace_routes(app.as_ref());
    assert!(
        routes.len() > 1,
        "the fixture must include an offline foreign route"
    );
    let base = ListQuery::new().filter(field("id").eq(authority.to_string()));
    for aggregate in [false, true] {
        let query = if aggregate {
            base.clone().aggregate(AggregateSpec {
                group_by: vec![],
                metrics: vec![AggregateMetric {
                    alias: "accounts".into(),
                    r#fn: AggregateFn::Count,
                    field: None,
                }],
                having: None,
            })
        } else {
            base.clone().include_total()
        };
        let response = execute_torii_read_fanout_for_resolved_routes(
            &app,
            routes.clone(),
            ToriiFanoutRouteScopeV1::AllDataspaces,
            ToriiReadFanoutMergeV1::List,
            crate::ToriiReadPayload {
                endpoint: ToriiReadEndpointV1::AccountsQuery,
                path_args: vec![],
                query_string: None,
                body: collection_query_body(
                    &query,
                    routing::collection_sources::collection_execution_limits(None)
                        .expect("test collection limits")
                        .bytes,
                )
                .unwrap(),
            },
            ToriiProxyResponseFormatV1::Json,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["items"].as_array().unwrap().len(), 1);
        assert!(json["next_cursor"].is_null());
        if aggregate {
            assert_eq!(json["items"][0]["accounts"].as_u64(), Some(1));
        } else {
            assert_eq!(json["total"].as_u64(), Some(1));
        }
    }
    let response = execute_torii_read_fanout_for_resolved_routes(
        &app,
        vec![],
        ToriiFanoutRouteScopeV1::AllDataspaces,
        ToriiReadFanoutMergeV1::List,
        crate::ToriiReadPayload {
            endpoint: ToriiReadEndpointV1::AccountsQuery,
            path_args: vec![],
            query_string: None,
            body: collection_query_body(
                &base.include_total(),
                routing::collection_sources::collection_limits().bytes,
            )
            .unwrap(),
        },
        ToriiProxyResponseFormatV1::Json,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert!(json["items"].as_array().unwrap().is_empty());
    assert_eq!(json["total"].as_u64(), Some(0));
    assert!(json["next_cursor"].is_null());
}

#[cfg(feature = "app_api")]
#[tokio::test]
async fn empty_collection_response_only_counts_when_requested() {
    for include_total in [false, true] {
        let response = empty_collection_page_response("local", include_total);
        let json = response_json(response).await;
        assert!(json["items"].as_array().unwrap().is_empty());
        assert!(json["next_cursor"].is_null());
        assert_eq!(
            json.get("total").and_then(Value::as_u64),
            include_total.then_some(0)
        );
    }
}

#[cfg(feature = "app_api")]
#[tokio::test]
async fn execute_account_history_single_route_returns_shared_page() {
    let authority = routed_read_test_account(0x91);
    let app = crate::tests_runtime_handlers::native_ingress_with_offline_foreign_app_for_test(
        world_with_account(&authority),
    );
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    assert!(
        is_local_authoritative_for_route(app.as_ref(), route),
        "the local-read fixture must be a current member of the exact committee"
    );
    let response = execute_collection_on_route(
        &app,
        route,
        ToriiFanoutRouteScopeV1::AllDataspaces,
        ToriiReadEndpointV1::AccountHistoryQuery,
        vec![authority.to_string()],
        collection_query_body(
            &ListQuery::new().limit(10),
            routing::collection_sources::collection_execution_limits(None)
                .expect("test collection limits")
                .bytes,
        )
        .expect("query body"),
        try_acquire_query_fanout_memory(&app).expect("full owner"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert!(json["items"].as_array().is_some());
    assert!(json["next_cursor"].is_null());
    for retired in [
        "query_source",
        "indexed_height",
        "indexed_block_hash",
        "count_mode",
        "has_more",
    ] {
        assert!(
            json.get(retired).is_none(),
            "retired envelope field {retired}"
        );
    }
}
#[cfg(feature = "app_api")]
#[test]
fn merged_list_response_rejects_array_payloads_from_legacy_list_handlers() {
    let payloads = vec![
        norito::json!([{"id": "alpha"}]),
        norito::json!([{"id": "alpha"}, {"id": "beta"}]),
    ];
    let response = merged_list_response(
        payloads,
        ToriiReadEndpointV1::AccountAssetsGet,
        "fanout",
        routed_read_test_budget(),
    )
    .expect_err("legacy raw-array list payloads must fail closed");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("invalid_proxy_response")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn with_torii_fanout_headers_adds_warning_for_successful_alias_responses_with_denied_routes()
{
    let mut diagnostics = ToriiFanoutDiagnostics::default();
    diagnostics.record_denied();
    diagnostics.record_attempt();
    diagnostics.record_success();
    let response = with_torii_fanout_headers(
        crate::utils::respond_value_with_format(norito::json!({"ok": true}), ResponseFormat::Json),
        diagnostics,
    );
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::WARNING)
            .and_then(|value| value.to_str().ok()),
        Some(r#"199 - "one or more alias routes were denied""#)
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-attempted")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-denied")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn with_torii_fanout_headers_does_not_add_warning_for_failed_alias_responses() {
    let mut diagnostics = ToriiFanoutDiagnostics::default();
    diagnostics.record_denied();
    let response = with_torii_fanout_headers(
        torii_alias_permission_denied_response("alias fanout denied"),
        diagnostics,
    );
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        response
            .headers()
            .get(axum::http::header::WARNING)
            .is_none(),
        "warning headers should only be added to successful responses"
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn collect_torii_alias_json_payloads_returns_permission_denied_when_only_synthetic_denials_exist()
 {
    let routes: &[RoutingDecision] = &[];
    let response = collect_torii_alias_json_payloads(
        routes,
        2,
        "alias fanout denied",
        routed_read_test_working_set_bytes(),
        ROUTED_READ_TEST_BODY_BYTES,
        |_route: RoutingDecision| async move {
            crate::utils::respond_value_with_format(norito::json!({}), ResponseFormat::Json)
        },
    )
    .await
    .expect_err("synthetic denied routes without an allowed route should fail closed");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-denied")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-first-failure")
            .and_then(|value| value.to_str().ok()),
        Some("permission_denied")
    );
    let error = response_error(response).await;
    assert_eq!(error.code(), "permission_denied");
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn collect_torii_alias_json_payloads_returns_not_found_when_no_visible_routes_remain() {
    let authority = routed_read_test_account(0x92);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&authority),
        crate::tests_runtime_handlers::private_ingress_with_offline_foreign_nexus_for_test(),
    );
    let (restricted_route, _) =
        crate::tests_runtime_handlers::configure_private_ingress_with_offline_foreign_route_for_test(&mut app);
    let (routes, denied_routes) =
        torii_partition_alias_index_routes_by_permission(&app, vec![restricted_route], None, 0)
            .expect("anonymous visibility removes the restricted route");
    assert!(routes.is_empty());
    assert_eq!(denied_routes, 0);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let response = collect_torii_alias_json_payloads(
        &routes,
        denied_routes,
        "alias fanout denied",
        routed_read_test_working_set_bytes(),
        ROUTED_READ_TEST_BODY_BYTES,
        {
            let calls = Arc::clone(&calls);
            move |_route: RoutingDecision| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    crate::utils::respond_value_with_format(norito::json!({}), ResponseFormat::Json)
                }
            }
        },
    )
    .await
    .expect_err("a route hidden from an anonymous lookup is no visible match");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("not_found")
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn collect_torii_alias_json_payloads_prefers_explicit_permission_denied_when_no_route_resolves()
 {
    let routes = [
        RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1)),
        RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2)),
    ];
    let response = collect_torii_alias_json_payloads(
        &routes,
        0,
        "alias fanout denied",
        routed_read_test_working_set_bytes(),
        ROUTED_READ_TEST_BODY_BYTES,
        move |route| async move {
            if route == routes[0] {
                torii_alias_permission_denied_response("routed dataspace blocked the lookup")
            } else {
                torii_proxy_error_response(StatusCode::NOT_FOUND, "not_found", "missing")
            }
        },
    )
    .await
    .expect_err("a routed permission denial should outrank misses when no route succeeds");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-denied")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-not-found")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    let error = response_error(response).await;
    assert_eq!(error.code(), "permission_denied");
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn collect_torii_alias_json_payloads_keeps_success_when_other_routes_are_denied() {
    let routes = [
        RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1)),
        RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2)),
    ];
    let expected = norito::json!({
        "account_id": "alice.i105.invalid",
        "total": 1,
        "items": [{
            "alias": "merchant@paynet",
            "dataspace": "paynet",
            "domain": null,
            "is_primary": true
        }],
        "source": "on_chain"
    });
    let collected = collect_torii_alias_json_payloads(
        &routes,
        0,
        "alias fanout denied",
        routed_read_test_working_set_bytes(),
        ROUTED_READ_TEST_BODY_BYTES,
        move |route| {
            let expected = expected.clone();
            async move {
                if route == routes[0] {
                    torii_alias_permission_denied_response("routed dataspace blocked the lookup")
                } else {
                    crate::utils::respond_value_with_format(expected, ResponseFormat::Json)
                }
            }
        },
    )
    .await
    .expect("successful alias payload should survive denied sibling routes");
    assert_eq!(collected.payloads.len(), 1);
    assert_eq!(collected.diagnostics.attempted_routes, 3);
    assert_eq!(collected.diagnostics.succeeded_routes, 1);
    assert_eq!(collected.diagnostics.denied_routes, 1);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn collect_torii_alias_json_payloads_prefers_not_found_over_route_unavailable_when_no_route_succeeds()
 {
    let routes = [
        RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1)),
        RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2)),
    ];
    let response = collect_torii_alias_json_payloads(
        &routes,
        0,
        "alias fanout denied",
        routed_read_test_working_set_bytes(),
        ROUTED_READ_TEST_BODY_BYTES,
        move |route| async move {
            if route == routes[0] {
                torii_proxy_error_response(StatusCode::NOT_FOUND, "not_found", "missing")
            } else {
                torii_proxy_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "route_unavailable",
                    "authoritative peers offline",
                )
            }
        },
    )
    .await
    .expect_err("not_found should outrank route_unavailable when no alias route succeeds");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-not-found")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-unavailable")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn collect_torii_alias_json_payloads_returns_route_unavailable_when_only_unavailable() {
    let routes = [
        RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1)),
        RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2)),
    ];
    let response = collect_torii_alias_json_payloads(
        &routes,
        0,
        "alias fanout denied",
        routed_read_test_working_set_bytes(),
        ROUTED_READ_TEST_BODY_BYTES,
        move |_route| async move {
            torii_proxy_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "route_unavailable",
                "authoritative peers offline",
            )
        },
    )
    .await
    .expect_err("all unavailable alias routes should surface route_unavailable");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("route_unavailable")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-unavailable")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn routed_contract_views_require_bound_caller() {
    let authority = routed_read_test_account(0xb5);
    let other = routed_read_test_account(0xb6);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    for endpoint in [
        ToriiReadEndpointV1::ContractViewPost,
        ToriiReadEndpointV1::ContractViewBatchPost,
    ] {
        let body = if endpoint == ToriiReadEndpointV1::ContractViewPost {
            norito::json!({"authority": (authority.to_string()), "entrypoint": "view", "gas_limit": 1})
        } else {
            norito::json!({"authority": (authority.to_string()), "items": []})
        };
        let body = norito::json::to_vec(&body).expect("request JSON");
        for (scope, expected) in [
            (
                ToriiFanoutRouteScopeV1::VisibleAccount {
                    caller_account_id: None,
                },
                StatusCode::FORBIDDEN,
            ),
            (
                ToriiFanoutRouteScopeV1::VisibleAccount {
                    caller_account_id: Some(other.to_string()),
                },
                StatusCode::FORBIDDEN,
            ),
            (
                ToriiFanoutRouteScopeV1::AllDataspaces,
                StatusCode::FORBIDDEN,
            ),
            (
                ToriiFanoutRouteScopeV1::TargetAccount {
                    account_id: authority.to_string(),
                    caller_account_id: Some(authority.to_string()),
                },
                StatusCode::FORBIDDEN,
            ),
            (
                ToriiFanoutRouteScopeV1::VisibleAccount {
                    caller_account_id: Some(authority.to_string()),
                },
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let response = execute_torii_read_request_locally(
                &app,
                torii_read_request(endpoint, scope, route, Vec::new(), None, body.clone()),
                route,
                "proxy",
            )
            .await;
            assert_eq!(
                response.status(),
                expected,
                "{endpoint:?}: only the exact ingress-authenticated caller reaches ordinary request validation"
            );
        }
    }
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn protected_contract_views_ignore_unsigned_public_upstream() {
    let authority = routed_read_test_account(0xb7);
    let mut app = crate::tests_runtime_handlers::native_ingress_with_offline_foreign_app_for_test(
        world_with_account(&authority),
    );
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .public_dataspace_upstreams = Arc::new(BTreeMap::from([(
        DataSpaceId::UNIVERSAL,
        "http://127.0.0.1:9".to_owned(),
    )]));
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    assert!(is_local_authoritative_for_route(app.as_ref(), route));
    for endpoint in [
        ToriiReadEndpointV1::ContractViewPost,
        ToriiReadEndpointV1::ContractViewBatchPost,
    ] {
        let body = if endpoint == ToriiReadEndpointV1::ContractViewPost {
            norito::json!({"authority": (authority.to_string()), "entrypoint": "view", "gas_limit": 1})
        } else {
            norito::json!({"authority": (authority.to_string()), "items": []})
        };
        let response = execute_torii_single_route_read_with_format(
            &app,
            route,
            crate::ToriiReadPayload {
                endpoint,
                path_args: Vec::new(),
                query_string: None,
                body: norito::json::to_vec(&body).expect("request JSON"),
            },
            ToriiProxyResponseFormatV1::Json,
            Some(&authority),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "exact caller must survive routing and reach local request validation"
        );
        assert_eq!(
            response
                .headers()
                .get("x-iroha-routed-by")
                .and_then(|value| value.to_str().ok()),
            Some("local")
        );
    }
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn execute_torii_read_request_locally_alias_resolve_rejects_invalid_proxy_body() {
    let authority = routed_read_test_account(0x81);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    let response = execute_torii_read_request_locally(
        &app,
        torii_read_request(
            ToriiReadEndpointV1::AliasResolve,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            route,
            Vec::new(),
            None,
            b"{".to_vec(),
        ),
        route,
        "local",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("invalid_proxy_request")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn execute_torii_read_request_locally_alias_resolve_index_rejects_invalid_proxy_body() {
    let authority = routed_read_test_account(0x82);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    let response = execute_torii_read_request_locally(
        &app,
        torii_read_request(
            ToriiReadEndpointV1::AliasResolveIndex,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            route,
            Vec::new(),
            None,
            b"{".to_vec(),
        ),
        route,
        "local",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("invalid_proxy_request")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn execute_torii_read_request_locally_alias_lookup_by_account_rejects_invalid_proxy_body() {
    let authority = routed_read_test_account(0x83);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    let response = execute_torii_read_request_locally(
        &app,
        torii_read_request(
            ToriiReadEndpointV1::AliasLookupByAccount,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            route,
            Vec::new(),
            None,
            b"{".to_vec(),
        ),
        route,
        "local",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("invalid_proxy_request")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn execute_torii_read_request_locally_alias_resolve_uses_route_local_alias() {
    let authority = routed_read_test_account(0x84);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    bind_account_alias_for_test(&app, &authority, "merchant@universal");
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    let body = norito::json::to_vec(&routing::AliasResolveRequestDto {
        alias: "merchant@universal".to_string(),
    })
    .expect("encode request");
    let response = execute_torii_read_request_locally(
        &app,
        torii_read_request(
            ToriiReadEndpointV1::AliasResolve,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            route,
            Vec::new(),
            None,
            body,
        ),
        route,
        "local",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-routed-by")
            .and_then(|value| value.to_str().ok()),
        Some("local")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-route-dataspace-id")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let payload: routing::AliasResolveResponseDto =
        norito::json::from_slice(&body).expect("alias-resolve response");
    assert_eq!(payload.alias, "merchant@universal");
    assert_eq!(payload.account_id, authority.to_string());
    assert_eq!(payload.source.as_deref(), Some("active_sns"));
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn routed_alias_resolve_sanitizer_rejects_forged_account_payload() {
    let authority = routed_read_test_account(0x94);
    let forged = routed_read_test_account(0x95);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    bind_account_alias_for_test(&app, &authority, "merchant@universal");
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    let request_body = norito::json::to_vec(&routing::AliasResolveRequestDto {
        alias: "merchant@universal".to_owned(),
    })
    .expect("encode request");
    let forged_body = norito::json::to_vec(&routing::AliasResolveResponseDto {
        alias: "merchant@universal".to_owned(),
        account_id: forged.to_string(),
        index: None,
        source: Some("active_sns".to_owned()),
    })
    .expect("encode forged response");
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(forged_body))
        .expect("forged response");
    let response = sanitize_exact_alias_route_response(
        &app,
        route,
        ToriiReadEndpointV1::AliasResolve,
        &request_body,
        response,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("invalid_proxy_response")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn routed_alias_index_sanitizer_rejects_mismatched_alias_payload() {
    let authority = routed_read_test_account(0x96);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    bind_account_alias_for_test(&app, &authority, "merchant@universal");
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    let request_body = norito::json::to_vec(&routing::AliasResolveIndexRequestDto { index: 0 })
        .expect("encode request");
    let forged_body = norito::json::to_vec(&routing::AliasResolveIndexResponseDto {
        index: 0,
        alias: "attacker@universal".to_owned(),
        account_id: authority.to_string(),
        source: Some("active_sns".to_owned()),
    })
    .expect("encode forged response");
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(forged_body))
        .expect("forged response");
    let response = sanitize_exact_alias_route_response(
        &app,
        route,
        ToriiReadEndpointV1::AliasResolveIndex,
        &request_body,
        response,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("invalid_proxy_response")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn routed_contract_alias_sanitizer_rejects_forged_subject_payload() {
    let authority = routed_read_test_account(0x98);
    let forged_subject = routed_read_test_account(0x99);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &authority,
        0,
        DataSpaceId::UNIVERSAL,
    )
    .expect("contract address");
    bind_contract_alias_for_test(&app, &contract_address, "router::universal");
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    let request_body = norito::json::to_vec(&routing::ContractAliasResolveRequestDto {
        contract_alias: "router::universal".to_owned(),
    })
    .expect("encode request");
    let forged_body = norito::json::to_vec(&routing::ContractAliasResolveResponseDto {
        contract_alias: "router::universal".to_owned(),
        contract_address: contract_address.to_string(),
        contract_subject_account: forged_subject.to_string(),
        dataspace: "universal".to_owned(),
        contract_alias_binding: routing::ContractAliasBindingDto {
            alias: "router::universal".to_owned(),
            status: "permanent".to_owned(),
            lease_expiry_ms: None,
            grace_until_ms: None,
            bound_at_ms: 0,
        },
        source: "world_state".to_owned(),
    })
    .expect("encode forged response");
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(forged_body))
        .expect("forged response");
    let response = sanitize_exact_alias_route_response(
        &app,
        route,
        ToriiReadEndpointV1::ContractAliasResolve,
        &request_body,
        response,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("invalid_proxy_response")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn protected_alias_reads_ignore_unsigned_public_upstream() {
    let authority = routed_read_test_account(0x97);
    let mut app = crate::tests_runtime_handlers::native_ingress_with_offline_foreign_app_for_test(
        world_with_account(&authority),
    );
    bind_account_alias_for_test(&app, &authority, "merchant@universal");
    let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
        app.state.network_id_ref(),
        &authority,
        1,
        DataSpaceId::UNIVERSAL,
    )
    .expect("contract address");
    bind_contract_alias_for_test(&app, &contract_address, "router::universal");
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .public_dataspace_upstreams = Arc::new(BTreeMap::from([(
        DataSpaceId::UNIVERSAL,
        "http://127.0.0.1:9".to_owned(),
    )]));
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    assert!(
        is_local_authoritative_for_route(app.as_ref(), route),
        "the local-read fixture must be a current member of the exact committee"
    );
    let body = norito::json::to_vec(&routing::AliasResolveIndexRequestDto { index: 0 })
        .expect("encode request");
    let response = execute_torii_read_for_route(
        &app,
        route,
        torii_read_request(
            ToriiReadEndpointV1::AliasResolveIndex,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            route,
            Vec::new(),
            None,
            body,
        ),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-routed-by")
            .and_then(|value| value.to_str().ok()),
        Some("local")
    );
    for (endpoint, body) in [
        (
            ToriiReadEndpointV1::AliasResolve,
            norito::json::to_vec(&routing::AliasResolveRequestDto {
                alias: "merchant@universal".to_owned(),
            })
            .expect("encode alias request"),
        ),
        (
            ToriiReadEndpointV1::ContractAliasResolve,
            norito::json::to_vec(&routing::ContractAliasResolveRequestDto {
                contract_alias: "router::universal".to_owned(),
            })
            .expect("encode contract alias request"),
        ),
    ] {
        let response = execute_torii_read_for_route(
            &app,
            route,
            torii_read_request(
                endpoint,
                ToriiFanoutRouteScopeV1::AllDataspaces,
                route,
                Vec::new(),
                None,
                body,
            ),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-iroha-routed-by")
                .and_then(|value| value.to_str().ok()),
            Some("local")
        );
    }
}
#[cfg(feature = "app_api")]
#[test]
fn exact_alias_resolve_rejects_expired_authoritative_lease() {
    let authority = routed_read_test_account(0x98);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let alias_literal = "merchant@universal";
    bind_account_alias_for_test(&app, &authority, alias_literal);
    let catalog = app.state.nexus_snapshot().dataspace_catalog;
    let alias = AccountAlias::from_literal(alias_literal, &catalog).expect("account alias");
    let selector = iroha_core::sns::selector_for_account_alias(&alias, &catalog)
        .expect("account alias selector");
    let account_address = AccountAddress::from_account_id(&authority).expect("account address");
    let expired = iroha_data_model::sns::NameRecordV1::new(
        selector.clone(),
        authority.clone(),
        vec![iroha_data_model::sns::NameControllerV1::account(
            &account_address,
        )],
        0,
        0,
        1,
        1,
        1,
        iroha_model_base::metadata::Metadata::default(),
    );
    let height = app
        .state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let header = BlockHeader::new(
        std::num::NonZeroU64::new(height).expect("nonzero height"),
        None,
        None,
        2,
        0,
    );
    let observation_header = header;
    let mut block = app.state.block(observation_header);
    let mut tx = block.transaction();
    tx.world_mut_for_testing()
        .smart_contract_state_mut_for_testing()
        .insert(
            iroha_core::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&expired),
        );
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit expired alias lease");
    app.state
        .update_latest_block_header_cache_for_tests(observation_header);
    assert_eq!(routing::asset_alias_observation_time_ms(&app.state), 2);
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    let response = execute_alias_resolve_local_read(
        &app,
        route,
        &routing::AliasResolveRequestDto {
            alias: alias_literal.to_owned(),
        },
    )
    .expect("expired alias should produce a not-found response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[cfg(feature = "app_api")]
#[test]
fn exact_alias_resolve_rejects_rekey_index_split_brain() {
    let authority = routed_read_test_account(0x99);
    let forged = routed_read_test_account(0x9a);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let alias_literal = "merchant@universal";
    bind_account_alias_for_test(&app, &authority, alias_literal);
    let alias =
        AccountAlias::from_literal(alias_literal, &app.state.nexus_snapshot().dataspace_catalog)
            .expect("account alias");
    let height = app
        .state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let header = BlockHeader::new(
        std::num::NonZeroU64::new(height).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    tx.world_mut_for_testing()
        .replace_account_rekey_record_for_testing(
            iroha_data_model::account::rekey::AccountRekeyRecord::new(alias, forged),
        );
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit split-brain rekey record");
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    let response = execute_alias_resolve_local_read(
        &app,
        route,
        &routing::AliasResolveRequestDto {
            alias: alias_literal.to_owned(),
        },
    )
    .expect("split-brain alias should produce a not-found response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn execute_torii_read_request_locally_alias_resolve_index_uses_route_local_index() {
    let authority = routed_read_test_account(0x85);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&authority),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    configure_multiple_dataspace_routes_for_test(&mut app);
    bind_account_alias_for_test(&app, &authority, "merchant@universal");
    bind_account_alias_for_test(&app, &authority, "merchant@secondary");
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::new(1))
        .expect("secondary route");
    let body = norito::json::to_vec(&routing::AliasResolveIndexRequestDto { index: 0 })
        .expect("encode request");
    let response = execute_torii_read_request_locally(
        &app,
        torii_read_request(
            ToriiReadEndpointV1::AliasResolveIndex,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            route,
            Vec::new(),
            None,
            body,
        ),
        route,
        "local",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-routed-by")
            .and_then(|value| value.to_str().ok()),
        Some("local")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-route-dataspace-id")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let payload: routing::AliasResolveIndexResponseDto =
        norito::json::from_slice(&body).expect("alias-index response");
    assert_eq!(payload.index, 0);
    assert_eq!(payload.alias, "merchant@secondary");
    assert_eq!(payload.account_id, authority.to_string());
    assert_eq!(payload.source.as_deref(), Some("active_sns"));
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn execute_alias_resolve_index_local_read_returns_not_found_for_route_without_aliases() {
    let authority = routed_read_test_account(0x86);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&authority),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    configure_multiple_dataspace_routes_for_test(&mut app);
    bind_account_alias_for_test(&app, &authority, "merchant@secondary");
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    let response = execute_alias_resolve_index_local_read(
        &app,
        route,
        &routing::AliasResolveIndexRequestDto { index: 0 },
    )
    .expect("route-local alias-index read should return a response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn execute_torii_read_request_locally_alias_lookup_by_account_filters_items_to_route_dataspace()
 {
    let authority = routed_read_test_account(0x87);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&authority),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    configure_multiple_dataspace_routes_for_test(&mut app);
    bind_account_alias_for_test(&app, &authority, "merchant@universal");
    bind_account_alias_for_test(&app, &authority, "merchant@secondary");
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::new(1))
        .expect("secondary route");
    let body = norito::json::to_vec(&routing::AliasLookupByAccountRequestDto {
        account_id: authority.to_string(),
        dataspace: None,
        domain: None,
    })
    .expect("encode request");
    let response = execute_torii_read_request_locally(
        &app,
        torii_read_request(
            ToriiReadEndpointV1::AliasLookupByAccount,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            route,
            Vec::new(),
            None,
            body,
        ),
        route,
        "local",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-route-dataspace-id")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let payload: routing::AliasLookupByAccountResponseDto =
        norito::json::from_slice(&body).expect("alias by-account response");
    assert_eq!(payload.account_id, authority.to_string());
    assert_eq!(payload.total, 1);
    assert_eq!(payload.items.len(), 1);
    assert_eq!(payload.items[0].alias, "merchant@secondary");
    assert_eq!(payload.items[0].dataspace, "secondary");
    assert_eq!(payload.source.as_deref(), Some("on_chain"));
}
#[cfg(feature = "app_api")]
#[test]
fn execute_alias_resolve_local_read_rejects_empty_alias() {
    let authority = routed_read_test_account(0x88);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    for (alias, expected) in [
        ("", "account alias must not be empty"),
        (
            "   ",
            "account alias must not contain leading or trailing whitespace",
        ),
    ] {
        let err = execute_alias_resolve_local_read(
            &app,
            route,
            &routing::AliasResolveRequestDto {
                alias: alias.to_owned(),
            },
        )
        .expect_err("empty and whitespace aliases must be rejected before local execution");
        match err {
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
            )) => assert_eq!(message, expected),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
#[cfg(feature = "app_api")]
#[test]
fn execute_alias_resolve_local_read_returns_not_found_for_route_mismatch() {
    let authority = routed_read_test_account(0x89);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&authority),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    configure_multiple_dataspace_routes_for_test(&mut app);
    bind_account_alias_for_test(&app, &authority, "merchant@secondary");
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    let response = execute_alias_resolve_local_read(
        &app,
        route,
        &routing::AliasResolveRequestDto {
            alias: "merchant@secondary".to_string(),
        },
    )
    .expect("route-mismatched local alias resolve should return a response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[cfg(feature = "app_api")]
#[test]
fn execute_alias_lookup_by_account_local_read_rejects_empty_account_id() {
    let authority = routed_read_test_account(0x8a);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    let err = execute_alias_lookup_by_account_local_read(
        &app,
        route,
        &routing::AliasLookupByAccountRequestDto {
            account_id: " ".to_string(),
            dataspace: None,
            domain: None,
        },
    )
    .expect_err("empty account ids should be rejected before local execution");
    match err {
        Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
        )) => assert_eq!(message, "account_id must not be empty"),
        other => panic!("unexpected error: {other:?}"),
    }
}
#[cfg(feature = "app_api")]
#[test]
fn execute_alias_lookup_by_account_local_read_rejects_invalid_account_id() {
    let authority = routed_read_test_account(0x8b);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    let err = execute_alias_lookup_by_account_local_read(
        &app,
        route,
        &routing::AliasLookupByAccountRequestDto {
            account_id: "not-an-account".to_string(),
            dataspace: None,
            domain: None,
        },
    )
    .expect_err("invalid account ids should be rejected before route-local lookup");
    match err {
        Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
        )) => assert!(
            message.starts_with("invalid account_id:"),
            "unexpected conversion message: {message}"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn execute_alias_lookup_by_account_local_read_returns_empty_items_when_route_filters_out_aliases()
 {
    let authority = routed_read_test_account(0x8c);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&authority),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    configure_multiple_dataspace_routes_for_test(&mut app);
    bind_account_alias_for_test(&app, &authority, "merchant@secondary");
    let route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("universal route");
    let response = execute_alias_lookup_by_account_local_read(
            &app,
            route,
            &routing::AliasLookupByAccountRequestDto {
                account_id: authority.to_string(),
                dataspace: None,
                domain: None,
            },
        )
        .expect("route-local alias-by-account should return an empty payload when filters remove every alias");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let payload: routing::AliasLookupByAccountResponseDto =
        norito::json::from_slice(&body).expect("alias by-account response");
    assert_eq!(payload.account_id, authority.to_string());
    assert_eq!(payload.total, 0);
    assert!(payload.items.is_empty());
    assert_eq!(payload.source.as_deref(), Some("on_chain"));
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn torii_partition_routes_by_visibility_counts_private_dataspaces_as_denied_for_unsigned_reads()
 {
    let authority = routed_read_test_account(0x8d);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::partition-unsigned"));
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account_bound_to_dataspace(&authority, uaid, DataSpaceId::new(10)),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    configure_private_ingress_routes_for_test(&mut app);
    let (allowed_routes, denied_routes) = torii_partition_routes_by_visibility(
        &app,
        torii_all_dataspace_routes(app.as_ref()),
        &ToriiAccountReadVisibility::None,
    );
    let dataspaces = allowed_routes
        .into_iter()
        .map(|route| route.dataspace_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        dataspaces,
        std::collections::BTreeSet::from([DataSpaceId::UNIVERSAL, DataSpaceId::new(1)])
    );
    assert_eq!(denied_routes, 1);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn torii_visibility_account_from_headers_rejects_unsigned_account_header() {
    let key_pair = routed_read_ed25519_test_keypair(0x8e);
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let method = Method::GET;
    let uri: Uri = format!("/v1/accounts/{authority}/transactions")
        .parse()
        .expect("valid URI");
    let mut headers = HeaderMap::new();
    headers.insert(
        HEADER_ACCOUNT,
        authority
            .to_canonical_hex()
            .expect("canonical account header")
            .parse()
            .expect("account header"),
    );
    let err = torii_visibility_account_from_headers(
        &app,
        &headers,
        &method,
        &uri,
        &[],
        routing::ENDPOINT_ACCOUNTS_TRANSACTIONS,
    )
    .expect_err("bare account headers must not create caller identity");
    let Error::AppUnauthorized { code, message } = err else {
        panic!("bare identity must be reported as authentication failure")
    };
    assert_eq!(code, "alias_auth_invalid");
    assert!(message.contains("complete canonical request signature"));
}
#[cfg(feature = "app_api")]
#[test]
fn torii_visibility_account_from_headers_rejects_partial_signature_as_unauthorized() {
    let authority = routed_read_test_account(0x8f);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let method = Method::GET;
    let uri: Uri = "/v1/explorer/transactions".parse().expect("valid URI");
    let mut headers = HeaderMap::new();
    headers.insert(HEADER_SIGNATURE, HeaderValue::from_static("00"));
    let err = torii_visibility_account_from_headers(
        &app,
        &headers,
        &method,
        &uri,
        &[],
        routing::ENDPOINT_EXPLORER_TRANSACTIONS,
    )
    .expect_err("partial canonical auth must not degrade to anonymous access");
    let Error::AppUnauthorized { code, .. } = &err else {
        panic!("partial canonical auth must be reported as authentication failure")
    };
    assert_eq!(*code, "canonical_authentication_invalid");
    assert_eq!(err.into_response().status(), StatusCode::UNAUTHORIZED);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn torii_visibility_account_from_headers_accepts_signed_caller() {
    let key_pair = routed_read_ed25519_test_keypair(0x90);
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let method = Method::GET;
    let uri: Uri = format!("/v1/accounts/{authority}/transactions")
        .parse()
        .expect("valid URI");
    let headers = crate::tests_runtime_handlers::signed_app_headers(
        &authority,
        &key_pair,
        &method,
        &uri,
        &[],
    );
    let visibility = torii_visibility_account_from_headers(
        &app,
        &headers,
        &method,
        &uri,
        &[],
        routing::ENDPOINT_ACCOUNTS_TRANSACTIONS,
    )
    .expect("signed account headers should verify");
    match visibility {
        ToriiAccountReadVisibility::Signed(account) => assert_eq!(account, authority),
        other => panic!("unexpected visibility: {other:?}"),
    }
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn torii_partition_routes_by_visibility_allows_bound_private_dataspaces_for_signed_caller() {
    let authority = routed_read_test_account(0x90);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::partition-caller"));
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account_bound_to_dataspace(&authority, uaid, DataSpaceId::new(10)),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    configure_private_ingress_routes_for_test(&mut app);
    let (allowed_routes, denied_routes) = torii_partition_routes_by_visibility(
        &app,
        torii_all_dataspace_routes(app.as_ref()),
        &ToriiAccountReadVisibility::Signed(authority.clone()),
    );
    let dataspaces = allowed_routes
        .into_iter()
        .map(|route| route.dataspace_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        dataspaces,
        std::collections::BTreeSet::from([
            DataSpaceId::UNIVERSAL,
            DataSpaceId::new(1),
            DataSpaceId::new(10),
        ])
    );
    assert_eq!(denied_routes, 0);
}
#[tokio::test]
async fn merged_list_response_deduplicates_items_and_sets_total() {
    let response = merged_list_response(
        vec![
            norito::json!({
                "items": [{"id": "a"}, {"id": "b"}],
                "total": 2
            }),
            norito::json!({
                "items": [{"id": "b"}, {"id": "c"}],
                "total": 2
            }),
        ],
        ToriiReadEndpointV1::AccountAssetsGet,
        "proxy",
        routed_read_test_budget(),
    )
    .expect("list merge should succeed");
    assert_eq!(
        response
            .headers()
            .get("x-iroha-routed-by")
            .expect("routed-by header should be present"),
        "proxy"
    );
    let json = response_json(response).await;
    let items = json["items"]
        .as_array()
        .expect("merged response should include items");
    let ids: Vec<&str> = items
        .iter()
        .map(|item| item["id"].as_str().expect("each item should have an id"))
        .collect();
    assert_eq!(ids, vec!["a", "b", "c"]);
    assert_eq!(json["total"].as_u64(), Some(3));
}
#[tokio::test]
async fn merged_list_response_preserves_first_seen_order() {
    let response = merged_list_response(
        vec![
            norito::json!({
                "items": [{"id": "b"}, {"id": "a"}],
                "total": 2
            }),
            norito::json!({
                "items": [{"id": "a"}, {"id": "c"}],
                "total": 2
            }),
        ],
        ToriiReadEndpointV1::AccountAssetsGet,
        "proxy",
        routed_read_test_budget(),
    )
    .expect("list merge should succeed");
    let json = response_json(response).await;
    let items = json["items"]
        .as_array()
        .expect("merged response should include items");
    let ids: Vec<&str> = items
        .iter()
        .map(|item| item["id"].as_str().expect("each item should have an id"))
        .collect();
    assert_eq!(ids, vec!["b", "a", "c"]);
}
#[test]
fn routed_collection_page_rejects_missing_cursor_metadata() {
    let payload = norito::json!({"items": [], "total": 0});
    assert!(
        norito::json::from_value::<iroha_torii_shared::list_query::Page<Value>>(payload).is_err()
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn merged_alias_resolve_index_response_deduplicates_identical_bindings() {
    let payload = norito::json!({
        "index": 7,
        "alias": "merchant@paynet",
        "account_id": "alice.i105.invalid",
        "source": "on_chain"
    });
    let response = merged_alias_resolve_index_response(
        vec![payload.clone(), payload],
        "proxy",
        "fanout",
        routed_read_test_budget(),
    )
    .expect("identical alias-index bindings should merge cleanly");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-routed-by")
            .and_then(|value| value.to_str().ok()),
        Some("proxy")
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let payload: routing::AliasResolveIndexResponseDto =
        norito::json::from_slice(&body).expect("alias-index response");
    assert_eq!(payload.index, 7);
    assert_eq!(payload.alias, "merchant@paynet");
    assert_eq!(payload.account_id, "alice.i105.invalid");
    assert_eq!(payload.source.as_deref(), Some("fanout"));
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn merged_alias_resolve_index_response_rejects_conflicting_bindings() {
    let response = merged_alias_resolve_index_response(
        vec![
            norito::json!({
                "index": 7,
                "alias": "merchant@paynet",
                "account_id": "alice.i105.invalid",
                "source": "on_chain"
            }),
            norito::json!({
                "index": 7,
                "alias": "merchant@aed",
                "account_id": "alice.i105.invalid",
                "source": "on_chain"
            }),
        ],
        "proxy",
        "fanout",
        routed_read_test_budget(),
    )
    .expect_err("incompatible alias-index bindings should conflict");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("route_conflict")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn merged_alias_resolve_index_response_rejects_malformed_payload() {
    let response = merged_alias_resolve_index_response(
        vec![norito::json!({
            "alias": "merchant@paynet",
            "account_id": "alice.i105.invalid"
        })],
        "proxy",
        "fanout",
        routed_read_test_budget(),
    )
    .expect_err("malformed alias-index payloads should fail decoding");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("invalid_proxy_response")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn merged_alias_resolve_index_response_returns_not_found_when_payloads_are_empty() {
    let response = merged_alias_resolve_index_response(
        Vec::new(),
        "proxy",
        "fanout",
        routed_read_test_budget(),
    )
    .expect_err("empty alias-index merges should surface not_found");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("not_found")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn merged_alias_lookup_by_account_response_deduplicates_items_and_recomputes_total() {
    let response = merged_alias_lookup_by_account_response(
        vec![
            norito::json!({
                "account_id": "alice.i105.invalid",
                "total": 2,
                "items": [{
                    "alias": "merchant@paynet",
                    "dataspace": "paynet",
                    "domain": null,
                    "is_primary": true
                }, {
                    "alias": "merchant@banka.paynet",
                    "dataspace": "paynet",
                    "domain": "banka",
                    "is_primary": false
                }],
                "source": "on_chain"
            }),
            norito::json!({
                "account_id": "alice.i105.invalid",
                "total": 1,
                "items": [{
                    "alias": "merchant@paynet",
                    "dataspace": "paynet",
                    "domain": null,
                    "is_primary": true
                }],
                "source": "on_chain"
            }),
        ],
        "proxy",
        "fanout",
        0,
        routed_read_test_budget(),
    )
    .expect("compatible alias-by-account payloads should merge");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let payload: routing::AliasLookupByAccountResponseDto =
        norito::json::from_slice(&body).expect("alias by-account response");
    assert_eq!(payload.account_id, "alice.i105.invalid");
    assert_eq!(payload.total, 2);
    assert_eq!(payload.items.len(), 2);
    assert_eq!(payload.source.as_deref(), Some("fanout"));
    assert_eq!(payload.items[0].alias, "merchant@banka.paynet");
    assert!(!payload.items[0].is_primary);
    assert_eq!(payload.items[1].alias, "merchant@paynet");
    assert!(payload.items[1].is_primary);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn merged_alias_lookup_by_account_response_rejects_malformed_payload() {
    let response = merged_alias_lookup_by_account_response(
        vec![norito::json!({
            "total": 1,
            "items": [],
            "source": "on_chain"
        })],
        "proxy",
        "fanout",
        0,
        routed_read_test_budget(),
    )
    .expect_err("malformed alias-account payloads should fail decoding");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("invalid_proxy_response")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn merged_alias_lookup_by_account_response_rejects_conflicting_account_roots() {
    let response = merged_alias_lookup_by_account_response(
        vec![
            norito::json!({
                "account_id": "alice.i105.invalid",
                "total": 1,
                "items": [],
                "source": "on_chain"
            }),
            norito::json!({
                "account_id": "bob.i105.invalid",
                "total": 1,
                "items": [],
                "source": "on_chain"
            }),
        ],
        "proxy",
        "fanout",
        0,
        routed_read_test_budget(),
    )
    .expect_err("conflicting account roots should fail");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("route_conflict")
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn merged_alias_lookup_by_account_response_returns_permission_denied_when_items_are_empty_and_denied_routes_exist()
 {
    let response = merged_alias_lookup_by_account_response(
        vec![norito::json!({
            "account_id": "alice.i105.invalid",
            "total": 0,
            "items": [],
            "source": "on_chain"
        })],
        "proxy",
        "fanout",
        1,
        routed_read_test_budget(),
    )
    .expect_err("empty merged alias rows with denied routes should fail closed");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let error = response_error(response).await;
    assert_eq!(error.code(), "permission_denied");
}
#[tokio::test]
async fn merged_singleton_response_rejects_conflicting_payloads() {
    let response = merged_singleton_response(
        vec![
            norito::json!({"id": "asset#a"}),
            norito::json!({"id": "asset#b"}),
        ],
        "proxy",
        routed_read_test_budget(),
    )
    .expect_err("conflicting singleton payloads should fail");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}
#[tokio::test]
async fn merged_pipeline_status_response_prefers_highest_semantic_status() {
    let response = merged_pipeline_status_response(
        vec![
            norito::json!({
                "hash": "abc",
                "status": {"kind": "Committed", "block_height": 7},
                "scope": "global",
                "resolved_from": "cache"
            }),
            norito::json!({
                "hash": "abc",
                "status": {"kind": "Applied", "block_height": 7},
                "scope": "global",
                "resolved_from": "state"
            }),
        ],
        "proxy",
        routed_read_test_budget(),
    )
    .expect("pipeline status fanout should merge semantically compatible statuses");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let payload: PipelineTransactionStatusResponse =
        norito::json::from_slice(&body).expect("status payload");
    assert_eq!(payload.status.kind, "Applied");
    assert_eq!(payload.resolved_from, "state");
}
#[tokio::test]
async fn merged_pipeline_status_response_prefers_applied_over_cached_rejection() {
    let response = merged_pipeline_status_response(
        vec![
            norito::json!({
                "hash": "abc",
                "status": {
                    "kind": "Rejected",
                    "block_height": null
                },
                "scope": "global",
                "resolved_from": "cache"
            }),
            norito::json!({
                "hash": "abc",
                "status": {"kind": "Applied", "block_height": 7},
                "scope": "global",
                "resolved_from": "state"
            }),
        ],
        "proxy",
        routed_read_test_budget(),
    )
    .expect("pipeline status fanout should prefer committed success over stale rejection");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let payload: PipelineTransactionStatusResponse =
        norito::json::from_slice(&body).expect("status payload");
    assert_eq!(payload.status.kind, "Applied");
    assert_eq!(payload.resolved_from, "state");
}
#[tokio::test]
async fn merged_pipeline_status_response_prefers_state_failure_over_cached_applied() {
    for failure in ["Rejected", "Expired"] {
        let response = merged_pipeline_status_response(
            vec![
                norito::json!({
                    "hash": "abc",
                    "status": {"kind": "Applied", "block_height": 7},
                    "scope": "global",
                    "resolved_from": "cache"
                }),
                norito::json!({
                    "hash": "abc",
                    "status": {"kind": failure, "block_height": 8},
                    "scope": "global",
                    "resolved_from": "state"
                }),
            ],
            "proxy",
            routed_read_test_budget(),
        )
        .expect("state finality must outrank a cached terminal hint");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let payload: PipelineTransactionStatusResponse =
            norito::json::from_slice(&body).expect("status payload");
        assert_eq!(payload.status.kind, failure);
        assert_eq!(payload.resolved_from, "state");
    }
}
fn pipeline_status_hint_response(kind: &str, resolved_from: &str) -> Response {
    crate::utils::respond_with_format(
        PipelineTransactionStatusResponse::new(
            HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed(
                [0x51; Hash::LENGTH],
            ))
            .to_string(),
            PipelineTransactionStatus {
                kind: kind.to_owned(),
                block_height: Some(7),
            },
            "global".to_owned(),
            resolved_from.to_owned(),
        ),
        ResponseFormat::Json,
    )
}
#[tokio::test]
async fn pipeline_status_hint_ignores_non_terminal_successes() {
    for kind in ["Queued", "Approved", "Committed"] {
        let response = pipeline_status_hint_response(kind, "cache");
        let hinted = pipeline_status_hinted_global_response(
            response,
            ROUTED_READ_TEST_BODY_BYTES,
            &HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed(
                [0x51; Hash::LENGTH],
            )),
        )
        .await
        .expect("hint classifier should not fail");
        assert!(
            hinted.is_none(),
            "global status must fan out instead of trusting hinted {kind} state"
        );
    }
}
#[tokio::test]
async fn pipeline_status_hint_ignores_cached_terminal_statuses() {
    for kind in ["Applied", "Rejected", "Expired"] {
        let response = pipeline_status_hint_response(kind, "cache");
        let hinted = pipeline_status_hinted_global_response(
            response,
            ROUTED_READ_TEST_BODY_BYTES,
            &HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed(
                [0x51; Hash::LENGTH],
            )),
        )
        .await
        .expect("hint classifier should not fail");
        assert!(
            hinted.is_none(),
            "global status must fan out instead of trusting hinted cached {kind}"
        );
    }
}
#[tokio::test]
async fn pipeline_status_hint_allows_authoritative_terminal_statuses() {
    for (kind, resolved_from) in [("Applied", "state"), ("Rejected", "state")] {
        let response = pipeline_status_hint_response(kind, resolved_from);
        let hinted = pipeline_status_hinted_global_response(
            response,
            ROUTED_READ_TEST_BODY_BYTES,
            &HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed(
                [0x51; Hash::LENGTH],
            )),
        )
        .await
        .expect("hint classifier should not fail")
        .expect("authoritative hinted status may short-circuit");
        let body = axum::body::to_bytes(hinted.into_body(), usize::MAX)
            .await
            .expect("hinted body should be readable");
        let payload: PipelineTransactionStatusResponse =
            norito::json::from_slice(&body).expect("status payload");
        assert_eq!(payload.status.kind, kind);
        assert_eq!(payload.resolved_from, resolved_from);
    }
}
#[tokio::test]
async fn pipeline_status_hint_ignores_malformed_success() {
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(br#"{"status":{"kind":"Queued"}"#.as_slice()))
        .expect("malformed JSON response");
    let hinted = pipeline_status_hinted_global_response(
        response,
        ROUTED_READ_TEST_BODY_BYTES,
        &HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed([0x51; Hash::LENGTH])),
    )
    .await
    .expect("malformed hinted success should fall through to fanout");
    assert!(hinted.is_none());
    let hash =
        HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed([0x51; Hash::LENGTH]));
    let absence = pipeline_status_not_found_response(
        &hash,
        PipelineStatusReadScope::Global,
        ResponseFormat::Json,
    );
    assert!(
        pipeline_status_hinted_global_response(absence, ROUTED_READ_TEST_BODY_BYTES, &hash)
            .await
            .expect("exact hinted absence continues fanout")
            .is_none()
    );
    let generic =
        torii_proxy_error_response(StatusCode::NOT_FOUND, "route_not_found", "wrong route");
    let error = pipeline_status_hinted_global_response(generic, ROUTED_READ_TEST_BODY_BYTES, &hash)
        .await
        .expect_err("generic hinted 404 is not absence");
    assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn merged_space_directory_bindings_response_unions_accounts_and_omits_singular_route() {
    let response = merged_space_directory_bindings_response(
        vec![
            norito::json!({
                "uaid": "uaid:alice",
                "dataspaces": [{
                    "dataspace_id": 2,
                    "dataspace_alias": "centralbank",
                    "accounts": ["alice@centralbank", "bob@centralbank"]
                }]
            }),
            norito::json!({
                "uaid": "uaid:alice",
                "dataspaces": [{
                    "dataspace_id": 2,
                    "dataspace_alias": "centralbank",
                    "accounts": ["alice@centralbank"]
                }, {
                    "dataspace_id": 7,
                    "dataspace_alias": "ops",
                    "accounts": ["carol@ops"]
                }]
            }),
        ],
        "proxy",
        routed_read_test_budget(),
    )
    .expect("bindings merge should succeed");
    assert_eq!(
        response
            .headers()
            .get("x-iroha-routed-by")
            .and_then(|value| value.to_str().ok()),
        Some("proxy")
    );
    assert!(
        response.headers().get("x-iroha-route-lane-id").is_none(),
        "fanout merge must not report a singular lane"
    );
    assert!(
        response
            .headers()
            .get("x-iroha-route-dataspace-id")
            .is_none(),
        "fanout merge must not report a singular dataspace"
    );
    let json = response_json(response).await;
    assert_eq!(json["uaid"].as_str(), Some("uaid:alice"));
    let dataspaces = json["dataspaces"]
        .as_array()
        .expect("bindings merge should expose dataspaces");
    assert_eq!(dataspaces.len(), 2);
    assert_eq!(dataspaces[0]["dataspace_id"].as_u64(), Some(2));
    assert_eq!(
        dataspaces[0]["dataspace_alias"].as_str(),
        Some("centralbank")
    );
    assert_eq!(
        dataspaces[0]["accounts"].as_array().expect("accounts"),
        &vec![
            Value::from("alice@centralbank"),
            Value::from("bob@centralbank"),
        ]
    );
    assert_eq!(dataspaces[1]["dataspace_id"].as_u64(), Some(7));
    assert_eq!(dataspaces[1]["dataspace_alias"].as_str(), Some("ops"));
}

#[tokio::test]
async fn pipeline_status_global_resolution_prefers_routed_terminal_over_local_queue() {
    let hash =
        HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed([0x51; Hash::LENGTH]));
    for kind in ["Applied", "Rejected"] {
        let response = pipeline_status_global_response_with_local_hint(
            pipeline_status_hint_response(kind, "state"),
            Some((
                PipelineStatusEntry::fresh(PipelineStatusKind::Queued, None, None),
                "queue",
            )),
            &hash,
            ResponseFormat::Json,
            ROUTED_READ_TEST_BODY_BYTES,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let payload = response_json(response).await;
        assert_eq!(payload["status"]["kind"].as_str(), Some(kind));
        assert_eq!(payload["resolved_from"].as_str(), Some("state"));
    }
}
#[tokio::test]
async fn pipeline_status_global_resolution_preserves_pending_and_refuses_unavailable_absence() {
    let hash =
        HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed([0x51; Hash::LENGTH]));
    let remote_pending = pipeline_status_global_response_with_local_hint(
        pipeline_status_hint_response("Queued", "queue"),
        None,
        &hash,
        ResponseFormat::Json,
        ROUTED_READ_TEST_BODY_BYTES,
    )
    .await;
    assert_eq!(remote_pending.status(), StatusCode::OK);
    assert_eq!(
        response_json(remote_pending).await["status"]["kind"].as_str(),
        Some("Queued")
    );
    let ingress_pending = pipeline_status_global_response_with_local_hint(
        pipeline_status_not_found_response(
            &hash,
            PipelineStatusReadScope::Global,
            ResponseFormat::Json,
        ),
        Some((
            PipelineStatusEntry::fresh(PipelineStatusKind::Queued, None, None),
            "queue",
        )),
        &hash,
        ResponseFormat::Json,
        ROUTED_READ_TEST_BODY_BYTES,
    )
    .await;
    assert_eq!(ingress_pending.status(), StatusCode::OK);
    assert_eq!(
        response_json(ingress_pending).await["status"]["kind"].as_str(),
        Some("Queued")
    );
    for local_hint in [
        None,
        Some((
            PipelineStatusEntry::fresh(PipelineStatusKind::Queued, None, None),
            "queue",
        )),
    ] {
        let unavailable = pipeline_status_global_response_with_local_hint(
            torii_proxy_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "route_unavailable",
                "peer offline",
            ),
            local_hint,
            &hash,
            ResponseFormat::Json,
            ROUTED_READ_TEST_BODY_BYTES,
        )
        .await;
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
#[tokio::test]
async fn pipeline_status_fanout_requires_exact_scoped_absence() {
    let routes = [
        RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1)),
        RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2)),
    ];
    let hash =
        HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed([0x51; Hash::LENGTH]));
    // The route-hint fast path must enforce the same exact selector as fanout.
    for (actual_hash, scope) in [
        (hash.to_string(), "global"),
        (
            HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed(
                [0x53; Hash::LENGTH],
            ))
            .to_string(),
            "global",
        ),
        (hash.to_string(), "local"),
    ] {
        let correct = actual_hash == hash.to_string() && scope == "global";
        let response = crate::utils::respond_with_format(
            PipelineTransactionStatusResponse::new(
                actual_hash,
                PipelineTransactionStatus {
                    kind: "Applied".into(),
                    block_height: Some(7),
                },
                scope.into(),
                "state".into(),
            ),
            ResponseFormat::Json,
        );
        let hinted =
            pipeline_status_hinted_global_response(response, ROUTED_READ_TEST_BODY_BYTES, &hash)
                .await;
        if correct {
            assert!(hinted.expect("exact authoritative hint").is_some());
        } else {
            assert_eq!(
                hinted.expect_err("hint selector mismatch").status(),
                StatusCode::BAD_GATEWAY
            );
        }
    }
    for case in 0..12_u8 {
        let result = collect_torii_pipeline_status_json_payloads(
            &routes,
            &hash,
            routed_read_test_working_set_bytes(),
            ROUTED_READ_TEST_BODY_BYTES,
            move |route| async move {
                if route == routes[0] {
                    return pipeline_status_not_found_response(
                        &hash,
                        PipelineStatusReadScope::Global,
                        ResponseFormat::Json,
                    );
                }
                match case {
                    0 => pipeline_status_not_found_response(
                        &hash,
                        PipelineStatusReadScope::Global,
                        ResponseFormat::Json,
                    ),
                    1 => torii_proxy_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "route_unavailable",
                        "peer offline",
                    ),
                    2 => torii_proxy_error_response(
                        StatusCode::NOT_FOUND,
                        "route_not_found",
                        "wrong route",
                    ),
                    3 => pipeline_status_not_found_response(
                        &hash,
                        PipelineStatusReadScope::Local,
                        ResponseFormat::Json,
                    ),
                    4 => pipeline_status_not_found_response(
                        &HashOf::from_untyped_unchecked(Hash::prehashed([0x53; Hash::LENGTH])),
                        PipelineStatusReadScope::Global,
                        ResponseFormat::Json,
                    ),
                    5 => Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header("content-type", "text/plain")
                        .body(Body::from("missing"))
                        .expect("response"),
                    6 => Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("response"),
                    7 => {
                        let mut response = pipeline_status_not_found_response(
                            &hash,
                            PipelineStatusReadScope::Global,
                            ResponseFormat::Json,
                        );
                        response
                            .headers_mut()
                            .append("content-type", HeaderValue::from_static("application/json"));
                        response
                    }
                    8 => pipeline_status_not_found_response(
                        &hash,
                        PipelineStatusReadScope::Global,
                        ResponseFormat::Norito,
                    ),
                    9 => {
                        let mut response = pipeline_status_not_found_response(
                            &hash,
                            PipelineStatusReadScope::Global,
                            ResponseFormat::Json,
                        );
                        *response.status_mut() = StatusCode::FORBIDDEN;
                        response
                    }
                    10 => crate::utils::respond_with_format(
                        PipelineTransactionStatusResponse::new(
                            hash.to_string(),
                            iroha_torii_shared::PipelineTransactionStatus {
                                kind: "Applied".to_owned(),
                                block_height: Some(7),
                            },
                            "global".to_owned(),
                            "state".to_owned(),
                        ),
                        ResponseFormat::Json,
                    ),
                    _ => {
                        let mut response = pipeline_status_not_found_response(
                            &hash,
                            PipelineStatusReadScope::Global,
                            ResponseFormat::Json,
                        );
                        response.headers_mut().remove("content-type");
                        response
                    }
                }
            },
        )
        .await;
        if case == 10 {
            let collected = result.expect("knownpositive");
            assert_eq!(collected.payloads.len(), 1);
            continue;
        }
        let response = result.expect_err("no positive or malformed shard");
        assert_eq!(
            response.status(),
            match case {
                0 => StatusCode::NOT_FOUND,
                1 => StatusCode::SERVICE_UNAVAILABLE,
                9 => StatusCode::FORBIDDEN,
                _ => StatusCode::BAD_GATEWAY,
            },
            "case {case}"
        );
        if case == 0 {
            validate_pipeline_status_absence_response(
                response,
                &hash,
                PipelineStatusReadScope::Global,
                4096,
            )
            .await
            .expect("complete exactabsence");
        }
    }
    let positive = collect_torii_pipeline_status_json_payloads(
        &routes,
        &hash,
        routed_read_test_working_set_bytes(),
        ROUTED_READ_TEST_BODY_BYTES,
        move |route| async move {
            if route == routes[0] {
                torii_proxy_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "route_unavailable",
                    "offline",
                )
            } else {
                crate::utils::respond_with_format(
                    PipelineTransactionStatusResponse::new(
                        hash.to_string(),
                        iroha_torii_shared::PipelineTransactionStatus {
                            kind: "Applied".to_owned(),
                            block_height: Some(7),
                        },
                        "global".to_owned(),
                        "state".to_owned(),
                    ),
                    ResponseFormat::Json,
                )
            }
        },
    )
    .await
    .expect("existing knownpositive semantics");
    assert_eq!(positive.payloads.len(), 1);
    assert_eq!(positive.diagnostics.unavailable_routes, 1);
    let empty = collect_torii_pipeline_status_json_payloads(
        &[],
        &hash,
        routed_read_test_working_set_bytes(),
        ROUTED_READ_TEST_BODY_BYTES,
        |_| async { unreachable!() },
    )
    .await
    .expect_err("no routes unavailable");
    assert_eq!(empty.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[cfg(feature = "app_api")]
#[tokio::test]
async fn permission_collection_counts_deduplicated_grants_once_across_routes() {
    use iroha_core::state::World;
    use iroha_data_model::{account::Account, permission::Permission, role::Role};
    for has_second_permission in [false, true] {
        let authority = routed_read_test_account(0xa0);
        let permission =
            |name: &str| Permission::new(name.to_owned(), iroha_primitives::json::Json::new(()));
        let first_id: iroha_data_model::role::RoleId = "first_permission_role".parse().unwrap();
        let second_id: iroha_data_model::role::RoleId = "second_permission_role".parse().unwrap();
        let first = Role::new(first_id.clone(), authority.clone())
            .add_permission(permission("CanSetParameters"))
            .build(&authority);
        let mut second = Role::new(second_id.clone(), authority.clone())
            .add_permission(permission("CanSetParameters"));
        if has_second_permission {
            second = second.add_permission(permission("CanRegisterDomain"));
        }
        let mut world = World::with_assets_and_roles(
            [],
            [Account::new(authority.clone()).build(&authority)],
            [],
            [],
            [],
            [first, second.build(&authority)],
        );
        world.grant_role_for_tests(authority.clone(), first_id);
        world.grant_role_for_tests(authority.clone(), second_id);
        let app =
            crate::tests_runtime_handlers::native_ingress_with_offline_foreign_app_for_test(world);
        let routes = torii_all_dataspace_routes(app.as_ref());
        assert!(routes.len() > 1);
        let response = execute_torii_read_fanout_for_resolved_routes(
            &app,
            routes,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            ToriiReadFanoutMergeV1::List,
            crate::ToriiReadPayload {
                endpoint: ToriiReadEndpointV1::AccountPermissionsQuery,
                path_args: vec![authority.to_string()],
                query_string: None,
                body: collection_query_body(
                    &ListQuery::new().limit(1).include_total(),
                    routing::collection_sources::collection_execution_limits(None)
                        .expect("test collection limits")
                        .bytes,
                )
                .unwrap(),
            },
            ToriiProxyResponseFormatV1::Json,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        let page: iroha_torii_shared::list_query::Page<Value> =
            norito::json::from_value(json.clone()).expect("shared permission page");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.total, Some(if has_second_permission { 2 } else { 1 }));
        assert_eq!(page.has_more(), has_second_permission);
        assert!(json.get("has_more").is_none(), "retired envelope is absent");
    }
}

#[cfg(feature = "app_api")]
#[test]
fn permission_collection_rejects_retired_or_missing_continuation_evidence() {
    for payload in [
        norito::json!({"items": [], "total": 0}),
        norito::json!({"items": [], "total": 0, "has_more": "false"}),
        norito::json!({"items": [], "total": 1, "has_more": true}),
        norito::json!({"items": [], "total": 0, "next_cursor": null, "has_more": false}),
    ] {
        assert!(
            norito::json::from_value::<iroha_torii_shared::list_query::Page<Value>>(payload)
                .is_err()
        );
    }
}

#[test]
fn contract_target_read_route_preserves_absent_and_active_targets() {
    let authority = routed_read_test_account(0xa1);
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        world_with_account(&authority),
        iroha_config::parameters::actual::Nexus::default(),
    );
    assert_eq!(
        torii_contract_target_read_route(app.as_ref(), None, None).unwrap(),
        None
    );
    let address = iroha_data_model::smart_contract::ContractAddress::derive(
        app.state.network_id_ref(),
        &authority,
        0,
        DataSpaceId::UNIVERSAL,
    )
    .expect("contract address under actual signed genesis");
    let route = torii_contract_target_read_route(app.as_ref(), Some(&address), None)
        .expect("active target route")
        .expect("explicit contract target retains its route");
    assert_eq!(
        route,
        resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL).unwrap()
    );
    assert_eq!(route.dataspace_id, DataSpaceId::UNIVERSAL);
    assert!(torii_lane_active_for_routing(app.as_ref(), route.lane_id));
}

#[tokio::test]
async fn contract_state_read_refuses_known_dataspace_without_active_lane_before_local_collection() {
    let authority = routed_read_test_account(0xa2);
    let target = DataSpaceId::new(10);
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    let dataspaces = iroha_data_model::nexus::DataSpaceCatalog::new(vec![
        iroha_data_model::nexus::DataSpaceMetadata::default(),
        iroha_data_model::nexus::DataSpaceMetadata {
            id: target,
            alias: "contract-target".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("configured target dataspace without a matching lane");
    nexus.dataspace_catalog = dataspaces.clone();
    nexus.configured_dataspace_catalog = dataspaces;
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        world_with_account(&authority),
        nexus,
    );
    assert!(matches!(
        resolve_torii_route_for_dataspace_id(app.as_ref(), target),
        Err(queue::RoutingResolveError::NoLaneForDataspace { dataspace_id }) if dataspace_id == target
    ));
    let address = iroha_data_model::smart_contract::ContractAddress::derive(
        app.state.network_id_ref(),
        &authority,
        0,
        target,
    )
    .expect("contract address binds original network and unavailable target");
    let address_literal = address.to_string();
    let query = || routing::ContractStateQuery {
        contract_address: Some(address_literal.clone()),
        path: Some("Counter".to_owned()),
        ..Default::default()
    };
    // Seed the original scoped storage owner. Exact-path reads require an existing value;
    // the successful component response proves the outer route barrier must refuse first.
    let stored_path = format!(
        "sc/{}/Counter",
        hex::encode(Hash::new(address_literal.as_bytes()).as_ref())
    );
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 1_001, 0);
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    tx.world_mut_for_testing()
        .smart_contract_state_mut_for_testing()
        .insert(
            stored_path.parse().expect("valid scoped Counter path"),
            norito::codec::Encode::encode(&7_u64),
        );
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("seed isolated scoped Counter data");
    let JsonBody(local) =
        routing::handle_get_contract_state(app.state.clone(), crate::NoritoQuery(query()))
            .await
            .expect("local component can read the original scoped value without choosing a lane");
    assert_eq!(
        local.contract_address.as_deref(),
        Some(address_literal.as_str())
    );
    assert_eq!(local.path.as_deref(), Some("Counter"));
    assert_eq!(local.entries.len(), 1);
    assert!(local.entries[0].found);
    assert_eq!(local.entries[0].value_len, Some(8));
    let route_error = torii_contract_target_read_route(app.as_ref(), Some(&address), None)
        .expect_err("known unavailable target cannot become absent/default target");
    assert!(matches!(
        route_error,
        Error::AppServiceUnavailable {
            code: "route_unavailable",
            ..
        }
    ));
    let error = handler_get_contract_state(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxQuery(query()),
    )
    .await
    .expect_err("explicit unroutable contract state request must not fall back to local storage");
    assert!(matches!(
        &error,
        Error::AppServiceUnavailable {
            code: "route_unavailable",
            ..
        }
    ));
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers().get("x-iroha-reject-code").unwrap(),
        "route_unavailable"
    );
    let envelope = response_error(response).await;
    assert_eq!(envelope.code(), "route_unavailable");
}

#[test]
fn contract_target_read_route_refuses_present_but_inactive_lane() {
    let authority = routed_read_test_account(0xa3);
    let mut app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    // This deliberately corrupt structural fixture exercises routing activity only,
    // and claims neither signed genesis nor authenticated native finality.
    let (lane, target) = configure_corrupt_inactive_autoscale_range_route_for_test(&mut app);
    assert!(
        app.state
            .nexus_snapshot()
            .lane_catalog
            .lanes()
            .iter()
            .any(|entry| entry.id == lane && entry.dataspace_id == target)
    );
    assert!(!torii_lane_active_for_routing(app.as_ref(), lane));
    let address = iroha_data_model::smart_contract::ContractAddress::derive(
        app.state.network_id_ref(),
        &authority,
        0,
        target,
    )
    .expect("structural target address");
    let error = torii_contract_target_read_route(app.as_ref(), Some(&address), None)
        .expect_err("inactive physical lane cannot authorize local contract fallback");
    assert!(matches!(
        error,
        Error::AppServiceUnavailable {
            code: "route_unavailable",
            ..
        }
    ));
}

#[cfg(feature = "app_api")]
#[tokio::test]
async fn canonical_visibility_busy_source_is_capacity_and_preserves_request_nonce() {
    let key_pair = routed_read_ed25519_test_keypair(0x97);
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let method = Method::POST;
    let uri: Uri = "/v1/accounts/query".parse().expect("query URI");
    let body = b"{}";
    let headers = crate::tests_runtime_handlers::signed_app_headers(
        &authority, &key_pair, &method, &uri, body,
    );
    let authenticate = || torii_visibility_account_from_headers(
        &app, &headers, &method, &uri, body, "v1/accounts/query",
    );
    let refused = app.state.with_held_header_for_reader_test(|_| {
        authenticate().expect_err("held original State source cannot authenticate")
    });
    assert!(matches!(
        &refused,
        Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
        ))
    ), "physical reader contention is not invalid credentials: {refused:?}");
    assert_eq!(refused.into_response().status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(matches!(authenticate().expect("same original request succeeds after release"),
        ToriiAccountReadVisibility::Signed(account) if account == authority));
    let replay = authenticate().expect_err("a consumed request remains replay-protected");
    assert!(matches!(&replay, Error::AppUnauthorized { code, message }
        if *code == "canonical_authentication_invalid" && message == "request nonce already used"));
    assert_eq!(replay.into_response().status(), StatusCode::UNAUTHORIZED);
}
