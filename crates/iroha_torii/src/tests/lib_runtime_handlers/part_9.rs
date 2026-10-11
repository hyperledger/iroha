#[tokio::test]
async fn single_operator_demo_budgets_admit_batched_tools_and_weighted_deployment() {
    let operator = "single-demo-operator";
    let mcp = limits::RateLimiter::new_per_minute(
        defaults::torii::mcp::RATE_PER_MINUTE,
        defaults::torii::mcp::BURST,
    );
    // The advertised batch extension charges each tool, including all calls
    // after the first one paid by the outer MCP request.
    for _ in 0..128 {
        assert!(
            mcp.allow_repeated(operator, crate::mcp::MAX_JSONRPC_BATCH_DISPATCHES)
                .await,
            "one operator's bounded MCP batch should fit the demo budget"
        );
    }
    assert!(mcp.allow_repeated(operator, 32).await);
    assert!(
        !mcp.allow_repeated(
            operator,
            defaults::torii::mcp::BURST.expect("finite MCP burst") as usize + 1,
        )
        .await,
        "the MCP budget must remain finite"
    );
    // An API-token overlay uses the fixed-key limiter with the same MCP
    // configuration. Check that branch's full operator workload as well.
    let authenticated_mcp = limits::FixedKeyRateLimiter::new_per_minute(
        defaults::torii::mcp::RATE_PER_MINUTE,
        defaults::torii::mcp::BURST,
        [operator.to_owned()],
    );
    for _ in 0..128 {
        assert!(
            authenticated_mcp
                .allow_repeated(operator, crate::mcp::MAX_JSONRPC_BATCH_DISPATCHES)
                .await,
            "authenticated MCP batch should fit the solo operator budget"
        );
    }
    assert!(authenticated_mcp.allow_repeated(operator, 32).await);

    let deploy = limits::RateLimiter::new(
        defaults::torii::DEPLOY_RATE_PER_ORIGIN_PER_SEC,
        defaults::torii::DEPLOY_BURST_PER_ORIGIN,
    );
    for _ in 0..48 {
        assert!(
            deploy.allow(operator).await,
            "one operator's contract mutation should fit the demo budget"
        );
    }
    for _ in 0..2 {
        assert!(
            deploy.allow(operator).await,
            "the final contract call should fit after deployment"
        );
    }
    assert!(deploy.allow("another-operator").await);
    assert!(
        !deploy
            .allow_cost(
                operator,
                u64::from(defaults::torii::DEPLOY_BURST_PER_ORIGIN.unwrap()) + 1,
            )
            .await,
        "the deployment budget must remain finite"
    );

    // Conservatively charge every MCP tool read as a finality-proof read in
    // the same bucket as 128 direct bridge-finality GETs. The advertised MCP
    // tool reaches the weighted route, so treating it as an ordinary read
    // would hide a solo-operator 429.
    let query = limits::RateLimiter::new(
        defaults::torii::QUERY_RATE_PER_AUTHORITY_PER_SEC,
        defaults::torii::QUERY_BURST_PER_AUTHORITY,
    );
    for _ in 0..128 {
        assert!(
            query
                .allow_cost_capped_to_burst(operator, super::FINALITY_HEAVY_QUERY_RATE_COST)
                .await,
            "the full weighted finality walk should fit"
        );
    }
    for _ in 0..(128 * crate::mcp::MAX_JSONRPC_BATCH_DISPATCHES + 32) {
        assert!(
            query
                .allow_cost_capped_to_burst(operator, super::FINALITY_HEAVY_QUERY_RATE_COST)
                .await,
            "MCP finality tools need their full weighted query budget"
        );
    }
    for _ in 0..(32 + 4 + 2) {
        assert!(
            query.allow(operator).await,
            "direct, funding, and contract reads need query headroom"
        );
    }
    assert!(
        !query
            .allow_cost(
                operator,
                u64::from(defaults::torii::QUERY_BURST_PER_AUTHORITY.unwrap()) + 1,
            )
            .await,
        "the query budget must remain finite"
    );
}
#[tokio::test]
async fn one_external_operator_walk_passes_the_real_preauth_gate() {
    let burst = defaults::torii::PREAUTH_BURST_PER_IP.expect("finite pre-auth burst");
    assert!(
        burst >= 100_000,
        "a large application burst sharing one public IP must fit"
    );
    let gate = limits::PreAuthGate::new(limits::PreAuthConfig {
        max_total: None,
        max_per_ip: None,
        rate_per_ip: defaults::torii::PREAUTH_RATE_PER_IP_PER_SEC,
        burst_per_ip: Some(burst),
        ban_duration: Some(defaults::torii::PREAUTH_BAN_DURATION),
        ban_capacity: defaults::torii::PREAUTH_BAN_CAPACITY,
        allow_nets: Vec::new(),
        scheme_limits: Vec::new(),
    });
    let operator = "198.51.100.10".parse().expect("test client IP");
    for request in 0..10_000 {
        drop(
            gate.acquire(Some(operator), None)
                .await
                .unwrap_or_else(|reason| {
                    panic!("one external operator was throttled at request {request}: {reason:?}")
                }),
        );
    }
}
#[tokio::test]
async fn application_default_budgets_admit_ten_thousand_operations_before_refill() {
    let operator = "application-operator";
    for (name, rate, burst) in [
        (
            "content read",
            Some(defaults::content::MAX_REQUESTS_PER_SECOND),
            Some(defaults::content::REQUEST_BURST),
        ),
        (
            "transaction",
            defaults::torii::TX_RATE_PER_AUTHORITY_PER_SEC,
            defaults::torii::TX_BURST_PER_AUTHORITY,
        ),
        (
            "deployment",
            defaults::torii::DEPLOY_RATE_PER_ORIGIN_PER_SEC,
            defaults::torii::DEPLOY_BURST_PER_ORIGIN,
        ),
        (
            "Soracloud public read",
            defaults::torii::SORACLOUD_PUBLIC_RATE_PER_IP_PER_SEC,
            defaults::torii::SORACLOUD_PUBLIC_BURST_PER_IP,
        ),
        (
            "Soracloud mutation",
            defaults::torii::SORACLOUD_MUTATION_RATE_PER_ACCOUNT_ORIGIN_PER_SEC,
            defaults::torii::SORACLOUD_MUTATION_BURST_PER_ACCOUNT_ORIGIN,
        ),
    ] {
        assert!(rate.is_some_and(|rate| rate >= 10_000), "{name} refill");
        let limiter = limits::RateLimiter::new(rate, burst);
        assert!(limiter.allow_repeated(operator, 10_000).await, "{name}");
        assert!(
            !limiter
                .allow_repeated(
                    operator,
                    burst.expect("finite application burst") as usize + 1
                )
                .await,
            "{name} still enforces an explicitly bounded budget"
        );
    }
    let proof = limits::RateLimiter::new_per_minute(
        defaults::torii::PROOF_RATE_PER_MIN,
        defaults::torii::PROOF_BURST,
    );
    assert!(proof.allow_repeated(operator, 10_000).await);
    let query = limits::RateLimiter::new(
        defaults::torii::QUERY_RATE_PER_AUTHORITY_PER_SEC,
        defaults::torii::QUERY_BURST_PER_AUTHORITY,
    );
    assert!(
        query
            .allow_cost(operator, 10_000 * super::FINALITY_HEAVY_QUERY_RATE_COST)
            .await,
        "10,000 weighted finality reads must fit before any refill"
    );
}
#[tokio::test]
async fn content_default_egress_serves_large_solo_bundle_bursts() {
    let burst = defaults::content::EGRESS_BURST_BYTES;
    let limiter = limits::RateLimiter::new_u64(
        Some(u64::from(defaults::content::MAX_EGRESS_BYTES_PER_SECOND)),
        Some(burst),
    );
    let reader = "solo-content-reader";
    let bundles = 128_u64;
    assert!(
        limiter
            .allow_cost(reader, bundles * defaults::content::MAX_BUNDLE_BYTES)
            .await
    );
    assert!(!limiter.allow_cost(reader, burst + 1).await);
}
#[tokio::test]
async fn solo_finality_walk_fits_the_proof_egress_budget() {
    let mut node = ReadinessNode::start_at_tip(true);
    let proof = iroha_core::sumeragi::finality::build_proof(&node.app.state.view(), 2)
        .expect("current real-node embedded certificate proof");
    proof
        .decode_checked()
        .expect("current proof verifies before measuring egress");
    node.stop();
    let response_bytes = u64::try_from(
        norito::json::to_json_pretty(&proof)
            .expect("encode the actual current finality JSON response")
            .len(),
    )
    .expect("response length fits u64");
    let other_proof_response_bytes = 2 * 1024 * 1024;
    let burst = defaults::torii::PROOF_EGRESS_BURST_BYTES.expect("finite proof egress burst");
    let finality_reads = 128 + 6 * crate::mcp::MAX_JSONRPC_BATCH_DISPATCHES + 32;
    assert!(
        response_bytes
            .checked_mul(u64::try_from(finality_reads).expect("bounded proof count"))
            .and_then(|bytes| bytes.checked_add(other_proof_response_bytes))
            .is_some_and(|bytes| bytes <= burst),
        "direct and MCP finality responses plus 2 MiB for proof-submit responses must fit"
    );
    let egress =
        limits::RateLimiter::new_u64(defaults::torii::PROOF_EGRESS_BYTES_PER_SEC, Some(burst));
    for read in 0..finality_reads {
        assert!(
            egress.allow_cost("solo-proof-reader", response_bytes).await,
            "actual finality response {read} exceeded proof egress"
        );
    }
    assert!(
        egress
            .allow_cost("solo-proof-reader", other_proof_response_bytes)
            .await,
        "proof-submit responses need 2 MiB of shared egress headroom"
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn solo_heavy_read_waits_for_a_bounded_permit_instead_of_immediate_429() {
    let mut app = mk_app_state_for_tests();
    let state = Arc::get_mut(&mut app).expect("unique Torii app fixture");
    state.query_inflight = Arc::new(tokio::sync::Semaphore::new(
        defaults::torii::QUERY_MAX_INFLIGHT.get(),
    ));
    state.query_heavy_inflight = Arc::new(tokio::sync::Semaphore::new(
        defaults::torii::QUERY_HEAVY_MAX_INFLIGHT.get(),
    ));
    state.query_queue_timeout = Duration::from_millis(defaults::torii::QUERY_QUEUE_TIMEOUT_MS);
    let mut active = Vec::new();
    for _ in 0..defaults::torii::QUERY_HEAVY_MAX_INFLIGHT.get() {
        active.push(
            acquire_query_admission(app.as_ref(), true)
                .await
                .expect("a bounded heavy proof read fits the active permits"),
        );
    }
    let waiting_app = Arc::clone(&app);
    let waiter =
        tokio::spawn(async move { acquire_query_admission(waiting_app.as_ref(), true).await });
    // A healthy solo burst must not receive 429 merely because one occupied
    // heavy-query wave takes longer than the former one-second deadline.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(
        !waiter.is_finished(),
        "the next heavy read must wait for a permit"
    );
    drop(active.pop());
    let admitted = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .expect("bounded wait completes before the default deadline")
        .expect("waiting task remains live")
        .expect("the next solo heavy read is admitted");
    drop(admitted);
    drop(active);
}
#[tokio::test]
async fn openapi_enforces_token_policy() {
    let mut app = mk_app_state_for_tests();
    {
        let state = Arc::get_mut(&mut app).expect("unique app state");
        state.require_api_token = true;
        state.api_token_digests = Arc::new(limits::ApiTokenDigestSet::from_tokens(["token-123"]));
    }
    let headers = HeaderMap::new();
    let missing = super::handler_openapi(
        State(app.clone()),
        headers.clone(),
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
    )
    .await;
    assert!(matches!(
        missing,
        Err(Error::Query(
            iroha_data_model::ValidationFail::NotPermitted(_)
        ))
    ));
    let mut headers_with_token = HeaderMap::new();
    headers_with_token.insert("x-api-token", HeaderValue::from_static("token-123"));
    let ok = super::handler_openapi(
        State(app),
        headers_with_token,
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
    )
    .await
    .expect("token accepted");
    assert_eq!(ok.status(), axum::http::StatusCode::OK);
}
/// Execute signed service deployment so status reads its original lifecycle audit.
#[cfg(feature = "app_api")]
fn soracloud_status_app_for_test(nexus: iroha_config::parameters::actual::Nexus) -> SharedAppState {
    use iroha_data_model::soracloud::SoraServiceMutationPreconditionV1;
    let fixture = seed_public_soracloud_world();
    let mut bundle = fixture
        .view()
        .soracloud_service_revisions()
        .get(&("web_portal".to_owned(), "2026.02.0".to_owned()))
        .cloned()
        .expect("original public service bundle");
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let mut config =
        iroha_core::sumeragi::test_chain::TestChainConfig::new(World::default(), 1_000);
    config.nexus = Some(iroha_config::parameters::actual::Nexus::default());
    let authority = AccountId::new(config.genesis_key.public_key().clone());
    config.genesis_instructions.push(
        Grant::account_permission(
            Permission::new(
                "CanManageSoracloud".to_owned(),
                iroha_primitives::json::Json::new(()),
            ),
            authority.clone(),
        )
        .into(),
    );
    let initial_service_configs = BTreeMap::new();
    let initial_service_secrets = BTreeMap::new();
    let precondition = SoraServiceMutationPreconditionV1::ServiceAbsent;
    let payload = iroha_data_model::soracloud::encode_bundle_with_materials_provenance_payload(
        &bundle,
        &initial_service_configs,
        &initial_service_secrets,
        &precondition,
    )
    .expect("canonical signed deployment payload");
    let provenance = iroha_data_model::smart_contract::manifest::ManifestProvenance {
        signer: config.genesis_key.public_key().clone(),
        signature: checked_torii_test_signature(
            &config.genesis_key,
            &payload,
            "sign original service deployment",
        ),
    };
    config.genesis_instructions.push(
        iroha_data_model::isi::soracloud::DeploySoracloudService {
            bundle,
            initial_service_configs,
            initial_service_secrets,
            precondition,
            provenance,
        }
        .into(),
    );
    let app = native_ingress_app_with_config_for_test(config);
    let global_route =
        super::lane_authority_route(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL));
    let original_global_authority = app
        .state
        .resolve_route_authority(global_route)
        .expect("genuine service genesis committee before routing projection");
    let original_audit_hash = {
        let view = app.state.view();
        HashOf::new(
            view.world()
                .soracloud_service_audit_events()
                .get(&1)
                .expect("original executed deployment audit"),
        )
    };
    // Future/corrupt capacity catalogs are intentional routing projections, not
    // startup, commit, recovery or native-proof fixtures. The canonical owner
    // requires no committed runtime catalog and retains the genuine World.
    app.state
        .install_synthetic_routing_snapshot_for_testing(nexus);
    assert_eq!(
        app.state.resolve_route_authority(global_route).unwrap(),
        original_global_authority
    );
    {
        let view = app.state.view();
        assert_eq!(view.height(), 1, "genuine signed deployment height");
        let audit = view
            .world()
            .soracloud_service_audit_events()
            .get(&1)
            .expect("executed deployment lifecycle audit");
        assert_eq!(
            HashOf::new(audit),
            original_audit_hash,
            "routing projection cannot replace the executed lifecycle event"
        );
        audit
            .validate()
            .expect("original lifecycle audit is canonical");
        assert_eq!(
            audit.action,
            iroha_data_model::soracloud::SoraServiceLifecycleActionV1::Deploy
        );
        assert_eq!(audit.signer, *authority.expect_single_signatory());
        assert_eq!(audit.to_version, "2026.02.0");
    }
    app
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn soracloud_status_handler_returns_snapshot_sections() {
    let mut app = soracloud_status_app_for_test(iroha_config::parameters::actual::Nexus::default());
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .soracloud_runtime = Some(Arc::new(TestLocalReadRuntime::snapshot_only(
        sample_soracloud_runtime_snapshot(
            iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        ),
    )));
    let response = super::handler_soracloud_status(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        None,
    )
    .await
    .expect("soracloud status should succeed");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = decode_torii_json(response, "collect body", "decode JSON response").await;
    assert_eq!(
        payload
            .get("schema_version")
            .and_then(norito::json::Value::as_u64),
        Some(1)
    );
    for (section, diagnostic) in [
        ("service_health", "service_health section should be present"),
        ("routing", "routing section should be present"),
        (
            "hosted_http_topology",
            "hosted_http_topology section should be present",
        ),
        (
            "resource_pressure",
            "resource_pressure section should be present",
        ),
        (
            "failed_admissions",
            "failed_admissions section should be present",
        ),
        ("control_plane", "control_plane section should be present"),
        (
            "runtime_manager",
            "runtime_manager section should be present",
        ),
    ] {
        assert!(
            payload
                .get(section)
                .and_then(norito::json::Value::as_object)
                .is_some(),
            "{diagnostic}"
        );
    }
    assert_eq!(
        payload
            .get("failed_admissions")
            .and_then(norito::json::Value::as_object)
            .and_then(|value| value.get("available"))
            .and_then(norito::json::Value::as_bool),
        Some(cfg!(feature = "telemetry"))
    );
    assert_eq!(
        payload
            .get("service_health")
            .and_then(norito::json::Value::as_object)
            .and_then(|value| value.get("mode"))
            .and_then(norito::json::Value::as_str),
        Some("embedded_runtime_manager")
    );
}
#[cfg(feature = "app_api")]
async fn soracloud_status_routing_for_test(
    nexus: iroha_config::parameters::actual::Nexus,
) -> norito::json::Map {
    let app = soracloud_status_app_for_test(nexus);
    let response = super::handler_soracloud_status(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        None,
    )
    .await
    .expect("soracloud status should succeed");
    assert_eq!(response.status(), StatusCode::OK);
    decode_torii_json(response, "collect body", "decode JSON response")
        .await
        .get("routing")
        .and_then(norito::json::Value::as_object)
        .expect("routing section")
        .clone()
}
#[cfg(feature = "app_api")]
fn soracloud_routing_count(routing: &norito::json::Map, field: &str) -> Option<u64> {
    routing.get(field).and_then(norito::json::Value::as_u64)
}
#[cfg(feature = "app_api")]
fn soracloud_routing_lane_ids(routing: &norito::json::Map, field: &str) -> Option<Vec<u64>> {
    routing
        .get(field)
        .and_then(norito::json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(norito::json::Value::as_u64)
                .collect()
        })
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn soracloud_status_routing_counts_only_active_autoscale_capacity_lanes() {
    let future_lane = LaneId::new(1);
    let mut future_autoscale_lane = iroha_data_model::nexus::LaneConfig {
        id: future_lane,
        alias: "elastic-lane-1".to_owned(),
        visibility: iroha_data_model::nexus::LaneVisibility::Public,
        ..iroha_data_model::nexus::LaneConfig::default()
    };
    future_autoscale_lane.metadata.insert(
        iroha_data_model::nexus::AUTOSCALE_META_MANAGED.to_owned(),
        "true".to_owned(),
    );
    future_autoscale_lane.metadata.insert(
        iroha_data_model::nexus::AUTOSCALE_META_CREATED_HEIGHT.to_owned(),
        "7".to_owned(),
    );
    let lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
        NonZeroU32::new(2).expect("nonzero lane count"),
        vec![
            iroha_data_model::nexus::LaneConfig::default(),
            future_autoscale_lane,
        ],
    )
    .expect("future-created autoscale lane catalog");
    let mut nexus = iroha_config::parameters::actual::Nexus {
        lane_config: iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog),
        lane_catalog,
        ..iroha_config::parameters::actual::Nexus::default()
    };
    nexus.autoscale.enabled = true;
    nexus.autoscale.min_lane_id = NonZeroU32::new(1).expect("nonzero min lanes");
    nexus.autoscale.max_lane_id_exclusive = NonZeroU32::new(2).expect("nonzero max lanes");
    let routing = soracloud_status_routing_for_test(nexus).await;
    assert_eq!(
        soracloud_routing_count(&routing, "configured_lane_count"),
        Some(2)
    );
    assert!(
        routing.get("lane_count").is_none(),
        "first-release status must not expose the retired lane-count alias"
    );
    assert_eq!(
        soracloud_routing_count(&routing, "declared_lane_count"),
        Some(2),
        "declared lane count reports catalog metadata entries"
    );
    assert_eq!(
        soracloud_routing_count(&routing, "active_lane_count"),
        Some(1),
        "future-created autoscale lanes must not count as active"
    );
    assert_eq!(
        soracloud_routing_lane_ids(&routing, "active_lane_ids"),
        Some(vec![0])
    );
    assert_eq!(
        soracloud_routing_count(&routing, "autoscale_capacity_lane_count"),
        Some(0),
        "future-created autoscale lanes must not count as live capacity"
    );
    assert!(
        soracloud_routing_lane_ids(&routing, "autoscale_capacity_lane_ids")
            .is_some_and(|ids| ids.is_empty()),
        "future-created autoscale lanes must be absent from capacity ids"
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn soracloud_status_routing_reports_sparse_configured_lane_namespace() {
    let lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
        NonZeroU32::new(4).expect("nonzero lane namespace"),
        vec![iroha_data_model::nexus::LaneConfig::default()],
    )
    .expect("sparse lane catalog");
    let nexus = iroha_config::parameters::actual::Nexus {
        lane_config: iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog),
        lane_catalog,
        ..iroha_config::parameters::actual::Nexus::default()
    };
    let routing = soracloud_status_routing_for_test(nexus).await;
    assert_eq!(
        soracloud_routing_count(&routing, "configured_lane_count"),
        Some(4),
        "configured count must report the lane namespace size"
    );
    assert!(
        routing.get("lane_count").is_none(),
        "first-release status must not expose the retired lane-count alias"
    );
    assert_eq!(
        soracloud_routing_count(&routing, "declared_lane_count"),
        Some(1),
        "declared count reports only catalog metadata entries"
    );
    assert_eq!(
        soracloud_routing_count(&routing, "active_lane_count"),
        Some(1)
    );
    assert_eq!(
        soracloud_routing_lane_ids(&routing, "active_lane_ids"),
        Some(vec![0])
    );
    assert_eq!(
        soracloud_routing_count(&routing, "autoscale_capacity_lane_count"),
        Some(0)
    );
    assert!(
        soracloud_routing_lane_ids(&routing, "autoscale_capacity_lane_ids")
            .is_some_and(|ids| ids.is_empty())
    );
}
#[test]
#[cfg(feature = "app_api")]
fn soracloud_hosted_http_topology_section_excludes_inactive_validator() {
    let mut world = seed_public_soracloud_world();
    let service_name: iroha_model_base::name::Name =
        "web_portal".parse().expect("hosted topology service");
    let service_version = "2026.02.0";
    let alice_peer_id = PeerId::from(ALICE_ID.expect_single_signatory().clone()).to_string();
    let (validator_two, validator_two_peer_id) = checked_torii_test_inrou_host_identity(
        0x7d,
        "derive canonical hosted HTTP topology second validator host fixture key",
    );
    let validator_two_peer_id = validator_two_peer_id.to_string();
    let mut bundle = world
        .view()
        .soracloud_service_revisions()
        .get(&(service_name.to_string(), service_version.to_owned()))
        .cloned()
        .expect("public service bundle");
    bundle.container.runtime = iroha_data_model::soracloud::SoraContainerRuntimeV1::Inrou;
    bundle.container.inrou = Some(test_inrou_manifest());
    bundle.container.entrypoint = "/app/main".to_owned();
    bundle.service.execution_plane =
        iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService;
    bundle.service.replicas = std::num::NonZeroU16::new(2).expect("replicas");
    bundle.service.placement_targets = BTreeSet::from([
        iroha_data_model::soracloud::SoraInrouPlacementTargetV1 {
            validator_account_id: ALICE_ID.clone(),
            peer_id: alice_peer_id.clone(),
        },
        iroha_data_model::soracloud::SoraInrouPlacementTargetV1 {
            validator_account_id: validator_two.clone(),
            peer_id: validator_two_peer_id.clone(),
        },
    ]);
    bundle.service.state_bindings.clear();
    bundle.service.handlers.clear();
    bundle.service.artifacts.clear();
    bundle.service.lease_volumes = vec![iroha_data_model::soracloud::SoraLeaseVolumeBindingV1 {
        volume_name: "root_disk".parse().expect("volume"),
        kind: iroha_data_model::soracloud::SoraLeaseVolumeKindV1::PersistentRootLeaseVolume,
        storage_class: iroha_data_model::sorafs::pin_registry::StorageClass::Warm,
        mount_path: "/".to_owned(),
        max_total_bytes: std::num::NonZeroU64::new(1024 * 1024 * 1024).expect("bytes"),
    }];
    bundle
        .service
        .lease_volumes
        .push(iroha_data_model::soracloud::SoraLeaseVolumeBindingV1 {
            volume_name: "service_state".parse().expect("volume"),
            kind: iroha_data_model::soracloud::SoraLeaseVolumeKindV1::ServiceLeaseVolume,
            storage_class: iroha_data_model::sorafs::pin_registry::StorageClass::Warm,
            mount_path: "/var/lib/soracloud/volumes/service_state".to_owned(),
            max_total_bytes: NonZeroU64::new(1024 * 1024).expect("bytes"),
        });
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    bundle
        .validate_for_admission()
        .expect("hosted topology bundle must pass production admission");
    world.soracloud_service_revisions_mut_for_testing().insert(
        (service_name.to_string(), service_version.to_owned()),
        bundle.clone(),
    );
    let mut service_lease = hosted_http_service_lease_state(
        iroha_data_model::soracloud::SoraServiceLeaseStatusV1::Active,
        "50".parse().expect("runtime balance"),
        u64::MAX,
    );
    service_lease.replica_count = bundle.service.replicas;
    let mut deployment = world
        .view()
        .soracloud_service_deployments()
        .get(&service_name)
        .cloned()
        .expect("public service deployment");
    deployment.current_service_manifest_hash = bundle.service_manifest_hash();
    deployment.current_container_manifest_hash = bundle.container_manifest_hash();
    deployment.service_lease = Some(service_lease.clone());
    deployment.lease_volume_states = hosted_http_lease_volume_states(&bundle, Some(&service_lease));
    deployment
        .validate()
        .expect("hosted topology deployment must pass production validation");
    iroha_core::soracloud_runtime::validate_soracloud_deployment_lease_volume_bindings(
        &deployment,
        &bundle,
    )
    .expect("hosted topology storage rows must exactly match the admitted bundle");
    world
        .soracloud_service_deployments_mut_for_testing()
        .insert(service_name, deployment);
    for (validator_account_id, status, peer_id) in [
        (
            ALICE_ID.clone(),
            iroha_data_model::nexus::staking::PublicLaneValidatorStatus::Active,
            alice_peer_id.clone(),
        ),
        (
            validator_two.clone(),
            iroha_data_model::nexus::staking::PublicLaneValidatorStatus::Exited,
            validator_two_peer_id.clone(),
        ),
    ] {
        let deactivation_height = matches!(
            &status,
            iroha_data_model::nexus::staking::PublicLaneValidatorStatus::Exited
        )
        .then_some(1);
        {
            let mut stake_block = world.block();
            let mut stake_tx = stake_block.transaction_without_telemetry(
                iroha_config::parameters::actual::LaneConfig::default(),
                0,
            );
            stake_tx.public_lane_stake_shares_mut_for_testing().insert(
                (
                    iroha_model_base::topology::LaneId::SINGLE,
                    validator_account_id.clone(),
                    validator_account_id.clone(),
                ),
                iroha_data_model::nexus::PublicLaneStakeShare {
                    lane_id: iroha_model_base::topology::LaneId::SINGLE,
                    validator: validator_account_id.clone(),
                    staker: validator_account_id.clone(),
                    bonded: Quantity::from(1_u64),
                    pending_unbonds: BTreeMap::new(),
                    metadata: Default::default(),
                },
            );
            stake_tx.apply();
            stake_block.commit();
        }
        world.public_lane_validators_mut_for_testing().insert(
            (
                iroha_model_base::topology::LaneId::SINGLE,
                validator_account_id.clone(),
            ),
            iroha_data_model::nexus::staking::PublicLaneValidatorRecord {
                lane_id: iroha_model_base::topology::LaneId::SINGLE,
                validator: validator_account_id.clone(),
                peer_id: peer_id.parse().expect("validator peer id"),
                stake_account: validator_account_id,
                total_stake: Quantity::from(1_u64),
                self_stake: Quantity::from(1_u64),
                metadata: iroha_model_base::metadata::Metadata::default(),
                status,
                activation_height: 1,
                election_exit_height: deactivation_height,
                deactivation_height,
            },
        );
    }
    let alice_capability = iroha_data_model::soracloud::SoraInrouHostCapabilityRecordV1 {
        schema_version: iroha_data_model::soracloud::SORA_INROU_HOST_CAPABILITY_RECORD_VERSION_V1,
        validator_account_id: ALICE_ID.clone(),
        peer_id: alice_peer_id.clone(),
        supported_guest_isas: std::collections::BTreeSet::from([
            iroha_data_model::soracloud::SoraInrouGuestIsaV1::X8664,
        ]),
        trusted_guest_artifact:
            iroha_data_model::soracloud::SoraPublishedInrouGuestImageArtifactV1 {
                manifest_digest_hex: "31".repeat(32),
                content_cid: "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge"
                    .to_owned(),
            },
        max_hosted_replica_capacity:
            iroha_data_model::soracloud::SORA_INROU_HOSTED_REPLICA_CAPACITY_V1,
        max_cpu_millis: 2_000,
        max_memory_bytes: 2 * 1024 * 1024 * 1024,
        max_storage_bytes: 16 * 1024 * 1024 * 1024,
        advertised_at_ms: 1,
        heartbeat_expires_at_ms: u64::MAX,
    };
    alice_capability
        .validate()
        .expect("active topology capability fixture must be production-valid");
    world
        .soracloud_inrou_host_capabilities_mut_for_testing()
        .insert(ALICE_ID.clone(), alice_capability);
    let validator_two_capability = iroha_data_model::soracloud::SoraInrouHostCapabilityRecordV1 {
        schema_version: iroha_data_model::soracloud::SORA_INROU_HOST_CAPABILITY_RECORD_VERSION_V1,
        validator_account_id: validator_two.clone(),
        peer_id: validator_two_peer_id.clone(),
        supported_guest_isas: std::collections::BTreeSet::from([
            iroha_data_model::soracloud::SoraInrouGuestIsaV1::X8664,
        ]),
        trusted_guest_artifact:
            iroha_data_model::soracloud::SoraPublishedInrouGuestImageArtifactV1 {
                manifest_digest_hex: "31".repeat(32),
                content_cid: "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge"
                    .to_owned(),
            },
        max_hosted_replica_capacity:
            iroha_data_model::soracloud::SORA_INROU_HOSTED_REPLICA_CAPACITY_V1,
        max_cpu_millis: 1_000,
        max_memory_bytes: 1024 * 1024 * 1024,
        max_storage_bytes: 8 * 1024 * 1024 * 1024,
        advertised_at_ms: 1,
        heartbeat_expires_at_ms: u64::MAX,
    };
    validator_two_capability
        .validate()
        .expect("inactive topology capability fixture must still be production-valid");
    world
        .soracloud_inrou_host_capabilities_mut_for_testing()
        .insert(validator_two.clone(), validator_two_capability);
    let placement_record = iroha_data_model::soracloud::SoraInrouServicePlacementRecordV1 {
        schema_version: iroha_data_model::soracloud::SORA_INROU_SERVICE_PLACEMENT_RECORD_VERSION_V1,
        service_name: "web_portal".parse().expect("service"),
        service_version: "2026.02.0".to_owned(),
        desired_replica_count: 2,
        eligible_validator_count: 2,
        placements: vec![
            iroha_data_model::soracloud::SoraInrouReplicaPlacementV1 {
                replica_slot: 1,
                economic_clock:
                    iroha_data_model::soracloud::SoraServiceLeaseClockV1::CanonicalBlockHeight,
                lease_started_height: 1,
                placement_incarnation: iroha_crypto::Hash::new(b"placement-1"),
                host_availability:
                    iroha_data_model::soracloud::SoraInrouReplicaHostAvailabilityV1::Available,
                validator_account_id: ALICE_ID.clone(),
                peer_id: alice_peer_id,
                selected_guest_isa: iroha_data_model::soracloud::SoraInrouGuestIsaV1::X8664,
            },
            iroha_data_model::soracloud::SoraInrouReplicaPlacementV1 {
                replica_slot: 2,
                economic_clock:
                    iroha_data_model::soracloud::SoraServiceLeaseClockV1::CanonicalBlockHeight,
                lease_started_height: 1,
                placement_incarnation: iroha_crypto::Hash::new(b"placement-2"),
                host_availability:
                    iroha_data_model::soracloud::SoraInrouReplicaHostAvailabilityV1::Unavailable,
                validator_account_id: validator_two,
                peer_id: validator_two_peer_id,
                selected_guest_isa: iroha_data_model::soracloud::SoraInrouGuestIsaV1::X8664,
            },
        ],
        reconciled_at_ms: 1,
        last_error: None,
    };
    placement_record
        .validate()
        .expect("topology placement fixture must be production-valid");
    world
        .soracloud_inrou_service_placements_mut_for_testing()
        .insert(
            ("web_portal".to_owned(), "2026.02.0".to_owned()),
            placement_record,
        );
    let app = mk_hosted_http_app_with_world(world);
    let topology = super::soracloud_hosted_http_topology_section(&app);
    assert_eq!(
        topology
            .get("active_capability_adverts")
            .and_then(norito::json::Value::as_u64),
        Some(1),
        "inactive validators must not contribute live topology adverts"
    );
    assert_eq!(
        topology
            .get("placed_host_count")
            .and_then(norito::json::Value::as_u64),
        Some(1),
        "inactive validators must not contribute placed hosts"
    );
    assert_eq!(
        topology
            .get("hosted_replica_count")
            .and_then(norito::json::Value::as_u64),
        Some(1),
        "inactive validators must not contribute hosted replicas"
    );
    assert_eq!(
        topology
            .get("unavailable_replica_count")
            .and_then(norito::json::Value::as_u64),
        Some(1)
    );
    assert!(topology.get("backend_mix").is_none());
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn soracloud_runtime_status_sections_report_degraded_for_hydrating_snapshots() {
    let mut app = mk_app_state_for_tests();
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .soracloud_runtime = Some(Arc::new(TestLocalReadRuntime::snapshot_only(
        sample_soracloud_runtime_snapshot(
            iroha_data_model::soracloud::SoraServiceHealthStatusV1::Hydrating,
        ),
    )));
    let (service_health, _runtime_pressure, runtime_manager) =
        super::soracloud_runtime_status_sections(&app);
    assert_eq!(
        service_health
            .get("status")
            .and_then(norito::json::Value::as_str),
        Some("degraded")
    );
    assert_eq!(
        runtime_manager
            .get("available")
            .and_then(norito::json::Value::as_bool),
        Some(true)
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn soracloud_runtime_status_sections_report_unavailable_without_runtime() {
    let app = mk_app_state_for_tests();
    let (service_health, runtime_pressure, runtime_manager) =
        super::soracloud_runtime_status_sections(&app);
    assert_eq!(
        service_health
            .get("status")
            .and_then(norito::json::Value::as_str),
        Some("unavailable")
    );
    assert_eq!(
        runtime_pressure
            .get("enabled")
            .and_then(norito::json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        runtime_manager
            .get("available")
            .and_then(norito::json::Value::as_bool),
        Some(false)
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn proof_rate_limit_sets_retry_after_header() {
    let mut app = mk_app_state_for_tests();
    {
        let state = Arc::get_mut(&mut app).expect("unique app state");
        state.proof_rate_limiter = limits::RateLimiter::new(Some(1), Some(1));
        state.proof_limits = routing::ProofApiLimits::new(
            10,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(3),
            usize::try_from(iroha_config::parameters::defaults::torii::PROOF_MAX_BODY_BYTES.get())
                .expect("proof body limit fits target address space"),
            std::time::Duration::from_millis(
                iroha_config::parameters::defaults::torii::PROOF_BODY_READ_TIMEOUT_MS,
            ),
        );
    }
    let headers = HeaderMap::new();
    let q = crate::NoritoQuery(routing::ProofListQuery {
        limit: Some(1),
        ..Default::default()
    });
    let first = super::handler_list_proofs(
        State(app.clone()),
        headers.clone(),
        crate::loopback_connect_info(),
        q.clone(),
    )
    .await
    .expect("first request allowed")
    .into_response();
    assert_eq!(first.status(), axum::http::StatusCode::OK);
    let resp = match super::handler_list_proofs(
        State(app.clone()),
        headers,
        crate::loopback_connect_info(),
        q,
    )
    .await
    {
        Ok(_) => panic!("second request should be throttled"),
        Err(err) => err.into_response(),
    };
    assert_eq!(resp.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    let retry_after = resp.headers().get(axum::http::header::RETRY_AFTER);
    assert_eq!(retry_after.and_then(|h| h.to_str().ok()), Some("3"));
}
#[tokio::test]
async fn policy_rate_limit_keys_transport_remote_when_internal_header_missing() {
    let mut app = mk_app_state_for_tests();
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .rate_limiter = limits::RateLimiter::new(Some(1), Some(1));
    let first = super::handler_policy(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::ConnectInfo(SocketAddr::from(([198, 51, 100, 10], 0))),
    )
    .await
    .expect("first policy request should be allowed")
    .into_response();
    assert_eq!(first.status(), StatusCode::OK);
    let second = super::handler_policy(
        State(app),
        HeaderMap::new(),
        axum::extract::ConnectInfo(SocketAddr::from(([198, 51, 100, 11], 0))),
    )
    .await
    .expect("second policy request from a different remote should use a separate bucket")
    .into_response();
    assert_eq!(second.status(), StatusCode::OK);
}
#[cfg(feature = "profiling")]
#[tokio::test]
async fn profiling_enforces_token_policy() {
    let mut app = mk_app_state_for_tests();
    {
        let state = Arc::get_mut(&mut app).expect("unique app state");
        state.require_api_token = true;
        state.api_token_digests = Arc::new(limits::ApiTokenDigestSet::from_tokens(["token-456"]));
    }
    let params: routing::profiling::ProfileParams =
        norito::json::from_value(norito::json!({})).expect("defaults");
    let headers = HeaderMap::new();
    let missing = super::handler_profile(
        State(app.clone()),
        headers.clone(),
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        AxQuery(params),
    )
    .await;
    assert!(matches!(
        missing,
        Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
        )))
    ));
    let mut headers_with_token = HeaderMap::new();
    headers_with_token.insert("x-api-token", HeaderValue::from_static("token-456"));
    let ok = super::handler_profile(
        State(app),
        headers_with_token,
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        AxQuery(norito::json::from_value(norito::json!({})).expect("defaults for second run")),
    )
    .await
    .expect("token accepted");
    assert!(!ok.is_empty());
}
#[cfg(feature = "schema")]
#[tokio::test]
async fn schema_handler_ok() {
    let app = mk_app_state_for_tests();
    let headers = HeaderMap::new();
    let resp = super::handler_schema(
        State(app),
        headers,
        axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
    )
    .await
    .expect("ok")
    .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn telemetry_handlers_ok() {
    let app = mk_app_state_for_tests();
    let headers = HeaderMap::new();
    // Status root
    let resp = super::handler_status_root(
        State(app.clone()),
        headers.clone(),
        None,
        axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
    )
    .await
    .expect("ok")
    .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    // Exact status probes
    let remote = axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    let resp = super::handler_status_blocks(State(app.clone()), headers.clone(), remote)
        .await
        .expect("blocks status")
        .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let resp = super::handler_status_peers(State(app.clone()), headers.clone(), remote)
        .await
        .expect("peers status")
        .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    // Metrics
    let text = super::handler_metrics(
        State(app.clone()),
        headers.clone(),
        axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
    )
    .await
    .expect("ok");
    assert!(!text.is_empty());
    app.state.metrics().set_axt_proof_cache_state(
        iroha_model_base::topology::DataSpaceId::new(1),
        "miss",
        [0x11; 32],
        2,
        Some(5),
    );
    app.state.metrics().set_axt_reject_hint(
        DataSpaceId::new(1),
        LaneId::new(7),
        10,
        2,
        AxtRejectReason::HandleEra,
    );
    let resp = super::handler_debug_axt_cache(
        State(app.clone()),
        headers.clone(),
        crate::loopback_connect_info(),
    )
    .await
    .expect("ok")
    .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = torii_body_bytes(resp, "read body").await;
    let body = String::from_utf8(body.to_vec()).expect("utf8 body");
    let body_json: norito::json::Value = norito::json::from_str(&body).expect("cache status json");
    let entries = body_json
        .get("entries")
        .and_then(norito::json::Value::as_array)
        .expect("entries array");
    assert!(
        entries.iter().any(|entry| {
            entry.get("status").and_then(norito::json::Value::as_str) == Some("miss")
        }),
        "cache status response should include miss entry"
    );
    assert!(
        body_json
            .get("snapshot_version")
            .and_then(norito::json::Value::as_u64)
            .is_some(),
        "cache status response should include snapshot version"
    );
    let hints = body_json
        .get("reject_hints")
        .and_then(norito::json::Value::as_array)
        .expect("reject_hints array");
    assert_eq!(hints.len(), 1, "reject hints should include dsid=1");
    let hint = &hints[0];
    assert_eq!(
        hint.get("dataspace").and_then(norito::json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        hint.get("target_lane")
            .and_then(norito::json::Value::as_u64),
        Some(7)
    );
    assert_eq!(
        hint.get("active_handle_era")
            .and_then(norito::json::Value::as_u64),
        Some(10)
    );
    assert_eq!(
        hint.get("next_handle_counter")
            .and_then(norito::json::Value::as_u64),
        Some(2)
    );
    assert_eq!(
        hint.get("reason").and_then(norito::json::Value::as_str),
        Some(AxtRejectReason::HandleEra.label())
    );
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn telemetry_params_and_bls_keys_ok() {
    let app = mk_app_state_for_tests();
    let headers = HeaderMap::new();
    let resp = super::handler_sumeragi_params(
        State(app.clone()),
        headers.clone(),
        crate::loopback_connect_info(),
    )
    .await
    .expect("ok")
    .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let resp =
        super::handler_sumeragi_bls_keys(State(app), headers, crate::loopback_connect_info())
            .await
            .expect("ok")
            .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn app_api_vk_and_proofs_lists_ok() {
    let app = mk_app_state_for_tests();
    let headers = HeaderMap::new();
    // List VKs
    let resp = super::handler_list_vk(
        State(app.clone()),
        headers.clone(),
        crate::loopback_connect_info(),
        AxQuery(crate::routing::VkListQuery::default()),
    )
    .await
    .expect("ok")
    .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    // List proofs
    let resp = super::handler_list_proofs(
        State(app.clone()),
        headers.clone(),
        crate::loopback_connect_info(),
        AxQuery(crate::routing::ProofListQuery::default()),
    )
    .await
    .expect("ok")
    .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    // Count proofs
    let resp = super::handler_count_proofs(
        State(app.clone()),
        headers,
        crate::loopback_connect_info(),
        AxQuery(crate::routing::ProofListQuery::default()),
    )
    .await
    .expect("ok")
    .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn app_api_get_by_id_not_found_returns_404() {
    let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let key_pair = checked_torii_test_ed25519_keypair(0xc1, "contract artifact read fixture");
    let caller = AccountId::new(key_pair.public_key().clone());
    let mut app = app_with_root_scope_for_handler_test(world_with_account(&caller), false);
    // The exact routing lookup and its authenticated handler both preserve scoped absence.
    let direct = routing::handle_get_contract_code(
        app.state.clone(),
        iroha_data_model::smart_contract::ContractArtifactId::new(
            DataSpaceId::UNIVERSAL,
            Hash::new(b"missing artifact"),
        ),
    )
    .await
    .err()
    .expect("missing scoped artifact must return an error")
    .into_response();
    assert_eq!(direct.status(), axum::http::StatusCode::NOT_FOUND);
    let code_hash = hex::encode(Hash::new(b"missing scoped contract artifact").as_ref());
    let method = axum::http::Method::GET;
    let uri: axum::http::Uri = format!("/v1/contracts/artifacts/0/{code_hash}")
        .parse()
        .expect("canonical scoped artifact URI");
    let headers = signed_network_app_headers(
        app.state.network_id_ref(),
        &caller,
        &key_pair,
        &method,
        &uri,
        &[],
    );
    let verified = crate::app_auth::verify_canonical_network_request(
        &app.state,
        app.state.network_id_ref(),
        &headers,
        &method,
        &uri,
        &[],
        Some(&caller),
        crate::history_producer::HistoryProducerOwner::for_test().allocation_context(),
    )
    .expect("valid exact-network artifact request signature")
    .expect("authenticated artifact reader");
    assert_eq!(verified.account, caller);
    assert_eq!(
        iroha_core::sumeragi::lanes::routing::committed_root_scope(app.state.view().world()),
        Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
    );
    // Contract artifact in the authenticated public dataspace (non-existent).
    let resp = super::handler_get_contract_code(
        State(app.clone()),
        headers.clone(),
        crate::loopback_connect_info(),
        axum::extract::Path(("0".to_string(), code_hash.clone())),
        axum::Extension(verified),
    )
    .await
    .unwrap_or_else(|error| error.into_response());
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    // VK by backend/name (non-existent)
    let resp = super::handler_get_vk_by_backend_name(
        State(app.clone()),
        headers.clone(),
        crate::loopback_connect_info(),
        axum::extract::Path(("halo2/ipa".to_string(), "demo".to_string())),
    )
    .await
    .expect("ok mapping")
    .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    // Proof by backend/hash (non-existent)
    let resp = super::handler_get_proof_by_backend_hash(
        State(app.clone()),
        headers,
        crate::loopback_connect_info(),
        axum::extract::Path((
            "halo2/ipa".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        )),
    )
    .await
    .expect("ok mapping")
    .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    // Authenticated artifact reads still pass through the finite route limiter.
    Arc::get_mut(&mut app)
        .expect("read fixture retains the sole app reference")
        .rate_limiter =
        limits::RateLimiter::new_without_refill_for_tests(std::num::NonZeroU32::MIN);
    for expected in [
        axum::http::StatusCode::NOT_FOUND,
        axum::http::StatusCode::TOO_MANY_REQUESTS,
    ] {
        let headers = signed_network_app_headers(
            app.state.network_id_ref(),
            &caller,
            &key_pair,
            &method,
            &uri,
            &[],
        );
        let verified = crate::app_auth::verify_canonical_network_request(
            &app.state,
            app.state.network_id_ref(),
            &headers,
            &method,
            &uri,
            &[],
            Some(&caller),
            crate::history_producer::HistoryProducerOwner::for_test().allocation_context(),
        )
        .expect("fresh rate-limited request verifies")
        .expect("signed rate-limited caller");
        let response = super::handler_get_contract_code(
            State(app.clone()),
            headers,
            crate::loopback_connect_info(),
            axum::extract::Path(("0".to_string(), code_hash.clone())),
            axum::Extension(verified),
        )
        .await
        .unwrap_or_else(|error| error.into_response());
        assert_eq!(
            response.status(),
            expected,
            "canonical admission retains the finite read budget"
        );
    }
}
struct RuntimeApiRouterFixture {
    router: crate::TestApiRouterRuntime,
    _kiso_child: iroha_futures::supervisor::Child,
}
impl RuntimeApiRouterFixture {
    fn standard(chain_id: &'static str) -> Self {
        let kura = Kura::blank_kura_for_testing();
        let state = Arc::new(IrohaState::new_for_testing(
            World::default(),
            kura.clone(),
            LiveQueryStore::start_test(),
        ));
        Self::with_runtime(
            chain_id,
            kura,
            state,
            ToriiRuntimeDeps::new(
                crate::build_identity_test_fixture::build_identity(),
                routing::MaybeTelemetry::disabled(),
            ),
        )
    }

    fn with_runtime(
        chain_id: &'static str,
        kura: Arc<Kura>,
        state: Arc<IrohaState>,
        runtime_deps: ToriiRuntimeDeps,
    ) -> Self {
        Self::with_configured_runtime(chain_id, kura, state, runtime_deps, |_| {})
    }

    fn with_configured_runtime(
        chain_id: &'static str,
        kura: Arc<Kura>,
        state: Arc<IrohaState>,
        runtime_deps: ToriiRuntimeDeps,
        configure: impl FnOnce(&mut iroha_config::parameters::actual::Root),
    ) -> Self {
        let mut cfg = crate::test_utils::mk_minimal_root_cfg();
        configure(&mut cfg);
        let (kiso, child) = KisoHandle::start(cfg.clone());
        let queue = Arc::new(Queue::from_config(
            iroha_config::parameters::actual::Queue {
                capacity: NonZeroUsize::new(100).expect("queue capacity non-zero"),
                capacity_per_user: NonZeroUsize::new(100)
                    .expect("queue per-user capacity non-zero"),
                transaction_time_to_live: Duration::from_secs(60),
                ..Default::default()
            },
            tokio::sync::broadcast::channel(1).0,
        ));
        let (_peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
        let torii = Torii::new_with_handle(
            ChainId::from(chain_id),
            *state.network_id_ref(),
            kiso,
            cfg.torii.clone(),
            queue,
            tokio::sync::broadcast::channel(1).0,
            LiveQueryStore::start_test(),
            kura,
            state,
            cfg.common.key_pair.clone(),
            OnlinePeersProvider::new(peers_rx),
            None,
            runtime_deps,
        )
        .expect("valid Torii runtime API fixture");
        Self {
            router: torii
                .api_router_for_tests()
                .expect("test Torii router initializes"),
            _kiso_child: child,
        }
    }

    async fn shutdown(self) {
        self.router.shutdown().await;
    }
}
#[tokio::test]
async fn node_capabilities_http_bootstraps_without_registered_account() {
    // This fixture has an empty world and mounts the production route catalog,
    // including authentication middleware. Calling the handler alone misses
    // the circular dependency between account registration and SDK preflight.
    let fixture = RuntimeApiRouterFixture::standard("public-node-capabilities-test");
    for (path, expected) in [
        ("/v1/node/capabilities", StatusCode::OK),
        ("/v1/privacy/capabilities", StatusCode::UNAUTHORIZED),
        ("/v1/runtime/upgrades", StatusCode::UNAUTHORIZED),
    ] {
        let mut request = Request::builder()
            .method(HttpMethod::GET)
            .uri(path)
            .header(axum::http::header::ACCEPT, "application/json")
            .body(Body::empty())
            .expect("unsigned metadata request");
        request
            .extensions_mut()
            .insert(crate::loopback_connect_info());
        let response = fixture
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("production route response");
        assert_eq!(response.status(), expected, "GET {path}");
        if expected == StatusCode::OK {
            let body = torii_body_bytes(response, "node capabilities body").await;
            let capabilities: crate::runtime::NodeCapabilitiesResponse =
                norito::json::from_slice(&body).expect("typed node capability metadata");
            assert_eq!(capabilities.abi_version, 1);
            assert_eq!(
                capabilities.data_model_version,
                iroha_data_model::DATA_MODEL_VERSION
            );
            assert_eq!(
                capabilities.signed_transaction_schema_hash_hex,
                hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>())
            );
        }
    }
    fixture.shutdown().await;
}
#[cfg(not(feature = "app_api"))]
#[tokio::test]
async fn public_sorafs_gateway_routes_are_mounted_without_app_api() {
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use tower::ServiceExt as _;

    let fixture = RuntimeApiRouterFixture::standard("sorafs-public-gateway-no-app-api-test");
    for path in [
        "/v1/sorafs/cid/example",
        "/.well-known/sorafs/manifest",
        "/sorafs/cid/example",
        "/sorafs/cid/example/index.html",
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .body(Body::empty())
            .expect("public SoraFS gateway mount probe");
        let response = fixture
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("public SoraFS gateway mount response");
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "GET-only public gateway path must remain mounted without app_api: {path}"
        );
    }
    fixture.shutdown().await;
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn retired_server_contract_deploy_routes_are_absent() {
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Method, Request, StatusCode},
    };
    use tower::ServiceExt as _;
    let fixture = RuntimeApiRouterFixture::standard("contracts-router-test");
    for (method, path) in [
        (Method::POST, "/v1/contracts/deploy"),
        (Method::POST, "/v1/contracts/deploy-bundle"),
        (
            Method::GET,
            "/v1/contracts/deploy-bundles/retired-bundle-digest",
        ),
    ] {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
        let response = fixture
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");
    }
    fixture.shutdown().await;
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn retired_storage_pin_route_cannot_mutate_chain_or_local_storage() {
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Method, Request, StatusCode},
    };
    use tower::ServiceExt as _;
    let kura = Kura::blank_kura_for_testing();
    let state = Arc::new(IrohaState::new_for_testing(
        World::default(),
        kura.clone(),
        LiveQueryStore::start_test(),
    ));
    let storage_dir = tempfile::tempdir().expect("storage tempdir");
    let sorafs_node = sorafs_node::NodeHandle::new(
        sorafs_node::config::StorageConfig::builder()
            .enabled(true)
            .data_dir(storage_dir.path().join("storage"))
            .build(),
    );
    let storage = sorafs_node.storage().expect("enabled storage");
    assert_eq!(storage.manifest_count(), 0);
    assert_eq!(state.view().world().pin_manifests().len(), 0);
    // Storage-enabled startup retains durable drain signers even though this
    // retired HTTP route must never submit an instruction or mutate storage.
    let native_signer = |role: SorafsNativeTransactionSignerRoleV1, seed| {
        Arc::new(
            crate::sorafs::native_transaction_signer::tests::TestProvider::new(
                role,
                format!("runtime://sorafs/retired-pin-router/{}", role.as_str()),
                seed,
            ),
        )
    };
    let proof_signer = native_signer(SorafsNativeTransactionSignerRoleV1::ProofOutcome, 0x95);
    let repair_signer = native_signer(SorafsNativeTransactionSignerRoleV1::Repair, 0x96);
    let reserve_signer = native_signer(SorafsNativeTransactionSignerRoleV1::Reserve, 0x97);
    let orderbook_signer = native_signer(SorafsNativeTransactionSignerRoleV1::Orderbook, 0x98);
    let configured_signer =
        |signer: &crate::sorafs::native_transaction_signer::tests::TestProvider| {
            let binding = signer.expected_binding();
            iroha_config::parameters::actual::SorafsNativeTransactionSignerBinding {
                software_credential: None,
                handle: binding.handle().to_owned(),
                authority: binding.authority().clone(),
                algorithm: binding.public_key().algorithm(),
                public_key: binding.public_key().clone(),
                revision: binding.qualification().revision(),
                policy_digest: binding.qualification().policy_digest(),
            }
        };
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_proof_outcome_signer(proof_signer.clone())
    .with_sorafs_repair_transaction_signer(repair_signer.clone())
    .with_sorafs_reserve_transaction_signer(reserve_signer.clone())
    .with_sorafs_orderbook_transaction_signer(orderbook_signer.clone())
    .with_sorafs_node(sorafs_node.clone())
    .with_sorafs_gateway_compliance_feed_transport(Arc::new(
        crate::gateway_runtime_config_tests::TestComplianceFeedTransport,
    ));
    let fixture = RuntimeApiRouterFixture::with_configured_runtime(
        "sorafs-retired-storage-pin-router-test",
        kura,
        Arc::clone(&state),
        runtime_deps,
        |cfg| {
            let expected = sorafs_node.config();
            cfg.torii.sorafs_storage.enabled = expected.enabled();
            cfg.torii.sorafs_storage.data_dir = expected.data_dir().clone();
            cfg.torii
                .sorafs_storage
                .native_transaction_signers
                .proof_outcome = Some(configured_signer(&proof_signer));
            cfg.torii.sorafs_storage.native_transaction_signers.repair =
                Some(configured_signer(&repair_signer));
            cfg.torii.sorafs_storage.native_transaction_signers.reserve =
                Some(configured_signer(&reserve_signer));
            cfg.torii
                .sorafs_storage
                .native_transaction_signers
                .orderbook = Some(configured_signer(&orderbook_signer));
            cfg.torii.sorafs_gateway.compliance =
                Some(crate::gateway_runtime_config_tests::compliance_config(
                    storage_dir
                        .path()
                        .canonicalize()
                        .expect("canonical storage fixture root")
                        .join("compliance.norito"),
                ));
        },
    );
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/v1/sorafs/storage/pin")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"manifest_b64":"AA==","payload_b64":"AA=="}"#,
        ))
        .expect("retired-route probe");
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    let response = fixture
        .router
        .router()
        .oneshot(request)
        .await
        .expect("retired-route response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        storage.manifest_count(),
        0,
        "an HTTP request must not mutate provider-local storage"
    );
    assert_eq!(
        state.view().world().pin_manifests().len(),
        0,
        "an HTTP request must not create pre-commit pin-registry state"
    );
    fixture.shutdown().await;
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn appeal_finance_publication_routes_authenticate_before_decoding() {
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Method, Request, StatusCode},
    };
    use sorafs_node::{
        GovernanceDagRuntimeProviderQualificationV1, GovernanceDagRuntimeSigner,
        GovernanceDagSealedCheckpointStore, GovernanceDagSealedStateRecord,
        GovernanceDagSealedStateSlot, NodeHandle, NodeRuntimeDeps,
    };
    use std::{
        fs,
        path::{Path, PathBuf},
    };
    use tower::ServiceExt as _;
    #[derive(Debug)]
    struct RouterGovernanceDagSigner {
        key_pair: KeyPair,
    }
    impl RouterGovernanceDagSigner {
        const HANDLE: &'static str = "provider:governance-dag:appeal-route-primary";
        const PEER_ID: &'static [u8] = b"12D3KooWAppealRoutePublisher";
        fn new() -> Self {
            Self {
                key_pair: KeyPair::try_from_seed(vec![0x4D; 32], Algorithm::Ed25519)
                    .expect("derive publication-route Governance DAG signer"),
            }
        }
        fn public_key_bytes(&self) -> [u8; 32] {
            let (algorithm, bytes) = self
                .key_pair
                .public_key()
                .try_to_bytes()
                .expect("serialize publication-route Governance DAG public key");
            assert_eq!(algorithm, Algorithm::Ed25519);
            bytes.try_into().expect("Ed25519 public key width")
        }
        fn expected_qualification() -> GovernanceDagRuntimeProviderQualificationV1 {
            GovernanceDagRuntimeProviderQualificationV1::new(1, [0x85; 32])
        }
    }
    impl GovernanceDagRuntimeSigner for RouterGovernanceDagSigner {
        fn handle(&self) -> &str {
            Self::HANDLE
        }
        fn qualification(&self) -> Result<GovernanceDagRuntimeProviderQualificationV1, String> {
            Ok(Self::expected_qualification())
        }
        fn publisher_peer_id(&self) -> &[u8] {
            Self::PEER_ID
        }
        fn public_key(&self) -> [u8; 32] {
            self.public_key_bytes()
        }
        fn sign(
            &self,
            _purpose: sorafs_node::GovernanceDagSigningPurposeV1,
            payload: &[u8],
        ) -> Result<[u8; 64], String> {
            Signature::try_new(self.key_pair.private_key(), payload)
                .map_err(|_| "publication-route Governance DAG signing failed".to_owned())?
                .payload()
                .try_into()
                .map_err(|_| "publication-route Governance DAG signature width changed".to_owned())
        }
    }
    #[derive(Debug)]
    struct RouterGovernanceDagCheckpointState {
        records: [Option<GovernanceDagSealedStateRecord>; 6],
        generation_floors: [u64; 6],
    }
    impl Default for RouterGovernanceDagCheckpointState {
        fn default() -> Self {
            Self {
                records: std::array::from_fn(|_| None),
                generation_floors: [0; 6],
            }
        }
    }
    #[derive(Debug, Default)]
    struct RouterGovernanceDagCheckpointStore {
        state: std::sync::Mutex<RouterGovernanceDagCheckpointState>,
    }
    impl RouterGovernanceDagCheckpointStore {
        const HANDLE: &'static str = "sealed:governance-dag:appeal-route-primary";
        const POLICY_DIGEST: [u8; 32] = [0x86; 32];
        const fn slot_index(slot: GovernanceDagSealedStateSlot) -> usize {
            match slot {
                GovernanceDagSealedStateSlot::Checkpoint => 0,
                GovernanceDagSealedStateSlot::PublishIntent => 1,
                GovernanceDagSealedStateSlot::ProducerCheckpoint => 2,
                GovernanceDagSealedStateSlot::ProducerPublishIntent => 3,
                GovernanceDagSealedStateSlot::IpfsRequestReplay => 4,
                GovernanceDagSealedStateSlot::SignedHeadRequestReplay => 5,
            }
        }
        fn expected_qualification() -> GovernanceDagRuntimeProviderQualificationV1 {
            GovernanceDagRuntimeProviderQualificationV1::new(1, Self::POLICY_DIGEST)
        }
    }
    impl GovernanceDagSealedCheckpointStore for RouterGovernanceDagCheckpointStore {
        fn handle(&self) -> &str {
            Self::HANDLE
        }
        fn qualification(&self) -> Result<GovernanceDagRuntimeProviderQualificationV1, String> {
            Ok(Self::expected_qualification())
        }
        fn load(
            &self,
            slot: GovernanceDagSealedStateSlot,
        ) -> Result<Option<GovernanceDagSealedStateRecord>, String> {
            let state = self.state.lock().map_err(|_| "poisoned".to_owned())?;
            Ok(state.records[Self::slot_index(slot)].clone())
        }
        fn compare_and_swap(
            &self,
            slot: GovernanceDagSealedStateSlot,
            expected_revision: Option<[u8; 32]>,
            next: GovernanceDagSealedStateRecord,
        ) -> Result<(), String> {
            let index = Self::slot_index(slot);
            let mut state = self.state.lock().map_err(|_| "poisoned".to_owned())?;
            if state.records[index].as_ref().map(|record| record.revision) != expected_revision {
                return Err("compare-and-swap conflict".to_owned());
            }
            if next.generation <= state.generation_floors[index]
                || next.payload.is_empty()
                || !next.has_valid_revision(slot)
            {
                return Err("invalid or non-monotonic record".to_owned());
            }
            state.generation_floors[index] = next.generation;
            state.records[index] = Some(next);
            Ok(())
        }
        fn delete(
            &self,
            slot: GovernanceDagSealedStateSlot,
            expected_revision: [u8; 32],
        ) -> Result<(), String> {
            let index = Self::slot_index(slot);
            let mut state = self.state.lock().map_err(|_| "poisoned".to_owned())?;
            if state.records[index].as_ref().map(|record| record.revision)
                != Some(expected_revision)
            {
                return Err("delete conflict".to_owned());
            }
            state.records[index] = None;
            Ok(())
        }
    }
    fn snapshot_files(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        fn visit(root: &Path, directory: &Path, snapshot: &mut Vec<(PathBuf, Option<Vec<u8>>)>) {
            let mut entries = fs::read_dir(directory)
                .unwrap_or_else(|error| {
                    panic!("read snapshot directory {}: {error}", directory.display())
                })
                .map(|entry| entry.expect("read snapshot entry"))
                .collect::<Vec<_>>();
            entries.sort_by_key(std::fs::DirEntry::path);
            for entry in entries {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .expect("snapshot path is rooted")
                    .to_path_buf();
                if entry
                    .file_type()
                    .expect("read snapshot entry type")
                    .is_dir()
                {
                    snapshot.push((relative, None));
                    visit(root, &path, snapshot);
                } else {
                    snapshot.push((
                        relative,
                        Some(fs::read(&path).unwrap_or_else(|error| {
                            panic!("read snapshot file {}: {error}", path.display())
                        })),
                    ));
                }
            }
        }
        let mut snapshot = Vec::new();
        visit(root, root, &mut snapshot);
        snapshot
    }
    let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let caller_key =
        checked_torii_test_ed25519_keypair(0xb5, "rejected publication caller fixture");
    let caller = AccountId::new(caller_key.public_key().clone());
    let publisher_key = checked_torii_test_ed25519_keypair(0xb6, "publication publisher fixture");
    let publisher = AccountId::new(publisher_key.public_key().clone());
    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
    let mut world = World::with(
        [Domain::new(domain_id).build(&caller)],
        [
            Account::new(caller.clone()).build(&caller),
            Account::new(publisher.clone()).build(&publisher),
        ],
        [],
    );
    world.grant_role_for_tests(
        publisher.clone(),
        "sorafs_appeal_finance_publisher"
            .parse()
            .expect("publisher role"),
    );
    let kura = Kura::blank_kura_for_testing();
    let state = Arc::new(IrohaState::new_for_testing(
        world,
        kura.clone(),
        LiveQueryStore::start_test(),
    ));
    let network_id = *state.network_id_ref();
    let storage_dir = tempfile::tempdir().expect("appeal publication storage tempdir");
    let storage_root = storage_dir
        .path()
        .canonicalize()
        .expect("canonical appeal publication storage root");
    let signer = Arc::new(RouterGovernanceDagSigner::new());
    let checkpoint_store = Arc::new(RouterGovernanceDagCheckpointStore::default());
    let sorafs_node = NodeHandle::try_new_with_runtime_deps(
        sorafs_node::config::StorageConfig::builder()
            .enabled(true)
            .data_dir(storage_root.join("storage"))
            .governance_dir(Some(storage_root.join("governance")))
            .governance_dag_publisher_peer_id(Some(
                String::from_utf8(RouterGovernanceDagSigner::PEER_ID.to_vec())
                    .expect("publication-route publisher peer id is UTF-8"),
            ))
            .governance_dag_signer_handle(Some(RouterGovernanceDagSigner::HANDLE.to_owned()))
            .governance_dag_signer_qualification(Some(
                RouterGovernanceDagSigner::expected_qualification(),
            ))
            .governance_dag_checkpoint_store_handle(Some(
                RouterGovernanceDagCheckpointStore::HANDLE.to_owned(),
            ))
            .governance_dag_checkpoint_store_qualification(Some(
                RouterGovernanceDagCheckpointStore::expected_qualification(),
            ))
            .governance_dag_publisher_public_key_hex(Some(hex::encode(signer.public_key_bytes())))
            .build(),
        NodeRuntimeDeps::default()
            .with_governance_dag_signer(signer)
            .with_governance_dag_checkpoint_store(checkpoint_store),
    )
    .expect("initialise runtime-signed Governance DAG publisher");
    assert!(sorafs_node.has_governance_publisher());
    let native_signer = |role: SorafsNativeTransactionSignerRoleV1, seed| {
        Arc::new(
            crate::sorafs::native_transaction_signer::tests::TestProvider::new(
                role,
                format!("runtime://sorafs/publication-router/{}", role.as_str()),
                seed,
            ),
        )
    };
    let proof_signer = native_signer(SorafsNativeTransactionSignerRoleV1::ProofOutcome, 0x91);
    let repair_signer = native_signer(SorafsNativeTransactionSignerRoleV1::Repair, 0x92);
    let reserve_signer = native_signer(SorafsNativeTransactionSignerRoleV1::Reserve, 0x93);
    let orderbook_signer = native_signer(SorafsNativeTransactionSignerRoleV1::Orderbook, 0x94);
    let configured_signer =
        |signer: &crate::sorafs::native_transaction_signer::tests::TestProvider| {
            let binding = signer.expected_binding();
            iroha_config::parameters::actual::SorafsNativeTransactionSignerBinding {
                software_credential: None,
                handle: binding.handle().to_owned(),
                authority: binding.authority().clone(),
                algorithm: binding.public_key().algorithm(),
                public_key: binding.public_key().clone(),
                revision: binding.qualification().revision(),
                policy_digest: binding.qualification().policy_digest(),
            }
        };
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_proof_outcome_signer(proof_signer.clone())
    .with_sorafs_repair_transaction_signer(repair_signer.clone())
    .with_sorafs_reserve_transaction_signer(reserve_signer.clone())
    .with_sorafs_orderbook_transaction_signer(orderbook_signer.clone())
    .with_sorafs_node(sorafs_node.clone())
    .with_sorafs_gateway_compliance_feed_transport(Arc::new(
        crate::gateway_runtime_config_tests::TestComplianceFeedTransport,
    ));
    let fixture = RuntimeApiRouterFixture::with_configured_runtime(
        "sorafs-appeal-publication-router-test",
        kura,
        state,
        runtime_deps,
        |cfg| {
            // The mounted runtime must retain the exact public signer and sealed
            // checkpoint-store policy of this fixture's prebuilt publisher.
            let expected = sorafs_node.config();
            cfg.torii.sorafs_gateway.compliance =
                Some(crate::gateway_runtime_config_tests::compliance_config(
                    storage_root.join("compliance.json"),
                ));
            let storage = &mut cfg.torii.sorafs_storage;
            storage.enabled = expected.enabled();
            storage.native_transaction_signers.proof_outcome =
                Some(configured_signer(&proof_signer));
            storage.native_transaction_signers.repair = Some(configured_signer(&repair_signer));
            storage.native_transaction_signers.reserve = Some(configured_signer(&reserve_signer));
            storage.native_transaction_signers.orderbook =
                Some(configured_signer(&orderbook_signer));
            storage.data_dir = expected.data_dir().clone();
            storage.governance_dag_dir = expected.governance_dir().cloned();
            storage.governance_dag_publisher_peer_id =
                expected.governance_dag_publisher_peer_id().cloned();
            storage.governance_dag_publisher_public_key_hex =
                expected.governance_dag_publisher_public_key_hex().cloned();
            storage.governance_dag_signer_handle = expected.governance_dag_signer_handle().cloned();
            let signer = expected.governance_dag_signer_qualification().unwrap();
            storage.governance_dag_signer_revision = Some(signer.revision);
            storage.governance_dag_signer_policy_digest = Some(signer.policy_digest);
            let store = expected
                .governance_dag_checkpoint_store_qualification()
                .unwrap();
            storage.governance_dag_service.checkpoint_store_handle =
                expected.governance_dag_checkpoint_store_handle().cloned();
            storage.governance_dag_service.checkpoint_store_revision = Some(store.revision);
            storage
                .governance_dag_service
                .checkpoint_store_policy_digest = Some(store.policy_digest);
        },
    );
    let router = fixture.router.router();
    let files_before = snapshot_files(&storage_root);
    let pending_before = sorafs_node.pending_governance_publication_count();
    for path in [
        "/v1/sorafs/appeals/finance/reports",
        "/v1/sorafs/appeals/finance/weekly-rollups",
    ] {
        for (identity, expected, expected_error) in [
            (None, StatusCode::UNAUTHORIZED, None),
            (
                Some((&caller, &caller_key)),
                StatusCode::FORBIDDEN,
                Some(("forbidden", "The request is not permitted.")),
            ),
            (
                Some((&publisher, &publisher_key)),
                StatusCode::BAD_REQUEST,
                Some(("bad_request", "The request is invalid.")),
            ),
        ] {
            let uri = path.parse().expect("publication URI");
            let mut request = Request::builder()
                .method(Method::POST)
                .uri(&uri)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .header(axum::http::header::ACCEPT, "application/json")
                .body(Body::from("{}"))
                .expect("appeal-finance publication route probe");
            if let Some((authority, key)) = identity {
                request.headers_mut().extend(signed_network_app_headers(
                    &network_id,
                    authority,
                    key,
                    &Method::POST,
                    &uri,
                    b"{}",
                ));
            }
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
            let response = router
                .clone()
                .oneshot(request)
                .await
                .expect("appeal-finance publication route response");
            assert_eq!(response.status(), expected, "{path}, expected={expected}");
            if let Some((code, message)) = expected_error {
                let body = torii_body_bytes(response, "publication rejection body").await;
                let body: norito::json::Value =
                    norito::json::from_slice(&body).expect("publication rejection JSON");
                // The mounted HTTP boundary redacts handler diagnostics. The exact
                // 403-to-400 change proves the publisher passed the role guard.
                assert_eq!(
                    body,
                    norito::json!({ "code": code, "message": message }),
                    "{path}: canonical public error envelope"
                );
            }
        }
    }

    assert_eq!(
        sorafs_node.pending_governance_publication_count(),
        pending_before,
        "rejected publication routes must not enqueue durable Governance work"
    );
    assert_eq!(
        snapshot_files(&storage_root),
        files_before,
        "rejected publication routes must not mutate the Governance DAG, publish index, or durable outbox"
    );
    fixture.shutdown().await;
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn contract_route_mounts_authenticate_mutation_and_compute_before_decode() {
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Method, Request, StatusCode},
    };
    use tower::ServiceExt as _;
    let fixture = RuntimeApiRouterFixture::standard("contracts-aliases-router-test");
    let router = fixture.router.router();
    for path in [
        "/v1/contracts/aliases",
        "/v1/contracts/call/simulate",
        "/v1/contracts/view",
        "/v1/contracts/view/batch",
    ] {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from("{"))
            .expect("request");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("protected route response");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{path} must authenticate the bounded raw body before DTO decoding"
        );
    }
    let mut public_query = Request::builder()
        .method(Method::POST)
        .uri("/v1/sorafs/appeals/pricing/quote")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from("{"))
        .expect("public query request");
    public_query
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    let response = router
        .oneshot(public_query)
        .await
        .expect("public query response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    fixture.shutdown().await;
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn contract_compute_routes_bind_authenticated_authority_before_work() {
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Method, Request},
        routing::post,
    };
    use tower::ServiceExt as _;
    let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let key = checked_torii_test_ed25519_keypair(0xb4, "contract view caller fixture");
    let caller = AccountId::new(key.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&caller));
    let router = axum::Router::new()
        .route(
            "/v1/contracts/view",
            post(super::handler_post_contract_view),
        )
        .route(
            "/v1/contracts/view/batch",
            post(super::handler_post_contract_view_batch),
        )
        .route(
            "/v1/contracts/call/simulate",
            post(super::handler_post_contract_call_simulate),
        )
        .layer(axum::middleware::from_fn_with_state(
            super::CanonicalAccountBodyAuthState {
                app: app.clone(),
                max_body_bytes: 4096,
                missing_auth_code: "canonical_authentication_required",
                missing_auth_message: "canonical account request authentication is required",
            },
            super::enforce_canonical_account_body_authentication,
        ))
        .with_state(app);
    for path in [
        "/v1/contracts/view",
        "/v1/contracts/view/batch",
        "/v1/contracts/call/simulate",
    ] {
        for (authority, expected) in [
            (&*ALICE_ID, StatusCode::FORBIDDEN),
            (&caller, StatusCode::BAD_REQUEST),
        ] {
            let body = if path.ends_with("/batch") {
                norito::json!({"authority": (authority.to_string()), "items": []})
            } else {
                norito::json!({"authority": (authority.to_string()), "entrypoint": "view", "gas_limit": 1})
            };
            let body = norito::json::to_vec(&body).expect("request JSON");
            let uri = path.parse().expect("request URI");
            let headers = signed_app_headers(&caller, &key, &Method::POST, &uri, &body);
            let mut request = Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .expect("signed view request");
            request.headers_mut().extend(headers);
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
            let response = router
                .clone()
                .oneshot(request)
                .await
                .expect("view response");
            assert_eq!(
                response.status(),
                expected,
                "{path}: foreign authority is rejected before target/VM validation; exact caller reaches ordinary request validation"
            );
        }
    }
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn sorafs_capacity_declare_route_is_mounted_in_api_router() {
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Method, Request, StatusCode},
    };
    use tower::ServiceExt as _;
    let fixture = RuntimeApiRouterFixture::standard("sorafs-capacity-declare-router-test");
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/v1/sorafs/capacity/declare")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from("{"))
        .expect("request");
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    let response = fixture
        .router
        .router()
        .oneshot(request)
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    fixture.shutdown().await;
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn retired_sorafs_mutation_routes_are_absent() {
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Method, Request, StatusCode},
    };
    use tower::ServiceExt as _;
    let fixture = RuntimeApiRouterFixture::standard("sorafs-retired-por-router-test");
    let router = fixture.router.router();
    for path in [
        "/v1/sorafs/capacity/dispute",
        "/v1/sorafs/capacity/schedule",
        "/v1/sorafs/capacity/complete",
        "/v1/sorafs/capacity/uptime",
        "/v1/sorafs/capacity/failure",
        "/v1/sorafs/por/trigger",
        "/v1/sorafs/capacity/por-challenge",
        "/v1/sorafs/capacity/por",
        "/v1/sorafs/storage/por-challenge",
        "/v1/sorafs/storage/por-proof",
        "/v1/sorafs/storage/por-verdict",
        "/v1/sorafs/moderation/viewer-audit-reports",
        "/v1/sorafs/moderation/viewer-audit-reports/publish-due",
    ] {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .expect("removed-route probe");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("removed-route response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
    for (method, path) in [
        (Method::POST, "/v1/sorafs/capacity/por-proof"),
        (Method::POST, "/v1/sorafs/capacity/por-verdict"),
        (Method::POST, "/v1/sorafs/por/vrf"),
        (Method::GET, "/v1/sorafs/por/status"),
        (Method::GET, "/v1/sorafs/por/export"),
        (Method::GET, "/v1/sorafs/por/report/2026-W01"),
        (Method::GET, "/v1/evidence/audit"),
        (Method::GET, "/v1/evidence/status"),
    ] {
        let mut request = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .expect("live-route probe");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("live-route response");
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "live SoraFS route was removed accidentally: {method} {path}"
        );
    }
    fixture.shutdown().await;
}
#[test]
fn iso_error_mapping_returns_expected_variants() {
    use iroha_data_model::ValidationFail::{InternalError, NotPermitted};
    assert!(matches!(
        super::map_iso_error(MsgError::InvalidFormat),
        NotPermitted(_)
    ));
    assert!(matches!(
        super::map_iso_error(MsgError::NoActiveMessage),
        InternalError(_)
    ));
}
#[test]
fn push_into_queue_error_sets_backpressure_headers() {
    use nonzero_ext::nonzero;
    let err = super::Error::PushIntoQueue {
        source: Box::new(queue::Error::Full),
        backpressure: queue::BackpressureState::Saturated {
            queued: 5,
            capacity: nonzero!(5_usize),
        },
    };
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let headers = response.headers();
    assert_eq!(
        headers
            .get("X-Iroha-Queue-State")
            .map(|v| v.to_str().unwrap()),
        Some("saturated")
    );
    assert_eq!(
        headers.get("Retry-After").map(|v| v.to_str().unwrap()),
        Some("1")
    );
}
#[test]
fn push_into_queue_error_sets_reject_code_header() {
    use nonzero_ext::nonzero;
    let err = super::Error::PushIntoQueue {
        source: Box::new(queue::Error::InBlockchain),
        backpressure: queue::BackpressureState::Healthy {
            queued: 0,
            capacity: nonzero!(1_usize),
        },
    };
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|v| v.to_str().ok()),
        Some("PRTRY:ALREADY_COMMITTED")
    );
}
#[test]
fn push_into_queue_unresolved_route_maps_to_bad_request() {
    use nonzero_ext::nonzero;
    let err = super::Error::PushIntoQueue {
        source: Box::new(queue::Error::UnresolvedRoute {
            reason: "lane 9 is not present in the lane catalog".to_owned(),
        }),
        backpressure: queue::BackpressureState::Healthy {
            queued: 0,
            capacity: nonzero!(1_usize),
        },
    };
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|v| v.to_str().ok()),
        Some("PRTRY:ROUTE_UNRESOLVED")
    );
}
#[test]
fn push_into_queue_fee_rejections_are_typed_and_redacted() {
    use nonzero_ext::nonzero;
    const PRIVATE_REASON: &str = "private sponsor rule internals";
    for (source, expected_status, expected_code) in [
        (
            queue::Error::NexusFeeAdmissionRejected {
                code: FeeRejectionCode::BeneficiaryNotEligible,
                reason: PRIVATE_REASON.to_owned(),
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            FeeRejectionCode::BeneficiaryNotEligible,
        ),
        (
            queue::Error::NexusFeeAdmissionConfigInvalid {
                code: FeeRejectionCode::InvalidProgramConfiguration,
                reason: PRIVATE_REASON.to_owned(),
            },
            StatusCode::SERVICE_UNAVAILABLE,
            FeeRejectionCode::InvalidProgramConfiguration,
        ),
    ] {
        let (_, public_detail) = queue_rejection_metadata(&source);
        assert!(!public_detail.contains(PRIVATE_REASON));
        assert!(public_detail.contains(expected_code.as_str()));
        let response = super::Error::PushIntoQueue {
            source: Box::new(source),
            backpressure: queue::BackpressureState::Healthy {
                queued: 0,
                capacity: nonzero!(1_usize),
            },
        }
        .into_response();
        assert_eq!(response.status(), expected_status);
        let body = executor::block_on(http_body_util::BodyExt::collect(response.into_body()))
            .expect("fee queue response body")
            .to_bytes();
        assert!(!String::from_utf8_lossy(&body).contains(PRIVATE_REASON));
        let envelope: ErrorEnvelope =
            norito::decode_from_bytes(&body).expect("typed fee queue envelope");
        let fee = envelope
            .details
            .and_then(|details| details.fee)
            .expect("typed fee rejection details");
        assert_eq!(fee.code, expected_code.as_str());
    }
}
#[tokio::test]
async fn serialization_error_emits_redacted_norito_payload() {
    let err = super::Error::SerializationFailure {
        context: "unit_test",
        source: Box::new(norito::json::Error::Message("boom".into())),
    };
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .map(|value| value.to_str().unwrap())
        .expect("content-type header present");
    assert_eq!(content_type, super::utils::NORITO_MIME_TYPE);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let payload = norito::decode_from_bytes::<super::ErrorEnvelope>(&body).unwrap();
    assert_eq!(payload.code(), "serialization_error");
    assert_eq!(payload.message(), "failed to serialize unit_test payload");
    assert!(
        !payload.message().contains("boom"),
        "redacted message leaked internal context"
    );
}
#[tokio::test]
async fn internal_validation_failures_never_expose_their_source_message() {
    const MARKER: &str = "private_runtime_marker_9a2c";
    for format in [ResponseFormat::Json, ResponseFormat::Norito] {
        let response = error_response_with_format(
            super::Error::Query(ValidationFail::InternalError(MARKER.to_owned())),
            format,
        );
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("collect redacted validation response")
            .to_bytes();
        assert!(!String::from_utf8_lossy(&body).contains(MARKER));
        let envelope: super::ErrorEnvelope = match format {
            ResponseFormat::Json => {
                norito::json::from_slice(&body).expect("decode JSON validation error")
            }
            ResponseFormat::Norito => {
                norito::decode_from_bytes(&body).expect("decode Norito validation error")
            }
        };
        assert_eq!(envelope.code(), "internal_server_error");
        assert_eq!(envelope.message(), "Torii could not complete the request.");
        assert!(envelope.details.is_none());
    }
    let response =
        super::Error::Query(ValidationFail::InternalError(MARKER.to_owned())).into_response();
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect direct validation response")
        .to_bytes();
    let envelope: super::ErrorEnvelope =
        norito::decode_from_bytes(&body).expect("decode direct validation error");
    assert_eq!(envelope.code(), "internal_server_error");
    assert!(!envelope.message().contains(MARKER));
}
#[test]
fn accept_transaction_signature_failure_sets_code_and_header() {
    let kp = checked_torii_test_ed25519_keypair(
        0x7f,
        "derive accept-transaction signature failure fixture key",
    );
    let authority = AccountId::of(kp.public_key().clone());
    let tx = TransactionBuilder::new(
        signed_query_test_network_id(),
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(kp.private_key());
    let fail = iroha_core::tx::SignatureVerificationFail::new(
        tx.signature().clone(),
        iroha_core::tx::SignatureRejectionCode::UnsupportedAuthority,
        iroha_data_model::transaction::signed::MULTISIG_SIGNING_UNSUPPORTED_REASON,
    );
    let err = super::Error::AcceptTransaction(
        iroha_core::tx::AcceptTransactionFail::SignatureVerification(fail),
    );
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let headers = response.headers();
    assert_eq!(
        headers
            .get("x-iroha-reject-code")
            .and_then(|v| v.to_str().ok()),
        Some(iroha_core::tx::SignatureRejectionCode::UnsupportedAuthority.as_str())
    );
    let body = executor::block_on(http_body_util::BodyExt::collect(response.into_body()))
        .expect("collect body")
        .to_bytes();
    let envelope =
        norito::decode_from_bytes::<super::ErrorEnvelope>(&body).expect("decode error envelope");
    assert_eq!(
        envelope.code(),
        iroha_core::tx::SignatureRejectionCode::UnsupportedAuthority.as_str()
    );
    assert!(envelope.message().contains("failed to accept transaction"));
}
include!("part_9b_error_headers.rs");

include!("push_rate_limits.rs");
