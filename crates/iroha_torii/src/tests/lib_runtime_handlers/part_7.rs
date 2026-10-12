#[cfg(feature = "app_api")]
fn install_test_local_read_runtime(app: &mut SharedAppState, runtime: TestLocalReadRuntime) {
    let torii_peer_id = runtime
        .local_peer_id
        .as_deref()
        .map(|peer_id| peer_id.parse().expect("valid test runtime peer id"));
    let app = Arc::get_mut(app).expect("unique app state");
    app.local_peer_id = torii_peer_id;
    app.soracloud_runtime = Some(Arc::new(runtime));
}
#[cfg(feature = "app_api")]
fn install_unavailable_local_read_runtime(
    app: &mut SharedAppState,
    local_peer_id: Option<String>,
    message: &'static str,
) {
    install_test_local_read_runtime(
        app,
        TestLocalReadRuntime::unavailable(local_peer_id, message),
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn hosted_connection_driver_panic_is_contained_to_the_proxy_request() {
    let task = super::spawn_soracloud_hosted_connection_driver(async {
        assert!(
            iroha_panic_hook::is_suppressed(),
            "the physical hosted connection driver must suppress the process shutdown hook"
        );
        panic!("injected hosted connection driver panic");
        #[allow(unreachable_code)]
        Ok::<(), &'static str>(())
    });
    assert!(matches!(task.await, Ok(Err(_))));
    assert!(
        !iroha_panic_hook::is_suppressed(),
        "hosted driver suppression must not leak into the request task"
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn soracloud_public_split_app_routes_hosted_live_and_ordered_vault_updates_on_one_node() {
    use tower::ServiceExt as _;
    let TravelSplitTopologyFixture {
        world,
        snapshot,
        temp,
        live_peer_id,
        upstream_task,
    } = travel_split_topology_fixture(TravelSplitVaultMode::OrderedMailbox).await;
    let captured_requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let runtime = TestMailboxRuntime {
        snapshot,
        state_dir: temp.path().to_path_buf(),
        local_peer_id: Some(live_peer_id.to_string()),
        result: Ok(
            iroha_core::soracloud_runtime::SoracloudOrderedMailboxExecutionResult {
                state_mutations: Vec::new(),
                outbound_mailbox_messages: Vec::new(),
                response_bytes: br#"{"status":"queued"}"#.to_vec(),
                content_type: Some("application/json".to_owned()),
                runtime_state: None,
                runtime_receipt: iroha_data_model::soracloud::SoraRuntimeReceiptV1 {
                    schema_version: iroha_data_model::soracloud::SORA_RUNTIME_RECEIPT_VERSION_V1,
                    receipt_id: Hash::new(b"travel-vault-preferences-receipt"),
                    service_name: "travel_ops_vault".parse().expect("service"),
                    service_version: "2026.04.0".to_owned(),
                    handler_name: "preferences_put".parse().expect("handler"),
                    handler_class: iroha_data_model::soracloud::SoraServiceHandlerClassV1::Update,
                    request_commitment: Hash::new(b"travel-vault-preferences-request"),
                    result_commitment: Hash::new(b"travel-vault-preferences-result"),
                    certified_by: iroha_data_model::soracloud::SoraCertifiedResponsePolicyV1::None,
                    emitted_sequence: 1,
                    mailbox_message_id: Some(Hash::new(b"travel-vault-preferences-message")),
                    journal_artifact_hash: None,
                    checkpoint_artifact_hash: None,
                    execution_host: None,
                },
            },
        ),
        captured_requests: Arc::clone(&captured_requests),
    };
    let mut app = mk_hosted_http_app_with_world(world);
    let app_mut = Arc::get_mut(&mut app).expect("unique app state");
    app_mut.local_peer_id = Some(live_peer_id);
    app_mut.soracloud_runtime = Some(Arc::new(runtime));
    let router = axum::Router::new()
        .fallback(any(handler_soracloud_public_local_read))
        .with_state(app);
    let live_response = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/search")
                .header(axum::http::header::HOST, "travel.sora")
                .extension(crate::loopback_connect_info())
                .body(Body::empty())
                .expect("live request"),
        )
        .await
        .expect("live response");
    assert_eq!(live_response.status(), StatusCode::OK);
    let live_body = torii_body_bytes(live_response, "live body").await;
    assert_eq!(live_body.as_ref(), br#"{"source":"live"}"#);
    assert!(
        captured_requests.lock().expect("capture lock").is_empty(),
        "hosted live routes must bypass ordered mailbox execution"
    );
    let vault_payload = br#"{"home_airport":"BNE","cabin_preference":"business"}"#;
    let vault_response = router
        .oneshot(
            axum::http::Request::builder()
                .method("PUT")
                .uri("/api/v1/user/preferences")
                .header(axum::http::header::HOST, "travel.sora")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .extension(crate::loopback_connect_info())
                .body(Body::from(vault_payload.to_vec()))
                .expect("vault request"),
        )
        .await
        .expect("vault response");
    assert_eq!(vault_response.status(), StatusCode::OK);
    let vault_body = torii_body_bytes(vault_response, "vault body").await;
    assert_eq!(vault_body.as_ref(), br#"{"status":"queued"}"#);
    let captured = captured_requests.lock().expect("capture lock");
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].deployment.service_name.as_ref(),
        "travel_ops_vault"
    );
    assert_eq!(
        captured[0]
            .handler
            .as_ref()
            .expect("handler")
            .handler_name
            .as_ref(),
        "preferences_put"
    );
    assert_eq!(
        captured[0].handler.as_ref().expect("handler").class,
        iroha_data_model::soracloud::SoraServiceHandlerClassV1::Update
    );
    assert_eq!(
        captured[0].mailbox_message.payload_bytes.as_slice(),
        vault_payload
    );
    assert_eq!(
        captured[0].mailbox_message.to_handler.as_ref(),
        "preferences_put"
    );
    assert_eq!(captured[0].authoritative_pending_mailbox_messages, 1);

    upstream_task.abort();
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn soracloud_public_local_read_route_returns_503_for_unhydrated_runtime() {
    use tower::ServiceExt as _;
    let mut app = mk_app_state_for_tests_with_world(seed_public_soracloud_world());
    install_unavailable_local_read_runtime(&mut app, None, "runtime hydration incomplete");
    let router = axum::Router::new()
        .fallback(any(handler_soracloud_public_local_read))
        .with_state(app);
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri("/app/query")
                .header(axum::http::header::HOST, "portal.sora")
                .extension(crate::loopback_connect_info())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn soracloud_public_ordered_mailbox_route_invokes_runtime_with_authoritative_context() {
    use tower::ServiceExt as _;
    let captured_requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let runtime = TestMailboxRuntime {
        snapshot: iroha_core::soracloud_runtime::SoracloudRuntimeSnapshot::default(),
        state_dir: PathBuf::from("/tmp/test-soracloud-runtime"),
        local_peer_id: None,
        result: Ok(
            iroha_core::soracloud_runtime::SoracloudOrderedMailboxExecutionResult {
                state_mutations: Vec::new(),
                outbound_mailbox_messages: Vec::new(),
                response_bytes: br#"{"status":"queued"}"#.to_vec(),
                content_type: Some("application/json".to_owned()),
                runtime_state: None,
                runtime_receipt: iroha_data_model::soracloud::SoraRuntimeReceiptV1 {
                    schema_version: iroha_data_model::soracloud::SORA_RUNTIME_RECEIPT_VERSION_V1,
                    receipt_id: Hash::new(b"public-mailbox-receipt"),
                    service_name: "web_portal".parse().expect("service"),
                    service_version: "2026.02.0".to_owned(),
                    handler_name: "update".parse().expect("handler"),
                    handler_class: iroha_data_model::soracloud::SoraServiceHandlerClassV1::Update,
                    request_commitment: Hash::new(b"public-mailbox-request"),
                    result_commitment: Hash::new(b"public-mailbox-result"),
                    certified_by: iroha_data_model::soracloud::SoraCertifiedResponsePolicyV1::None,
                    emitted_sequence: 1,
                    mailbox_message_id: Some(Hash::new(b"public-mailbox-message")),
                    journal_artifact_hash: None,
                    checkpoint_artifact_hash: None,
                    execution_host: None,
                },
            },
        ),
        captured_requests: Arc::clone(&captured_requests),
    };
    let mut app = mk_app_state_for_tests_with_world(seed_public_soracloud_world());
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .soracloud_runtime = Some(Arc::new(runtime));
    let router = axum::Router::new()
        .fallback(any(handler_soracloud_public_local_read))
        .with_state(app);
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/app/update/search?fresh=1")
                .header(axum::http::header::HOST, "portal.sora")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .extension(crate::loopback_connect_info())
                .body(Body::from(
                    br#"{"origin":"DXB","destination":"HIR"}"#.to_vec(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    let expected_receipt_id = Hash::new(b"public-mailbox-receipt").to_string();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        torii_response_header(&response, "content-type"),
        Some("application/json")
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-soracloud-receipt-id"),
        Some(expected_receipt_id.as_str())
    );
    let body = torii_body_bytes(response, "body").await;
    assert_eq!(body.as_ref(), br#"{"status":"queued"}"#);
    let captured = captured_requests.lock().expect("capture lock");
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].deployment.service_name.as_ref(), "web_portal");
    assert_eq!(
        captured[0]
            .handler
            .as_ref()
            .expect("handler")
            .handler_name
            .as_ref(),
        "update"
    );
    assert_eq!(
        captured[0].handler.as_ref().expect("handler").class,
        iroha_data_model::soracloud::SoraServiceHandlerClassV1::Update
    );
    assert_eq!(captured[0].observed_sequence, 1);
    assert_eq!(
        captured[0].mailbox_message.payload_bytes.as_slice(),
        br#"{"origin":"DXB","destination":"HIR"}"#
    );
    assert_eq!(captured[0].mailbox_message.to_handler.as_ref(), "update");
    assert_eq!(captured[0].authoritative_pending_mailbox_messages, 1);
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn soracloud_public_hosted_http_route_streams_sse_bodies() {
    use http_body_util::BodyExt as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tower::ServiceExt as _;
    const FIRST_SSE_FRAME: &[u8] = b"event: session\ndata: ready\n\n";
    const SECOND_SSE_FRAME: &[u8] = b"data: {\"id\":\"search_1\"}\n\n";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let addr = listener.local_addr().expect("upstream addr");
    let captured_upstream_requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_upstream_requests_for_task = Arc::clone(&captured_upstream_requests);
    let upstream_task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _addr)) = listener.accept().await else {
                break;
            };
            let captured_upstream_requests = Arc::clone(&captured_upstream_requests_for_task);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            request.extend_from_slice(&buf[..n]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                            if request.len() > 8192 {
                                return;
                            }
                        }
                    }
                }
                captured_upstream_requests
                    .lock()
                    .expect("capture lock")
                    .push(request);
                if socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nx-iroha-soracloud-served-service-name: spoofed-service\r\nx-iroha-soracloud-served-service-version: stale-version\r\nx-iroha-soracloud-served-replica-slot: 999\r\nx-iroha-soracloud-served-process-generation: 999\r\nx-iroha-soracloud-served-materialized-bundle-hash: hash:spoofed\r\ntransfer-encoding: chunked\r\n\r\n",
                        )
                        .await
                        .is_err()
                    {
                        return;
                    }
                let first_len = format!("{:x}\r\n", FIRST_SSE_FRAME.len());
                if socket.write_all(first_len.as_bytes()).await.is_err()
                    || socket.write_all(FIRST_SSE_FRAME).await.is_err()
                    || socket.write_all(b"\r\n").await.is_err()
                    || socket.flush().await.is_err()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
                let second_len = format!("{:x}\r\n", SECOND_SSE_FRAME.len());
                let _ = socket.write_all(second_len.as_bytes()).await;
                let _ = socket.write_all(SECOND_SSE_FRAME).await;
                let _ = socket.write_all(b"\r\n0\r\n\r\n").await;
                let _ = socket.flush().await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let temp = tempfile::tempdir().expect("tempdir");
    let materialization_dir = temp.path().join("service");
    std::fs::create_dir_all(&materialization_dir).expect("materialization dir");
    let listen_base_url = format!("http://{addr}");
    let mut world = seed_public_soracloud_world();
    let mut bundle = world
        .view()
        .soracloud_service_revisions()
        .get(&("web_portal".to_owned(), "2026.02.0".to_owned()))
        .cloned()
        .expect("public service bundle");
    let (hosted_validator_account_id, hosted_peer_id) = checked_torii_test_inrou_host_identity(
        0x49,
        "derive canonical hosted SSE host fixture key",
    );

    bundle.container.runtime = iroha_data_model::soracloud::SoraContainerRuntimeV1::Inrou;
    bundle.container.inrou = Some(test_inrou_manifest());
    bundle.container.entrypoint = "/app/main".to_owned();
    bundle.service.execution_plane =
        iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService;
    bundle.service.replicas = std::num::NonZeroU16::new(1).expect("replicas");
    bundle.service.placement_targets =
        BTreeSet::from([iroha_data_model::soracloud::SoraInrouPlacementTargetV1 {
            validator_account_id: hosted_validator_account_id.clone(),
            peer_id: hosted_peer_id.to_string(),
        }]);
    bundle.service.state_bindings.clear();
    bundle.service.handlers.clear();
    bundle.service.artifacts.clear();
    bundle.service.lease_volumes = vec![
        iroha_data_model::soracloud::SoraLeaseVolumeBindingV1 {
            volume_name: "root_disk".parse().expect("volume"),
            kind: iroha_data_model::soracloud::SoraLeaseVolumeKindV1::PersistentRootLeaseVolume,
            storage_class: iroha_data_model::sorafs::pin_registry::StorageClass::Warm,
            mount_path: "/".to_owned(),
            max_total_bytes: std::num::NonZeroU64::new(8 * 1024 * 1024 * 1024).expect("bytes"),
        },
        iroha_data_model::soracloud::SoraLeaseVolumeBindingV1 {
            volume_name: "index_state".parse().expect("volume"),
            kind: iroha_data_model::soracloud::SoraLeaseVolumeKindV1::ServiceLeaseVolume,
            storage_class: iroha_data_model::sorafs::pin_registry::StorageClass::Warm,
            mount_path: "/var/lib/soracloud/volumes/index_state".to_owned(),
            max_total_bytes: std::num::NonZeroU64::new(1024 * 1024).expect("bytes"),
        },
    ];
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    bundle
        .validate_for_admission()
        .expect("hosted HTTP Inrou SSE fixture must pass production validation");
    world.soracloud_service_revisions_mut_for_testing().insert(
        ("web_portal".to_owned(), "2026.02.0".to_owned()),
        bundle.clone(),
    );
    let service_lease = hosted_http_service_lease_state(
        iroha_data_model::soracloud::SoraServiceLeaseStatusV1::Active,
        "50".parse().expect("runtime balance"),
        100,
    );
    let lease_volume_states = hosted_http_lease_volume_states(&bundle, Some(&service_lease));
    let deployment = iroha_data_model::soracloud::SoraServiceDeploymentStateV1 {
        schema_version: iroha_data_model::soracloud::SORA_SERVICE_DEPLOYMENT_STATE_VERSION_V1,
        service_name: "web_portal".parse().expect("service"),
        current_service_version: "2026.02.0".to_owned(),
        current_service_manifest_hash: bundle.service_manifest_hash(),
        current_container_manifest_hash: bundle.container_manifest_hash(),
        revision_count: 1,
        process_generation: 1,
        process_started_sequence: 1,
        active_rollout: None,
        last_rollout: None,
        config_generation: 0,
        secret_generation: 0,
        service_configs: BTreeMap::new(),
        service_secrets: BTreeMap::new(),
        fhe_policy_records: BTreeMap::new(),
        service_lease: Some(service_lease),
        lease_volume_states,
    };
    deployment
        .validate()
        .expect("hosted HTTP SSE deployment must be production-valid");
    iroha_core::soracloud_runtime::validate_soracloud_deployment_lease_volume_bindings(
        &deployment,
        &bundle,
    )
    .expect("hosted HTTP SSE deployment must exactly match admitted lease-volume economics");
    world
        .soracloud_service_deployments_mut_for_testing()
        .insert("web_portal".parse().expect("service"), deployment);
    seed_authoritative_hosted_http_revision(
        &mut world,
        &bundle,
        bundle.service.replicas.get(),
        &[(
            1,
            hosted_validator_account_id.clone(),
            hosted_peer_id.to_string(),
            iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        )],
    );
    let expected_materialized_bundle_hash = bundle.container.bundle_hash.to_string();
    let mut snapshot = iroha_core::soracloud_runtime::SoracloudRuntimeSnapshot::default();
    snapshot.local_peer_id = Some(hosted_peer_id.to_string());
    snapshot.services.insert(
        "web_portal".to_owned(),
        BTreeMap::from([(
            "2026.02.0".to_owned(),
            iroha_core::soracloud_runtime::SoracloudRuntimeServicePlan {
                service_name: "web_portal".to_owned(),
                service_version: "2026.02.0".to_owned(),
                role: iroha_core::soracloud_runtime::SoracloudRuntimeRevisionRole::Active,
                traffic_percent: 100,
                runtime: iroha_data_model::soracloud::SoraContainerRuntimeV1::Inrou,
                execution_plane:
                    iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService,
                bundle_hash: expected_materialized_bundle_hash.clone(),
                bundle_path: "/runtime/bin/launch.sh".to_owned(),
                entrypoint: "/runtime/bin/launch.sh".to_owned(),
                inrou: None,
                bundle_cache_path: temp.path().join("bundle.tar.gz").display().to_string(),
                bundle_available_locally: true,
                process_generation: Some(1),
                desired_replica_count: 1,
                local_replica_slots: vec![1],
                local_replicas: vec![SoracloudRuntimeReplicaPlan {
                    replica_slot: 1,
                    lease_started_height: 1,
                    placement_incarnation: Hash::new(Encode::encode(&("placement", 1_u16)))
                        .to_string(),
                    host_availability:
                        iroha_data_model::soracloud::SoraInrouReplicaHostAvailabilityV1::Available,
                    validator_account_id: hosted_validator_account_id.to_string(),
                    peer_id: hosted_peer_id.to_string(),
                    materialization_dir: materialization_dir
                        .join("replicas/replica-0001")
                        .display()
                        .to_string(),
                    health_status: iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
                    listen_base_url: Some(listen_base_url.clone()),
                    pid: Some(101),
                    last_error: None,
                }],
                health_status: iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
                load_factor_bps: 0,
                authoritative_pending_mailbox_messages: 0,
                rollout_handle: None,
                config_generation: 0,
                secret_generation: 0,
                quota_class: Some("taira-open".to_owned()),
                service_lease_status: Some(
                    iroha_data_model::soracloud::SoraServiceLeaseStatusV1::Active,
                ),
                lease_expires_height: Some(100),
                remaining_runtime_balance: Some("50".parse().expect("runtime balance")),
                config_entry_count: 0,
                secret_entry_count: 0,
                config_exports: Vec::new(),
                supports_host_read_config: true,
                supports_host_read_secret_envelope: true,
                materialization_dir: materialization_dir.display().to_string(),
                config_materialization_dir: materialization_dir
                    .join("configs")
                    .display()
                    .to_string(),
                effective_env: BTreeMap::new(),
                effective_env_materialization_path: materialization_dir
                    .join("effective_env.json")
                    .display()
                    .to_string(),
                config_exports_materialization_dir: materialization_dir
                    .join("config_exports")
                    .display()
                    .to_string(),
                secret_envelopes_materialization_dir: materialization_dir
                    .join("secret_envelopes")
                    .display()
                    .to_string(),
                lease_volumes: Vec::new(),
                mailboxes: Vec::new(),
                artifacts: Vec::new(),
            },
        )]),
    );
    let runtime = TestLocalReadRuntime::with_result(
        snapshot,
        temp.path().to_path_buf(),
        Some(hosted_peer_id.to_string()),
        Err(
            iroha_core::soracloud_runtime::SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::Unavailable,
                "hosted HTTP proxy should bypass local-read execution",
            ),
        ),
    );
    let mut app = mk_hosted_http_app_with_world(world);
    seed_hosted_http_public_lane_validator(&app, &hosted_validator_account_id, &hosted_peer_id);
    let app_mut = Arc::get_mut(&mut app).expect("unique app state");
    app_mut.local_peer_id = Some(hosted_peer_id.clone());
    app_mut.soracloud_runtime = Some(Arc::new(runtime));
    {
        let state_view = app.state.view();
        let current_height = u64::try_from(state_view.height()).unwrap_or(u64::MAX);
        assert_eq!(current_height, 1, "hosted SSE lease must start at height 1");
        assert!(
            state_view.is_lane_active_for_authority(iroha_model_base::topology::LaneId::SINGLE),
            "hosted SSE validator lane must be active"
        );
        let world = state_view.world();
        let capability = world
            .soracloud_inrou_host_capabilities()
            .get(&hosted_validator_account_id)
            .expect("hosted SSE validator capability");
        assert!(
            capability.can_host_replicas_at(super::current_public_ingress_ledger_time_ms(&app)),
            "hosted SSE validator capability must be active"
        );
        assert!(
            iroha_core::soracloud_runtime::soracloud_validator_has_active_peer_binding(
                world,
                &hosted_validator_account_id,
                &hosted_peer_id.to_string(),
                current_height,
                |lane_id| state_view.is_lane_active_for_authority(lane_id),
            ),
            "hosted SSE validator must retain its canonical active peer binding"
        );
        let assignments = iroha_core::soracloud_runtime::resolve_active_inrou_replica_assignments(
            world,
            "web_portal",
            "2026.02.0",
            super::current_public_ingress_ledger_time_ms(&app),
            current_height,
            |lane_id| state_view.is_lane_active_for_authority(lane_id),
        )
        .expect("hosted SSE authoritative assignments");
        assert_eq!(assignments.len(), 1, "hosted SSE authoritative replica");
    }
    let route_match = match soracloud::resolve_public_route(
        &app,
        "portal.sora",
        "GET",
        "/app/v1/search/search_1/events",
    )
    .expect("hosted SSE route")
    {
        soracloud::PublicRouteMatch::HostedHttp(route_match) => route_match,
        other => panic!("expected hosted route match, got {other:?}"),
    };
    assert_eq!(route_match.request_path, "/v1/search/search_1/events");
    let target = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(IpAddr::from([127, 0, 0, 1])),
        &HttpMethod::GET,
        &"/app/v1/search/search_1/events".parse().expect("uri"),
    )
    .expect("hosted SSE target");
    assert_eq!(
        target.local_listen_base_url.as_deref(),
        Some(listen_base_url.as_str())
    );
    assert_eq!(
        target.materialized_bundle_hash,
        expected_materialized_bundle_hash
    );
    let mut direct_headers = HeaderMap::new();
    direct_headers.insert(
        axum::http::header::AUTHORIZATION,
        HeaderValue::from_static("Bearer tenant-token"),
    );
    direct_headers.insert("x-tenant-header", HeaderValue::from_static("visible"));
    direct_headers.insert(
        HEADER_API_TOKEN,
        HeaderValue::from_static("listener-secret"),
    );
    direct_headers.insert(
        "x-iroha-operator-token",
        HeaderValue::from_static("operator-secret"),
    );
    direct_headers.insert(
        "x-sorafs-stream-token",
        HeaderValue::from_static("stream-secret"),
    );
    direct_headers.insert(
        "sora-pop-authorization",
        HeaderValue::from_static("PopV1 credential-secret"),
    );
    direct_headers.insert(
        axum::http::header::CONNECTION,
        HeaderValue::from_static("x-hop-secret"),
    );
    direct_headers.insert(
        "x-hop-secret",
        HeaderValue::from_static("connection-secret"),
    );
    let direct_response = tokio::time::timeout(
        Duration::from_secs(3),
        super::proxy_soracloud_public_hosted_http_locally(
            &HttpMethod::GET,
            &"/app/v1/search/search_1/events".parse().expect("uri"),
            &direct_headers,
            Bytes::new(),
            &route_match,
            &listen_base_url,
        ),
    )
    .await
    .expect("direct native proxy should not wait for the full SSE body")
    .expect("direct native proxy response");
    assert_eq!(direct_response.status(), StatusCode::OK);
    drop(direct_response);
    let captured = captured_upstream_requests.lock().expect("capture lock");
    let direct_request = String::from_utf8_lossy(&captured[0]).to_ascii_lowercase();
    assert!(direct_request.contains("authorization: bearer tenant-token\r\n"));
    assert!(direct_request.contains("x-tenant-header: visible\r\n"));
    for removed in [
        HEADER_API_TOKEN,
        "x-iroha-operator-token",
        "x-sorafs-stream-token",
        "sora-pop-authorization",
        "connection",
        "x-hop-secret",
    ] {
        assert!(
            !direct_request.contains(&format!("{removed}:")),
            "hosted tenant must not receive `{removed}`"
        );
    }
    drop(captured);

    #[cfg(any(feature = "p2p_ws", feature = "connect"))]
    {
        let ingress_peer_id =
            checked_torii_test_peer_id(0x4b, "derive hosted SSE proxy ingress peer fixture key");
        let incoming_response = tokio::time::timeout(
            Duration::from_secs(3),
            super::execute_incoming_torii_proxy_request(
                &app,
                ToriiProxyRequestV1 {
                    schema_version: TORII_PROXY_REQUEST_VERSION_V1,
                    request_id: Hash::new(b"incoming-hosted-sse-served-revision"),
                    deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
                    hop_count: 1,
                    max_hops: 3,
                    visited_peer_ids: vec![ingress_peer_id],
                    request: ToriiProxyRequestKindV1::HostedHttp(ToriiHostedHttpProxyRequestV1 {
                        service_name: "web_portal".to_owned(),
                        service_version: "2026.02.0".to_owned(),
                        replica_slot: 1,
                        request_path: "/v1/search/search_1/events".to_owned(),
                        method: "GET".to_owned(),
                        query_string: None,
                        headers: vec![
                            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                                name: "authorization".to_owned(),
                                value: b"Bearer remote-tenant-token".to_vec(),
                            },
                            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                                name: "x-tenant-header".to_owned(),
                                value: b"remote-visible".to_vec(),
                            },
                            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                                name: HEADER_API_TOKEN.to_owned(),
                                value: b"forged-listener-secret".to_vec(),
                            },
                            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                                name: "x-iroha-operator-token".to_owned(),
                                value: b"forged-operator-secret".to_vec(),
                            },
                            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                                name: "x-sorafs-evidence-grant".to_owned(),
                                value: b"forged-evidence-secret".to_vec(),
                            },
                            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                                name: "sora-pop-authorization".to_owned(),
                                value: b"PopV1 forged-credential-secret".to_vec(),
                            },
                            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                                name: "connection".to_owned(),
                                value: b"x-hop-secret".to_vec(),
                            },
                            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                                name: "x-hop-secret".to_owned(),
                                value: b"forged-connection-secret".to_vec(),
                            },
                        ],
                        body: Vec::new(),
                        remote_ip: Some("127.0.0.1".to_owned()),
                    }),
                },
                None,
            ),
        )
        .await
        .expect("incoming hosted proxy should not wait for the full SSE body");
        assert_eq!(incoming_response.status(), StatusCode::OK);
        for (header_name, expected_value) in [
            (
                iroha_torii_shared::SORACLOUD_SERVED_SERVICE_NAME_HEADER,
                "web_portal",
            ),
            (
                iroha_torii_shared::SORACLOUD_SERVED_SERVICE_VERSION_HEADER,
                "2026.02.0",
            ),
            (
                iroha_torii_shared::SORACLOUD_SERVED_REPLICA_SLOT_HEADER,
                "1",
            ),
            (
                iroha_torii_shared::SORACLOUD_SERVED_PROCESS_GENERATION_HEADER,
                "1",
            ),
            (
                iroha_torii_shared::SORACLOUD_SERVED_MATERIALIZED_BUNDLE_HASH_HEADER,
                expected_materialized_bundle_hash.as_str(),
            ),
        ] {
            assert_eq!(
                torii_response_header(&incoming_response, header_name),
                Some(expected_value),
                "the hosting peer must stamp its exact `{header_name}` target"
            );
            assert_eq!(
                incoming_response
                    .headers()
                    .get_all(header_name)
                    .iter()
                    .count(),
                1,
                "the hosting peer must replace guest-provided `{header_name}` values"
            );
        }
        drop(incoming_response);
        let captured = captured_upstream_requests.lock().expect("capture lock");
        let incoming_request = String::from_utf8_lossy(
            captured
                .last()
                .expect("incoming proxy request must reach the hosted tenant"),
        )
        .to_ascii_lowercase();
        assert!(incoming_request.contains("authorization: bearer remote-tenant-token\r\n"));
        assert!(incoming_request.contains("x-tenant-header: remote-visible\r\n"));
        for removed in [
            HEADER_API_TOKEN,
            "x-iroha-operator-token",
            "x-sorafs-evidence-grant",
            "sora-pop-authorization",
            "connection",
            "x-hop-secret",
        ] {
            assert!(
                !incoming_request.contains(&format!("{removed}:")),
                "peer envelope must not inject `{removed}` into the hosted tenant"
            );
        }
        drop(captured);
    }

    let router = axum::Router::new()
        .fallback(any(handler_soracloud_public_local_read))
        .with_state(app);
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        router.oneshot(
            axum::http::Request::builder()
                .uri("/app/v1/search/search_1/events")
                .header(axum::http::header::HOST, "portal.sora")
                .extension(crate::loopback_connect_info())
                .body(Body::empty())
                .expect("request"),
        ),
    )
    .await
    .expect("native proxy should not wait for the full SSE body")
    .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        torii_response_header(&response, "content-type"),
        Some("text/event-stream")
    );
    assert_eq!(
        torii_response_header(
            &response,
            iroha_torii_shared::SORACLOUD_SERVED_SERVICE_NAME_HEADER
        ),
        Some("web_portal")
    );
    assert_eq!(
        torii_response_header(
            &response,
            iroha_torii_shared::SORACLOUD_SERVED_SERVICE_VERSION_HEADER
        ),
        Some("2026.02.0")
    );
    assert_eq!(
        torii_response_header(
            &response,
            iroha_torii_shared::SORACLOUD_SERVED_REPLICA_SLOT_HEADER
        ),
        Some("1")
    );
    assert_eq!(
        torii_response_header(
            &response,
            iroha_torii_shared::SORACLOUD_SERVED_PROCESS_GENERATION_HEADER
        ),
        Some("1")
    );
    assert_eq!(
        torii_response_header(
            &response,
            iroha_torii_shared::SORACLOUD_SERVED_MATERIALIZED_BUNDLE_HASH_HEADER
        ),
        Some(expected_materialized_bundle_hash.as_str())
    );
    for header_name in [
        iroha_torii_shared::SORACLOUD_SERVED_SERVICE_NAME_HEADER,
        iroha_torii_shared::SORACLOUD_SERVED_SERVICE_VERSION_HEADER,
        iroha_torii_shared::SORACLOUD_SERVED_REPLICA_SLOT_HEADER,
        iroha_torii_shared::SORACLOUD_SERVED_PROCESS_GENERATION_HEADER,
        iroha_torii_shared::SORACLOUD_SERVED_MATERIALIZED_BUNDLE_HASH_HEADER,
    ] {
        assert_eq!(
            response.headers().get_all(header_name).iter().count(),
            1,
            "guest-provided `{header_name}` values must be replaced at ingress"
        );
    }
    let mut body = response.into_body();
    let first_frame = tokio::time::timeout(Duration::from_millis(300), body.frame())
        .await
        .expect("first SSE frame should be streamed promptly")
        .expect("body frame")
        .expect("streamed frame");
    let first_chunk = first_frame.into_data().expect("data frame");
    assert_eq!(first_chunk.as_ref(), FIRST_SSE_FRAME);
    let second_frame = tokio::time::timeout(Duration::from_secs(6), body.frame())
        .await
        .expect("second SSE frame should arrive")
        .expect("body frame")
        .expect("streamed frame");
    let second_chunk = second_frame.into_data().expect("data frame");
    assert_eq!(second_chunk.as_ref(), SECOND_SSE_FRAME);
    upstream_task.abort();
}
#[cfg(feature = "app_api")]
fn hosted_http_health_route(app: &SharedAppState) -> soracloud::HostedHttpRouteMatch {
    match soracloud::resolve_public_route(app, "portal.sora", "GET", "/app/v1/health")
        .expect("hosted route")
    {
        soracloud::PublicRouteMatch::HostedHttp(route_match) => route_match,
        other => panic!("expected hosted route match, got {other:?}"),
    }
}
#[cfg(feature = "app_api")]
fn mutate_hosted_http_deployment(
    app: &mut SharedAppState,
    mutate: impl FnOnce(&mut iroha_data_model::soracloud::SoraServiceDeploymentStateV1),
) {
    let service_name: iroha_model_base::name::Name = "web_portal".parse().expect("service name");
    let app = Arc::get_mut(app).expect("unique app state");
    let state = Arc::get_mut(&mut app.state).expect("unique state");
    let deployments = state.world.soracloud_service_deployments_mut_for_testing();
    let mut deployment = deployments
        .view()
        .get(&service_name)
        .cloned()
        .expect("hosted deployment");
    mutate(&mut deployment);
    deployments.insert(service_name, deployment);
}
#[cfg(feature = "app_api")]
fn mutate_authoritative_hosted_http_placement(
    world: &mut World,
    service_name: &str,
    service_version: &str,
    replica_slot: u16,
    mutate: impl FnOnce(&mut iroha_data_model::soracloud::SoraInrouReplicaPlacementV1),
) {
    let key = (service_name.to_owned(), service_version.to_owned());
    let placements = world.soracloud_inrou_service_placements_mut_for_testing();
    let mut record = placements
        .view()
        .get(&key)
        .cloned()
        .expect("authoritative hosted-http placement record");
    let placement = record
        .placements
        .iter_mut()
        .find(|placement| placement.replica_slot == replica_slot)
        .expect("authoritative hosted-http replica placement");
    mutate(placement);
    placements.insert(key, record);
}
#[cfg(feature = "app_api")]
fn mutate_authoritative_hosted_http_runtime(
    world: &mut World,
    service_name: &str,
    service_version: &str,
    replica_slot: u16,
    mutate: impl FnOnce(&mut iroha_data_model::soracloud::SoraInrouReplicaRuntimeStateV1),
) {
    let key = (
        service_name.to_owned(),
        service_version.to_owned(),
        replica_slot.to_string(),
    );
    let runtimes = world.soracloud_inrou_replica_runtime_mut_for_testing();
    let mut runtime = runtimes
        .view()
        .get(&key)
        .cloned()
        .expect("authoritative hosted-http replica runtime");
    mutate(&mut runtime);
    runtimes.insert(key, runtime);
}
#[cfg(feature = "app_api")]
fn inject_hosted_http_active_rollout(app: &mut SharedAppState) {
    mutate_hosted_http_deployment(app, |deployment| {
        let rollout = iroha_data_model::soracloud::SoraServiceRolloutStateV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_ROLLOUT_STATE_VERSION_V1,
            rollout_handle: "retired-inrou-canary".to_owned(),
            baseline_version: "2026.03.0".to_owned(),
            candidate_version: deployment.current_service_version.clone(),
            canary_percent: 20,
            traffic_percent: 20,
            stage: iroha_data_model::soracloud::SoraRolloutStageV1::Canary,
            health_failures: 0,
            max_health_failures: 3,
            health_window_secs: 60,
            created_sequence: 1,
            updated_sequence: 1,
        };
        deployment.active_rollout = Some(rollout.clone());
        deployment.last_rollout = Some(rollout);
        deployment
            .validate()
            .expect("injected rollout must remain structurally valid");
    });
}
#[test]
#[cfg(feature = "app_api")]
fn authoritative_hosted_http_version_uses_the_single_current_revision() {
    let temp = tempfile::tempdir().expect("tempdir");
    let app = seed_public_hosted_http_current_app(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
    );
    let state_view = app.state.view();
    let world = state_view.world();
    let current_height = u64::try_from(state_view.height()).unwrap_or(u64::MAX);
    assert_eq!(
        super::authoritative_hosted_http_revision(world, current_height, "web_portal")
            .expect("canonical hosted revision"),
        ("2026.02.0".to_owned(), 1)
    );
}
#[test]
#[cfg(feature = "app_api")]
fn authoritative_hosted_http_revision_rejects_active_inrou_canary() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut app = seed_public_hosted_http_current_app(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
    );
    inject_hosted_http_active_rollout(&mut app);
    let state_view = app.state.view();
    let current_height = u64::try_from(state_view.height()).unwrap_or(u64::MAX);
    let error =
        super::authoritative_hosted_http_revision(state_view.world(), current_height, "web_portal")
            .expect_err("first-release Inrou must reject an active canary");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Internal);
    assert!(
        error.message.contains("unsupported active Inrou canary")
            && error.message.contains("require one active revision"),
        "unexpected error: {}",
        error.message
    );
}

#[test]
#[cfg(feature = "app_api")]
fn hosted_http_ingress_and_exact_peer_reject_active_inrou_canary() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut app = seed_public_hosted_http_current_app(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
    );
    inject_hosted_http_active_rollout(&mut app);
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let ingress_error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(IpAddr::from([203, 0, 113, 7])),
        &method,
        &uri,
    )
    .expect_err("public ingress must reject an active Inrou canary");
    let exact_error =
        super::resolve_exact_hosted_http_runtime_target(&app, "web_portal", "2026.02.0", 1)
            .expect_err("authenticated exact-peer execution must reject an active Inrou canary");
    for error in [ingress_error, exact_error] {
        assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Internal);
        assert!(
            error.message.contains("unsupported active Inrou canary")
                && error.message.contains("require one active revision"),
            "unexpected error: {}",
            error.message
        );
    }
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn resolve_hosted_http_runtime_target_routes_only_the_current_revision() {
    let temp = tempfile::tempdir().expect("tempdir");
    let app = seed_public_hosted_http_current_app(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
    );
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let target = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(IpAddr::from([203, 0, 113, 7])),
        &method,
        &uri,
    )
    .expect("healthy current target");
    assert_eq!(target.route_match.service_version, "2026.02.0");
    let other_target = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(IpAddr::from([203, 0, 113, 211])),
        &method,
        &uri,
    )
    .expect("healthy current target for another client");
    assert_eq!(other_target.route_match.service_version, "2026.02.0");
}

#[test]
#[cfg(feature = "app_api")]
fn resolve_exact_hosted_http_runtime_target_rejects_inactive_revision() {
    let temp = tempfile::tempdir().expect("tempdir");
    let app = seed_public_hosted_http_current_app(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
    );
    let error = super::resolve_exact_hosted_http_runtime_target(&app, "web_portal", "2026.03.0", 1)
        .expect_err("an authenticated peer must not pin a retained inactive revision");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(
        error
            .message
            .contains("is not the current revision `2026.02.0`"),
        "unexpected error: {}",
        error.message
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn resolve_hosted_http_runtime_target_does_not_fall_back_to_an_inactive_revision() {
    let temp = tempfile::tempdir().expect("tempdir");
    let app = seed_public_hosted_http_current_app(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
    );
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(IpAddr::from([203, 0, 113, 7])),
        &method,
        &uri,
    )
    .expect_err("an unavailable current revision must not fall back to another revision");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(
        error
            .message
            .contains("hosted Soracloud current revision `2026.02.0`")
            && error
                .message
                .contains("has no healthy authoritative replica"),
        "unexpected error: {}",
        error.message
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn resolve_hosted_http_runtime_target_fails_closed_without_any_healthy_revision() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut app = seed_public_hosted_http_current_app(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
    );
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let baseline_ip = IpAddr::from([203, 0, 113, 77]);
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(baseline_ip),
        &method,
        &uri,
    )
    .expect_err("unhealthy revisions must fail closed");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(
        error
            .message
            .contains("has no healthy authoritative replica"),
        "unexpected error: {}",
        error.message
    );

    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
        mutate_authoritative_hosted_http_placement(
            &mut state.world,
            "web_portal",
            "2026.02.0",
            1,
            |placement| {
                placement.host_availability =
                    iroha_data_model::soracloud::SoraInrouReplicaHostAvailabilityV1::Unavailable;
            },
        );
        mutate_authoritative_hosted_http_runtime(
            &mut state.world,
            "web_portal",
            "2026.02.0",
            1,
            |runtime| {
                runtime.health_status =
                    iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy;
            },
        );
    }
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(baseline_ip),
        &method,
        &uri,
    )
    .expect_err("an unavailable placement must not enter authoritative routing");
    assert!(
        error
            .message
            .contains("has no healthy authoritative replica"),
        "unexpected error: {}",
        error.message
    );

    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
        mutate_authoritative_hosted_http_placement(
            &mut state.world,
            "web_portal",
            "2026.02.0",
            1,
            |placement| {
                placement.host_availability =
                    iroha_data_model::soracloud::SoraInrouReplicaHostAvailabilityV1::Available;
            },
        );
        mutate_authoritative_hosted_http_runtime(
            &mut state.world,
            "web_portal",
            "2026.02.0",
            1,
            |runtime| {
                runtime.placement_incarnation = iroha_crypto::Hash::new(b"stale-placement");
            },
        );
    }
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(baseline_ip),
        &method,
        &uri,
    )
    .expect_err("a stale placement incarnation must not enter authoritative routing");
    assert!(
        error
            .message
            .contains("has no healthy authoritative replica"),
        "unexpected error: {}",
        error.message
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn hosted_http_runtime_target_rejects_cross_keyed_and_invalid_placement_records() {
    for cross_keyed in [true, false] {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut app = seed_public_hosted_http_current_app(
            &temp,
            iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
            iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
        );
        {
            let app_mut = Arc::get_mut(&mut app).expect("unique app state");
            let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
            let key = ("web_portal".to_owned(), "2026.02.0".to_owned());
            let mut placements = state
                .world
                .soracloud_inrou_service_placements_mut_for_testing()
                .block();
            let record = placements.get_mut(&key).expect("baseline placement");
            if cross_keyed {
                record.service_version = "cross-bound-version".to_owned();
            } else {
                record.schema_version = 0;
            }
            placements.commit();
        }
        let route_match = hosted_http_health_route(&app);
        let method = HttpMethod::GET;
        let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
        let baseline_ip = IpAddr::from([203, 0, 113, 7]);
        let error = super::resolve_hosted_http_runtime_target(
            &app,
            &route_match,
            Some(baseline_ip),
            &method,
            &uri,
        )
        .expect_err("malformed placement must not serve public traffic");
        assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Internal);
        let expected = if cross_keyed {
            "storage key"
        } else {
            "malformed"
        };
        assert!(
            error.message.contains(expected),
            "unexpected error: {error:?}"
        );

        let exact_error =
            super::resolve_exact_hosted_http_runtime_target(&app, "web_portal", "2026.02.0", 1)
                .expect_err("malformed placement must not serve proxied traffic");
        assert_eq!(
            exact_error.kind,
            SoracloudRuntimeExecutionErrorKind::Internal
        );
        assert!(
            exact_error.message.contains(expected),
            "unexpected error: {exact_error:?}"
        );
    }
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn hosted_http_runtime_target_rejects_missing_or_expired_host_capability() {
    for remove_capability in [true, false] {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut app = seed_public_hosted_http_current_app(
            &temp,
            iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
            iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
        );
        let validator_account_id = {
            let view = app.state.view();
            view.world()
                .soracloud_inrou_service_placements()
                .get(&("web_portal".to_owned(), "2026.02.0".to_owned()))
                .and_then(|record| record.placements.first())
                .map(|placement| placement.validator_account_id.clone())
                .expect("baseline placement validator")
        };
        {
            let app_mut = Arc::get_mut(&mut app).expect("unique app state");
            let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
            let mut capabilities = state
                .world
                .soracloud_inrou_host_capabilities_mut_for_testing()
                .block();
            if remove_capability {
                capabilities.remove(validator_account_id.clone());
            } else {
                capabilities
                    .get_mut(&validator_account_id)
                    .expect("host capability")
                    .heartbeat_expires_at_ms = 2;
            }
            capabilities.commit();
        }
        let route_match = hosted_http_health_route(&app);
        let method = HttpMethod::GET;
        let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
        let baseline_ip = IpAddr::from([203, 0, 113, 7]);
        let error = super::resolve_hosted_http_runtime_target(
            &app,
            &route_match,
            Some(baseline_ip),
            &method,
            &uri,
        )
        .expect_err("stale host authority must not serve public traffic");
        assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
        assert!(error.message.contains("no healthy authoritative"));
        let exact_error =
            super::resolve_exact_hosted_http_runtime_target(&app, "web_portal", "2026.02.0", 1)
                .expect_err("stale host authority must not serve proxied traffic");
        assert_eq!(
            exact_error.kind,
            SoracloudRuntimeExecutionErrorKind::Unavailable
        );
        assert!(
            exact_error
                .message
                .contains("no active matching authoritative host capability")
        );
    }
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn hosted_http_runtime_target_rejects_inactive_validator_with_live_capability() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut app = seed_public_hosted_http_current_app(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
    );
    let validator_account_id = {
        let view = app.state.view();
        view.world()
            .soracloud_inrou_service_placements()
            .get(&("web_portal".to_owned(), "2026.02.0".to_owned()))
            .and_then(|record| record.placements.first())
            .map(|placement| placement.validator_account_id.clone())
            .expect("baseline placement validator")
    };
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
        let mut validators = state.world.public_lane_validators_mut_for_testing().block();
        let validator = validators
            .get_mut(&(
                iroha_model_base::topology::LaneId::SINGLE,
                validator_account_id,
            ))
            .expect("host validator record");
        validator.status = iroha_data_model::nexus::staking::PublicLaneValidatorStatus::Exited;
        validator.election_exit_height = Some(1);
        validator.deactivation_height = Some(1);
        validators.commit();
    }
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let baseline_ip = IpAddr::from([203, 0, 113, 7]);
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(baseline_ip),
        &method,
        &uri,
    )
    .expect_err("an exited validator must not serve with an unexpired advert");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(error.message.contains("no healthy authoritative"));
    let exact_error =
        super::resolve_exact_hosted_http_runtime_target(&app, "web_portal", "2026.02.0", 1)
            .expect_err("exact execution must also reject an exited validator");
    assert_eq!(
        exact_error.kind,
        SoracloudRuntimeExecutionErrorKind::Unavailable
    );
    assert!(
        exact_error
            .message
            .contains("no active matching authoritative host capability")
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn resolve_hosted_http_runtime_target_fails_closed_without_service_lease() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut app = seed_public_hosted_http_current_app_with_service_lease(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        Some(hosted_http_service_lease_state(
            iroha_data_model::soracloud::SoraServiceLeaseStatusV1::Active,
            "50".parse().expect("runtime balance"),
            100,
        )),
    );
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
        let service_name = "web_portal".parse().expect("service name");
        let mut deployments = state
            .world
            .soracloud_service_deployments_mut_for_testing()
            .block();
        let deployment = deployments
            .get_mut(&service_name)
            .expect("hosted service deployment");
        deployment.service_lease = None;
        deployment.lease_volume_states.clear();
        deployments.commit();
    }
    let route_match = soracloud::HostedHttpRouteMatch {
        service_name: "web_portal".to_owned(),
        service_version: "2026.02.0".to_owned(),
        request_path: "/app/v1/health".to_owned(),
    };
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(IpAddr::from([127, 0, 0, 1])),
        &method,
        &uri,
    )
    .expect_err("missing hosted-service lease must fail closed");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(
        error
            .message
            .contains("lease for service `web_portal` is unavailable"),
        "unexpected error: {}",
        error.message
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn resolve_hosted_http_runtime_target_fails_closed_when_service_lease_expires() {
    let temp = tempfile::tempdir().expect("tempdir");
    let app = seed_public_hosted_http_current_app_with_service_lease(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        Some(hosted_http_service_lease_state(
            iroha_data_model::soracloud::SoraServiceLeaseStatusV1::Expired,
            "50".parse().expect("runtime balance"),
            100,
        )),
    );
    let route_match = soracloud::HostedHttpRouteMatch {
        service_name: "web_portal".to_owned(),
        service_version: "2026.02.0".to_owned(),
        request_path: "/app/v1/health".to_owned(),
    };
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(IpAddr::from([127, 0, 0, 1])),
        &method,
        &uri,
    )
    .expect_err("expired hosted-service lease must fail closed");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(
        error.message.contains("Expired"),
        "unexpected error: {}",
        error.message
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn resolve_hosted_http_runtime_target_fails_closed_when_service_lease_is_exhausted() {
    let temp = tempfile::tempdir().expect("tempdir");
    let app = seed_public_hosted_http_current_app_with_service_lease(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        Some(hosted_http_service_lease_state(
            iroha_data_model::soracloud::SoraServiceLeaseStatusV1::Active,
            "0".parse().expect("runtime balance"),
            100,
        )),
    );
    let route_match = soracloud::HostedHttpRouteMatch {
        service_name: "web_portal".to_owned(),
        service_version: "2026.02.0".to_owned(),
        request_path: "/app/v1/health".to_owned(),
    };
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(IpAddr::from([127, 0, 0, 1])),
        &method,
        &uri,
    )
    .expect_err("exhausted hosted-service lease must fail closed");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(
        error.message.contains("Exhausted"),
        "unexpected error: {}",
        error.message
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn resolve_hosted_http_runtime_target_balances_across_distinct_healthy_hosts_within_revision()
{
    let temp = tempfile::tempdir().expect("tempdir");
    let app = seed_public_hosted_http_current_app_with_replica_plans(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
        vec![
            hosted_http_runtime_replica_plan(
                &temp.path().join("service-baseline"),
                1,
                iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
                Some("http://127.0.0.1:18080"),
                Some(101),
            ),
            hosted_http_runtime_replica_plan(
                &temp.path().join("service-baseline"),
                2,
                iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
                None,
                None,
            ),
        ],
        vec![hosted_http_runtime_replica_plan(
            &temp.path().join("service-canary"),
            1,
            iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
            None,
            None,
        )],
    );
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let first_ip =
        hosted_http_replica_test_ip("web_portal", "2026.02.0", &method, &uri, |bucket| {
            bucket % 2 == 0
        });
    let first_target = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(first_ip),
        &method,
        &uri,
    )
    .expect("first replica target");
    assert_eq!(
        first_target.local_listen_base_url.as_deref(),
        Some("http://127.0.0.1:18080")
    );
    assert_eq!(first_target.assigned_peer_id, hosted_http_local_peer_id());
    let second_ip =
        hosted_http_replica_test_ip("web_portal", "2026.02.0", &method, &uri, |bucket| {
            bucket % 2 == 1
        });
    let second_target = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(second_ip),
        &method,
        &uri,
    )
    .expect("second replica target");
    assert_eq!(second_target.local_listen_base_url, None);
    assert_ne!(
        second_target.assigned_peer_id, first_target.assigned_peer_id,
        "one-host-capacity fixtures must place each active replica on a distinct peer"
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn resolve_hosted_http_runtime_target_fails_closed_when_authoritative_runtime_state_lags() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut app = seed_public_hosted_http_current_app(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
    );
    let baseline_bundle = app
        .state
        .view()
        .world()
        .soracloud_service_revisions()
        .get(&("web_portal".to_owned(), "2026.02.0".to_owned()))
        .cloned()
        .expect("baseline bundle");
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
        seed_authoritative_hosted_http_revision(
            &mut state.world,
            &baseline_bundle,
            baseline_bundle.service.replicas.get(),
            &[(
                1,
                hosted_http_local_identity().0,
                app_mut
                    .local_peer_id
                    .as_ref()
                    .expect("local peer id")
                    .to_string(),
                iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
            )],
        );
    }
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let baseline_ip = IpAddr::from([203, 0, 113, 77]);
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(baseline_ip),
        &method,
        &uri,
    )
    .expect_err("node-local health must not override unavailable authoritative runtime state");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(
        error.message.contains("no healthy authoritative"),
        "unexpected error: {}",
        error.message
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn hosted_http_runtime_target_rejects_matching_forged_runtime_and_local_bundle_hashes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut app = seed_public_hosted_http_current_app(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
    );
    let forged_bundle_hash = Hash::new(b"unadmitted-authoritative-bundle");
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
        let runtime_key = (
            "web_portal".to_owned(),
            "2026.02.0".to_owned(),
            "1".to_owned(),
        );
        let mut runtimes = state
            .world
            .soracloud_inrou_replica_runtime_mut_for_testing()
            .block();
        let authoritative_state = runtimes
            .get_mut(&runtime_key)
            .expect("baseline authoritative replica state");
        authoritative_state.health_status =
            iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy;
        authoritative_state.materialized_bundle_hash = forged_bundle_hash;
        runtimes.commit();
    }
    let mut forged_snapshot = app
        .soracloud_runtime
        .as_ref()
        .expect("hosted runtime")
        .snapshot();
    forged_snapshot
        .services
        .get_mut("web_portal")
        .and_then(|versions| versions.get_mut("2026.02.0"))
        .expect("baseline local runtime plan")
        .bundle_hash = forged_bundle_hash.to_string();
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .soracloud_runtime = Some(Arc::new(TestLocalReadRuntime::snapshot_only(
        forged_snapshot,
    )));
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let baseline_ip = IpAddr::from([203, 0, 113, 7]);
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(baseline_ip),
        &method,
        &uri,
    )
    .expect_err("matching forged runtime and local hashes must not bypass the admitted bundle");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(
        error.message.contains("no healthy authoritative"),
        "unexpected error: {}",
        error.message
    );
    let exact_error =
        super::resolve_exact_hosted_http_runtime_target(&app, "web_portal", "2026.02.0", 1)
            .expect_err("exact hosted execution must reject an unadmitted runtime bundle");
    assert_eq!(
        exact_error.kind,
        SoracloudRuntimeExecutionErrorKind::Unavailable
    );
    assert!(
        exact_error
            .message
            .contains("no matching healthy authoritative runtime state"),
        "unexpected error: {}",
        exact_error.message
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn hosted_http_runtime_target_rejects_unadmitted_bundle_for_remote_replica() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut app = seed_public_hosted_http_current_app(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
    );
    let baseline_bundle = app
        .state
        .view()
        .world()
        .soracloud_service_revisions()
        .get(&("web_portal".to_owned(), "2026.02.0".to_owned()))
        .cloned()
        .expect("baseline bundle");
    let (remote_validator, remote_peer) = checked_torii_test_inrou_host_identity(
        0x70,
        "derive admitted remote forged-bundle host fixture key",
    );
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
        seed_authoritative_hosted_http_revision(
            &mut state.world,
            &baseline_bundle,
            baseline_bundle.service.replicas.get(),
            &[(
                1,
                remote_validator,
                remote_peer.to_string(),
                iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
            )],
        );
        let runtime_key = (
            "web_portal".to_owned(),
            "2026.02.0".to_owned(),
            "1".to_owned(),
        );
        let mut runtimes = state
            .world
            .soracloud_inrou_replica_runtime_mut_for_testing()
            .block();
        runtimes
            .get_mut(&runtime_key)
            .expect("remote authoritative runtime")
            .materialized_bundle_hash = Hash::new(b"unadmitted-remote-inrou-bundle");
        runtimes.commit();
    }
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let baseline_ip = IpAddr::from([203, 0, 113, 7]);
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(baseline_ip),
        &method,
        &uri,
    )
    .expect_err("remote routing must reject runtime state for an unadmitted artifact");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(error.message.contains("no healthy authoritative"));
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn hosted_http_runtime_target_rejects_local_snapshot_bundle_mismatch() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut app = seed_public_hosted_http_current_app(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
    );
    let mut stale_snapshot = app
        .soracloud_runtime
        .as_ref()
        .expect("hosted runtime")
        .snapshot();
    stale_snapshot
        .services
        .get_mut("web_portal")
        .and_then(|versions| versions.get_mut("2026.02.0"))
        .expect("baseline local runtime plan")
        .bundle_hash = Hash::new(b"stale-local-inrou-bundle").to_string();
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .soracloud_runtime = Some(Arc::new(TestLocalReadRuntime::snapshot_only(
        stale_snapshot,
    )));
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let baseline_ip = IpAddr::from([203, 0, 113, 7]);
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(baseline_ip),
        &method,
        &uri,
    )
    .expect_err("local runtime must materialize the admitted bundle exactly");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(
        error
            .message
            .contains("local bundle hash does not match the admitted service revision")
    );
    let exact_error =
        super::resolve_exact_hosted_http_runtime_target(&app, "web_portal", "2026.02.0", 1)
            .expect_err("exact local execution must reject a stale materialized bundle");
    assert_eq!(
        exact_error.kind,
        SoracloudRuntimeExecutionErrorKind::Unavailable
    );
    assert!(
        exact_error
            .message
            .contains("local bundle hash does not match the admitted service revision")
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn hosted_http_runtime_target_rejects_stale_local_process_generation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut app = seed_public_hosted_http_current_app(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
    );
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
        let service_name: Name = "web_portal".parse().expect("service name");
        let mut deployments = state
            .world
            .soracloud_service_deployments_mut_for_testing()
            .block();
        deployments
            .get_mut(&service_name)
            .expect("deployment")
            .process_generation = 2;
        deployments.commit();
    }
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let baseline_ip = IpAddr::from([203, 0, 113, 7]);
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(baseline_ip),
        &method,
        &uri,
    )
    .expect_err("a stale local process generation must not serve public traffic");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(
        error.message.contains("local process generation 1")
            && error.message.contains("authoritative generation 2"),
        "unexpected error: {}",
        error.message
    );

    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
        mutate_authoritative_hosted_http_placement(
            &mut state.world,
            "web_portal",
            "2026.02.0",
            1,
            |placement| {
                placement.host_availability =
                    iroha_data_model::soracloud::SoraInrouReplicaHostAvailabilityV1::Unavailable;
            },
        );
        mutate_authoritative_hosted_http_runtime(
            &mut state.world,
            "web_portal",
            "2026.02.0",
            1,
            |runtime| {
                runtime.health_status =
                    iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy;
            },
        );
    }
    let unavailable_error =
        super::resolve_exact_hosted_http_runtime_target(&app, "web_portal", "2026.02.0", 1)
            .expect_err("an unavailable sticky host must never be routed");
    assert_eq!(
        unavailable_error.kind,
        SoracloudRuntimeExecutionErrorKind::Unavailable
    );
    assert!(
        unavailable_error
            .message
            .contains("no active matching authoritative host capability or placement"),
        "unexpected error: {}",
        unavailable_error.message
    );

    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
        mutate_authoritative_hosted_http_placement(
            &mut state.world,
            "web_portal",
            "2026.02.0",
            1,
            |placement| {
                placement.host_availability =
                    iroha_data_model::soracloud::SoraInrouReplicaHostAvailabilityV1::Available;
            },
        );
        mutate_authoritative_hosted_http_runtime(
            &mut state.world,
            "web_portal",
            "2026.02.0",
            1,
            |runtime| {
                runtime.placement_incarnation = iroha_crypto::Hash::new(b"stale-placement");
            },
        );
    }
    let stale_error =
        super::resolve_exact_hosted_http_runtime_target(&app, "web_portal", "2026.02.0", 1)
            .expect_err("a healthy runtime from a stale placement incarnation must not be routed");
    assert_eq!(
        stale_error.kind,
        SoracloudRuntimeExecutionErrorKind::Unavailable
    );
    assert!(
        stale_error
            .message
            .contains("no matching healthy authoritative runtime state"),
        "unexpected error: {}",
        stale_error.message
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn resolve_hosted_http_runtime_target_fails_closed_without_snapshot_replica_targets() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut app = seed_public_hosted_http_current_app(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
    );
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(IpAddr::from([203, 0, 113, 77])),
        &method,
        &uri,
    )
    .expect("the original admitted replica routes before its local snapshot is removed");
    let mut snapshot = app.soracloud_runtime.as_ref().expect("runtime").snapshot();
    snapshot
        .services
        .get_mut("web_portal")
        .expect("service")
        .get_mut("2026.02.0")
        .expect("revision")
        .local_replicas
        .clear();
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .soracloud_runtime = Some(Arc::new(TestLocalReadRuntime::snapshot_only(snapshot)));
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(IpAddr::from([203, 0, 113, 77])),
        &method,
        &uri,
    )
    .expect_err("runtime snapshot without local replicas must fail closed");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(
        error.message.contains("no healthy authoritative replica"),
        "unexpected error: {}",
        error.message
    );
}
#[cfg(any(feature = "p2p_ws", feature = "connect"))]
#[tokio::test]
#[cfg(feature = "app_api")]
async fn resolve_hosted_http_runtime_target_rejects_snapshot_without_peer_identity() {
    let temp = tempfile::tempdir().expect("tempdir");
    let app = seed_public_hosted_http_current_app_with_replica_plans_and_snapshot_peer_id(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
        vec![hosted_http_runtime_replica_plan(
            &temp.path().join("service-baseline"),
            1,
            iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
            Some("http://127.0.0.1:18080"),
            Some(101),
        )],
        Vec::new(),
        None,
        Some(hosted_http_service_lease_state(
            iroha_data_model::soracloud::SoraServiceLeaseStatusV1::Active,
            "50".parse().expect("runtime balance"),
            100,
        )),
    );
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");

    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(IpAddr::from([203, 0, 113, 98])),
        &method,
        &uri,
    )
    .expect_err("an originless local runtime snapshot must fail closed");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(
        error.message.contains("no exact local peer identity"),
        "unexpected error: {}",
        error.message
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn resolve_hosted_http_runtime_target_rejects_snapshot_from_different_peer() {
    let temp = tempfile::tempdir().expect("tempdir");
    let remote_peer_id =
        checked_torii_test_peer_id(0x4b, "derive hosted HTTP remote snapshot peer fixture key");
    let (_, local_peer_id) = hosted_http_local_identity();
    let app = seed_public_hosted_http_current_app_with_replica_plans_and_snapshot_peer_id(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
        vec![hosted_http_runtime_replica_plan(
            &temp.path().join("service-baseline"),
            1,
            iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
            Some("http://127.0.0.1:18080"),
            Some(101),
        )],
        vec![hosted_http_runtime_replica_plan(
            &temp.path().join("service-canary"),
            1,
            iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
            None,
            None,
        )],
        Some(remote_peer_id.to_string()),
        Some(hosted_http_service_lease_state(
            iroha_data_model::soracloud::SoraServiceLeaseStatusV1::Active,
            "50".parse().expect("runtime balance"),
            100,
        )),
    );
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let baseline_ip = IpAddr::from([203, 0, 113, 77]);
    let error = super::resolve_hosted_http_runtime_target(
        &app,
        &route_match,
        Some(baseline_ip),
        &method,
        &uri,
    )
    .expect_err("foreign snapshot origin must fail closed");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(
        error.message.contains(remote_peer_id.to_string().as_str()),
        "unexpected error: {}",
        error.message
    );
    assert!(
        error.message.contains(local_peer_id.to_string().as_str()),
        "unexpected error: {}",
        error.message
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
#[cfg(feature = "app_api")]
async fn hosted_http_proxy_candidate_peers_exclude_local_and_visited() {
    let local_keypair = checked_torii_test_bls_keypair(
        0x4e,
        "derive hosted HTTP local proxy-candidate peer fixture key",
    );
    let first_remote_keypair = checked_torii_test_bls_keypair(
        0x4f,
        "derive hosted HTTP first remote proxy-candidate peer fixture key",
    );
    let second_remote_keypair = checked_torii_test_bls_keypair(
        0x50,
        "derive hosted HTTP second remote proxy-candidate peer fixture key",
    );
    let local_peer_id = PeerId::from(local_keypair.public_key().clone());
    let first_remote_peer_id = PeerId::from(first_remote_keypair.public_key().clone());
    let second_remote_peer_id = PeerId::from(second_remote_keypair.public_key().clone());
    let mut app = mk_app_state_for_tests();
    let (online_tx, online_rx) = tokio::sync::watch::channel(HashSet::new());
    online_tx
        .send(HashSet::from([
            Peer::new(
                "127.0.0.1:20001".parse().expect("valid local address"),
                local_keypair.public_key().clone(),
            ),
            Peer::new(
                "127.0.0.1:20002".parse().expect("valid remote address"),
                first_remote_keypair.public_key().clone(),
            ),
            Peer::new(
                "127.0.0.1:20003".parse().expect("valid remote address"),
                second_remote_keypair.public_key().clone(),
            ),
        ]))
        .expect("online peers update should succeed");
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .online_peers = OnlinePeersProvider::new(online_rx);
    let candidates = super::hosted_http_proxy_candidate_peer_ids(
        app.as_ref(),
        &local_peer_id,
        &[first_remote_peer_id.clone(), second_remote_peer_id.clone()],
        std::slice::from_ref(&second_remote_peer_id),
    );
    assert_eq!(candidates.peers, vec![first_remote_peer_id]);
    assert_eq!(candidates.loop_prevention_drops, 1);
}
#[cfg(feature = "connect")]
#[tokio::test]
#[cfg(feature = "app_api")]
async fn proxy_soracloud_public_hosted_http_falls_back_to_remote_peer() {
    let temp = tempfile::tempdir().expect("tempdir");
    let local_keypair =
        checked_torii_test_bls_keypair(0x51, "derive hosted HTTP local fallback peer fixture key");
    let remote_keypair = checked_torii_test_bls_keypair(
        0x70,
        "derive admitted hosted HTTP remote fallback peer fixture key",
    );
    let (remote_validator_account_id, admitted_remote_peer_id) =
        checked_torii_test_inrou_host_identity(
            0x70,
            "derive admitted hosted HTTP remote fallback account fixture key",
        );
    let local_peer_id = PeerId::from(local_keypair.public_key().clone());
    let remote_peer_id = PeerId::from(remote_keypair.public_key().clone());
    assert_eq!(remote_peer_id, admitted_remote_peer_id);
    let mut app = seed_public_hosted_http_current_app_with_replica_plans_and_snapshot_peer_id(
        &temp,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
        iroha_data_model::soracloud::SoraServiceHealthStatusV1::Unavailable,
        Vec::new(),
        Vec::new(),
        Some(local_peer_id.to_string()),
        Some(hosted_http_service_lease_state(
            iroha_data_model::soracloud::SoraServiceLeaseStatusV1::Active,
            "50".parse().expect("runtime balance"),
            100,
        )),
    );
    let baseline_bundle = app
        .state
        .view()
        .world()
        .soracloud_service_revisions()
        .get(&("web_portal".to_owned(), "2026.02.0".to_owned()))
        .cloned()
        .expect("baseline bundle");
    assert!(
        baseline_bundle
            .service
            .placement_targets
            .iter()
            .any(|target| target.peer_id == remote_peer_id.to_string()
                && target.validator_account_id == remote_validator_account_id),
        "fallback must target an admitted physical host"
    );
    let expected_materialized_bundle_hash = baseline_bundle.container.bundle_hash.to_string();
    // Retain the real bounded actor queues and inspect accepted posts before
    // injecting peer responses. This component test does not start peer sockets.
    let (network, mut actor) = iroha_core::IrohaNetwork::actor_admission_for_tests(
        local_peer_id.clone(),
        HashSet::from([remote_peer_id.clone()]),
        std::num::NonZeroUsize::new(1).expect("one pending proxy request"),
    );
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let (online_tx, online_rx) = tokio::sync::watch::channel(HashSet::new());
        online_tx
            .send(HashSet::from([
                Peer::new(
                    "127.0.0.1:21001".parse().expect("valid local address"),
                    local_keypair.public_key().clone(),
                ),
                Peer::new(
                    "127.0.0.1:21002".parse().expect("valid remote address"),
                    remote_keypair.public_key().clone(),
                ),
            ]))
            .expect("online peers update should succeed");
        app_mut.online_peers = OnlinePeersProvider::new(online_rx);
        app_mut.local_peer_id = Some(local_peer_id.clone());
        app_mut.p2p = Some(network);
        let state = Arc::get_mut(&mut app_mut.state).expect("unique state");
        seed_authoritative_hosted_http_revision(
            &mut state.world,
            &baseline_bundle,
            baseline_bundle.service.replicas.get(),
            &[(
                1,
                remote_validator_account_id,
                remote_peer_id.to_string(),
                iroha_data_model::soracloud::SoraServiceHealthStatusV1::Healthy,
            )],
        );
    }
    let route_match = hosted_http_health_route(&app);
    let method = HttpMethod::GET;
    let uri: axum::http::Uri = "/app/v1/health".parse().expect("uri");
    let baseline_ip = IpAddr::from([203, 0, 113, 77]);
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::HOST,
        HeaderValue::from_static("portal.sora"),
    );
    headers.insert("x-test-forward", HeaderValue::from_static("1"));
    let app_for_response = app.clone();
    let remote_peer_for_response = remote_peer_id.clone();
    let remote_materialized_bundle_hash = expected_materialized_bundle_hash.clone();
    let response_task = tokio::spawn(async move {
        let mut prior_request_id = None;
        for spoofed in [false, true] {
            let request_id = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let mut pending_request = None;
                    let admitted =
                        actor.drain_posts(|post| {
                            assert_eq!(post.peer_id, remote_peer_for_response);
                            let iroha_core::NetworkMessage::ToriiProxyRequest(request) = &post.data
                            else {
                                panic!("expected an admitted Torii proxy request");
                            };
                            assert_ne!(prior_request_id.as_ref(), Some(&request.request_id));
                            assert!(pending_request.replace(request.request_id).is_none());
                            assert!(app_for_response.torii_proxy_pending.lock().contains_key(&(
                                request.request_id,
                                remote_peer_for_response.clone(),
                            )));
                        });
                    assert!(admitted <= 1, "one exact request is admitted per response");
                    if let Some(request_id) = pending_request {
                        break request_id;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("hosted HTTP proxy request should reach the actor queue");
            prior_request_id = Some(request_id);
            super::process_incoming_torii_proxy_response(
                &app_for_response,
                remote_peer_for_response.clone(),
                ToriiProxyResponseV1 {
                    schema_version: TORII_PROXY_RESPONSE_VERSION_V1,
                    request_id,
                    response: ToriiProxyHttpResponseV1 {
                        status_code: StatusCode::OK.as_u16(),
                        headers: vec![
                            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                                name: "content-type".to_owned(),
                                value: b"text/plain".to_vec(),
                            },
                            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                                name: iroha_torii_shared::SORACLOUD_SERVED_SERVICE_NAME_HEADER
                                    .to_owned(),
                                value: if spoofed {
                                    b"spoofed-service".to_vec()
                                } else {
                                    b"web_portal".to_vec()
                                },
                            },
                            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                                name: iroha_torii_shared::SORACLOUD_SERVED_SERVICE_VERSION_HEADER
                                    .to_owned(),
                                value: if spoofed {
                                    b"stale-version".to_vec()
                                } else {
                                    b"2026.02.0".to_vec()
                                },
                            },
                            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                                name: iroha_torii_shared::SORACLOUD_SERVED_REPLICA_SLOT_HEADER
                                    .to_owned(),
                                value: if spoofed {
                                    b"999".to_vec()
                                } else {
                                    b"1".to_vec()
                                },
                            },
                            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                                name: iroha_torii_shared::SORACLOUD_SERVED_PROCESS_GENERATION_HEADER
                                    .to_owned(),
                                value: if spoofed {
                                    b"9".to_vec()
                                } else {
                                    b"1".to_vec()
                                },
                            },
                            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                                name: iroha_torii_shared::SORACLOUD_SERVED_MATERIALIZED_BUNDLE_HASH_HEADER
                                    .to_owned(),
                                value: if spoofed {
                                    b"hash:spoofed".to_vec()
                                } else {
                                    remote_materialized_bundle_hash.clone().into_bytes()
                                },
                            },
                        ],
                        body: if spoofed {
                            b"spoofed-remote-hosted-http".to_vec()
                        } else {
                            b"remote-hosted-http".to_vec()
                        },
                    },
                },
            )
            .await;
        }
    });
    let response = super::proxy_soracloud_public_hosted_http(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        headers.clone(),
        Bytes::from_static(b"remote-body"),
        route_match.clone(),
        Some(IpAddr::from([203, 0, 113, 77])),
    )
    .await;
    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = torii_body_bytes(response, "proxy failure body").await;
        panic!(
            "expected successful admitted proxy response, got {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    assert_eq!(
        torii_response_header(&response, "content-type"),
        Some("text/plain")
    );
    assert_eq!(
        torii_response_header(
            &response,
            iroha_torii_shared::SORACLOUD_SERVED_SERVICE_NAME_HEADER
        ),
        Some("web_portal")
    );
    assert_eq!(
        torii_response_header(
            &response,
            iroha_torii_shared::SORACLOUD_SERVED_SERVICE_VERSION_HEADER
        ),
        Some("2026.02.0")
    );
    assert_eq!(
        torii_response_header(
            &response,
            iroha_torii_shared::SORACLOUD_SERVED_REPLICA_SLOT_HEADER
        ),
        Some("1")
    );
    assert_eq!(
        torii_response_header(
            &response,
            iroha_torii_shared::SORACLOUD_SERVED_PROCESS_GENERATION_HEADER
        ),
        Some("1")
    );
    assert_eq!(
        torii_response_header(
            &response,
            iroha_torii_shared::SORACLOUD_SERVED_MATERIALIZED_BUNDLE_HASH_HEADER
        ),
        Some(expected_materialized_bundle_hash.as_str())
    );
    for header_name in [
        iroha_torii_shared::SORACLOUD_SERVED_SERVICE_NAME_HEADER,
        iroha_torii_shared::SORACLOUD_SERVED_SERVICE_VERSION_HEADER,
        iroha_torii_shared::SORACLOUD_SERVED_REPLICA_SLOT_HEADER,
        iroha_torii_shared::SORACLOUD_SERVED_PROCESS_GENERATION_HEADER,
        iroha_torii_shared::SORACLOUD_SERVED_MATERIALIZED_BUNDLE_HASH_HEADER,
    ] {
        assert_eq!(
            response.headers().get_all(header_name).iter().count(),
            1,
            "remote-provided `{header_name}` values must be replaced at ingress"
        );
    }
    let body = torii_body_bytes(response, "response body should be readable").await;
    assert_eq!(body.as_ref(), b"remote-hosted-http");

    let spoofed_response = super::proxy_soracloud_public_hosted_http(
        State(app),
        method,
        uri,
        headers,
        Bytes::from_static(b"remote-body"),
        route_match,
        Some(baseline_ip),
    )
    .await;
    response_task
        .await
        .expect("proxy response task should complete");
    assert_eq!(spoofed_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    for header_name in [
        iroha_torii_shared::SORACLOUD_SERVED_SERVICE_NAME_HEADER,
        iroha_torii_shared::SORACLOUD_SERVED_SERVICE_VERSION_HEADER,
        iroha_torii_shared::SORACLOUD_SERVED_REPLICA_SLOT_HEADER,
        iroha_torii_shared::SORACLOUD_SERVED_PROCESS_GENERATION_HEADER,
        iroha_torii_shared::SORACLOUD_SERVED_MATERIALIZED_BUNDLE_HASH_HEADER,
    ] {
        assert!(
            spoofed_response.headers().get(header_name).is_none(),
            "a mismatched remote `{header_name}` proof must fail closed instead of being relabeled"
        );
    }
}
#[test]
#[cfg(feature = "app_api")]
fn hosted_http_origin_rejects_spoofed_or_duplicate_remote_served_revision_headers() {
    let target = super::ResolvedHostedHttpTarget {
        route_match: soracloud::HostedHttpRouteMatch {
            service_name: "web_portal".to_owned(),
            service_version: "2026.02.0".to_owned(),
            request_path: "/v1/health".to_owned(),
        },
        replica_slot: 1,
        assigned_peer_id: checked_torii_test_peer_id(
            0x54,
            "derive served-revision validation peer fixture key",
        ),
        local_listen_base_url: None,
        materialized_bundle_hash: Hash::new(b"served-revision-bundle").to_string(),
        process_generation: 1,
    };
    let spoofed = Response::builder()
        .status(StatusCode::OK)
        .header(
            iroha_torii_shared::SORACLOUD_SERVED_SERVICE_NAME_HEADER,
            "spoofed-service",
        )
        .header(
            iroha_torii_shared::SORACLOUD_SERVED_SERVICE_VERSION_HEADER,
            "stale-version",
        )
        .header(
            iroha_torii_shared::SORACLOUD_SERVED_REPLICA_SLOT_HEADER,
            "999",
        )
        .header(
            iroha_torii_shared::SORACLOUD_SERVED_PROCESS_GENERATION_HEADER,
            "9",
        )
        .header(
            iroha_torii_shared::SORACLOUD_SERVED_MATERIALIZED_BUNDLE_HASH_HEADER,
            "hash:spoofed",
        )
        .body(Body::empty())
        .expect("spoofed hosted response");
    let error = super::validate_soracloud_served_revision_headers(&spoofed, &target)
        .expect_err("guest-provided served-revision headers must not bind a remote response");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);

    let mut stamped = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .expect("hosted response");
    super::overwrite_soracloud_served_revision_headers(&mut stamped, &target)
        .expect("Torii-owned served-revision headers");
    super::validate_soracloud_served_revision_headers(&stamped, &target)
        .expect("exact Torii-owned served-revision headers");
    let mut stale_generation = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .expect("stale-generation hosted response");
    super::overwrite_soracloud_served_revision_headers(&mut stale_generation, &target)
        .expect("Torii-owned served-revision headers");
    stale_generation.headers_mut().insert(
        iroha_torii_shared::SORACLOUD_SERVED_PROCESS_GENERATION_HEADER,
        HeaderValue::from_static("2"),
    );
    let stale_generation_error =
        super::validate_soracloud_served_revision_headers(&stale_generation, &target)
            .expect_err("a stale remote process generation must fail closed");
    assert_eq!(
        stale_generation_error.kind,
        SoracloudRuntimeExecutionErrorKind::Unavailable
    );
    stamped.headers_mut().append(
        iroha_torii_shared::SORACLOUD_SERVED_MATERIALIZED_BUNDLE_HASH_HEADER,
        HeaderValue::from_static("hash:spoofed"),
    );
    let duplicate_error = super::validate_soracloud_served_revision_headers(&stamped, &target)
        .expect_err("duplicate remote served-revision headers must fail closed");
    assert_eq!(
        duplicate_error.kind,
        SoracloudRuntimeExecutionErrorKind::Unavailable
    );
    assert!(
        duplicate_error.message.contains("duplicate Torii-owned"),
        "unexpected error: {}",
        duplicate_error.message
    );
}

#[tokio::test]
#[cfg(feature = "connect")]
async fn authoritative_lane_peers_require_explicit_bindings_for_permissioned_routes() {
    let local_keypair =
        checked_torii_test_ed25519_keypair(0x58, "derive authoritative-lane local fixture key");
    let remote_keypair =
        checked_torii_test_ed25519_keypair(0x59, "derive authoritative-lane remote fixture key");
    let local_peer_id = PeerId::from(local_keypair.public_key().clone());
    let remote_peer_id = PeerId::from(remote_keypair.public_key().clone());
    let identityless_app = mk_app_state_for_tests();
    assert!(
        !super::is_local_authoritative_for_peers(
            identityless_app.as_ref(),
            std::slice::from_ref(&remote_peer_id),
        ),
        "a missing local peer identity must never authorize a nonempty lane roster"
    );
    assert!(
        !super::should_execute_route_locally(
            identityless_app.as_ref(),
            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        ),
        "an unresolved default-lane roster must not authorize an identityless local executor"
    );
    let mut app = mk_app_state_for_tests();
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let (online_tx, online_rx) = tokio::sync::watch::channel(std::collections::HashSet::new());
        let local_peer = Peer::new(
            "127.0.0.1:10001".parse().expect("valid local address"),
            local_keypair.public_key().clone(),
        );
        let remote_peer = Peer::new(
            "127.0.0.1:10002".parse().expect("valid remote address"),
            remote_keypair.public_key().clone(),
        );
        online_tx
            .send(HashSet::from([local_peer, remote_peer]))
            .expect("online peers update should succeed");
        app_mut.online_peers = OnlinePeersProvider::new(online_rx);
        app_mut.local_peer_id = Some(local_peer_id.clone());
    }
    {
        let mut topology = app.state.commit_topology.block();
        topology.clear();
        topology.push(local_peer_id.clone());
        topology.push(remote_peer_id.clone());
        topology.commit();
    }
    let header = BlockHeader::new(
        NonZeroU64::new(1).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    let mut peers = block.world.peers_mut_for_testing().transaction();
    peers.clear();
    peers.push(local_peer_id.clone());
    peers.push(remote_peer_id.clone());
    peers.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit permissioned peer roster");
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let authoritative = super::authoritative_lane_peers(app.as_ref(), route).authoritative;
    assert!(
        authoritative.is_empty(),
        "permissioned public routes should fail closed without explicit authoritative bindings"
    );
    assert!(
        !super::is_local_authoritative_for_route(app.as_ref(), route),
        "permissioned public ingress should not infer authority from commit topology"
    );
    assert!(
        !super::should_execute_route_locally(app.as_ref(), route),
        "the default lane must fail closed when no authoritative bindings exist"
    );
}
struct TwoOnlinePeerFixture {
    app: SharedAppState,
    local_peer_id: PeerId,
    remote_peer_id: PeerId,
}
fn two_online_peer_fixture() -> TwoOnlinePeerFixture {
    let local_keypair =
        checked_torii_test_ed25519_keypair(0x58, "derive authoritative-lane local fixture key");
    let remote_keypair =
        checked_torii_test_ed25519_keypair(0x59, "derive authoritative-lane remote fixture key");
    let local_peer_id = PeerId::from(local_keypair.public_key().clone());
    let remote_peer_id = PeerId::from(remote_keypair.public_key().clone());
    let mut app = mk_app_state_for_tests();
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let (online_tx, online_rx) = tokio::sync::watch::channel(std::collections::HashSet::new());
        let local_peer = Peer::new(
            "127.0.0.1:10001".parse().expect("valid local address"),
            local_keypair.public_key().clone(),
        );
        let remote_peer = Peer::new(
            "127.0.0.1:10002".parse().expect("valid remote address"),
            remote_keypair.public_key().clone(),
        );
        online_tx
            .send(HashSet::from([local_peer, remote_peer]))
            .expect("online peers update should succeed");
        app_mut.online_peers = OnlinePeersProvider::new(online_rx);
        app_mut.local_peer_id = Some(local_peer_id.clone());
    }
    TwoOnlinePeerFixture {
        app,
        local_peer_id,
        remote_peer_id,
    }
}
fn install_two_peer_npos_roster(
    app: &SharedAppState,
    local_peer_id: &PeerId,
    remote_peer_id: &PeerId,
) {
    {
        let mut topology = app.state.commit_topology.block();
        topology.clear();
        topology.push(local_peer_id.clone());
        topology.push(remote_peer_id.clone());
        topology.commit();
    }
    let header = BlockHeader::new(
        NonZeroU64::new(1).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    block
        .world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        ))
        .expect("install the committed NPoS fixture parameters");
    let mut peers = block.world.peers_mut_for_testing().transaction();
    peers.clear();
    peers.push(local_peer_id.clone());
    peers.push(remote_peer_id.clone());
    peers.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit npos peer roster");
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn authoritative_lane_peers_do_not_fall_back_to_commit_topology_for_npos_core_lane() {
    let TwoOnlinePeerFixture {
        app,
        local_peer_id,
        remote_peer_id,
    } = two_online_peer_fixture();
    install_two_peer_npos_roster(&app, &local_peer_id, &remote_peer_id);
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let authoritative = super::authoritative_lane_peers(app.as_ref(), route).authoritative;
    assert!(
        authoritative.is_empty(),
        "NPoS core-lane routing should fail closed when no authoritative bindings are present"
    );
    assert!(
        !super::is_local_authoritative_for_route(app.as_ref(), route),
        "NPoS core-lane ingress should no longer infer authority from commit topology"
    );
    assert!(
        !super::should_execute_route_locally(app.as_ref(), route),
        "the default NPoS lane must fail closed without explicit bindings"
    );
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn one_lane_without_authoritative_binding_returns_route_unavailable() {
    let TwoOnlinePeerFixture {
        app,
        local_peer_id: _,
        remote_peer_id: _,
    } = two_online_peer_fixture();
    let nexus = app.state.nexus_snapshot();
    assert_eq!(
        nexus.lane_catalog.lanes().len(),
        1,
        "fixture must exercise the one-lane catalog"
    );
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let request = ToriiProxyRequestKindV1::Read(super::torii_read_request(
        ToriiReadEndpointV1::AccountGet,
        ToriiFanoutRouteScopeV1::AllDataspaces,
        route,
        vec![
            checked_torii_test_account_id(
                0x5A,
                "derive unresolved one-lane routed-read account fixture key",
            )
            .to_string(),
        ],
        None,
        Vec::new(),
    ));
    let response = super::execute_torii_proxy_request_with_fallback(&app, route, request).await;
    assert_route_unavailable_response(&response);
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-unavailable-reason"),
        Some("missing_authoritative_binding")
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn authoritative_lane_peers_do_not_fall_back_to_online_peers_when_state_is_empty() {
    let TwoOnlinePeerFixture {
        app,
        local_peer_id: _,
        remote_peer_id: _,
    } = two_online_peer_fixture();
    {
        let mut topology = app.state.commit_topology.block();
        topology.clear();
        topology.commit();
    }
    {
        let header = BlockHeader::new(
            NonZeroU64::new(1).expect("non-zero height"),
            None,
            None,
            0,
            0,
        );
        let mut block = app.state.block(header);
        block
            .world
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(
                SumeragiNposParameters::default().into_custom_parameter(),
            ))
            .expect("install the committed NPoS fixture parameters");
        let mut peers = block.world.peers_mut_for_testing().transaction();
        peers.clear();
        peers.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit empty npos peer roster");
    }
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let authoritative = super::authoritative_lane_peers(app.as_ref(), route).authoritative;
    assert!(
        authoritative.is_empty(),
        "empty state snapshots should leave authoritative routing unresolved"
    );
    assert!(
        !super::is_local_authoritative_for_route(app.as_ref(), route),
        "empty state snapshots should not infer local authority from connected peers"
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn authoritative_lane_peers_do_not_fall_back_for_npos_non_core_lane() {
    let TwoOnlinePeerFixture {
        app,
        local_peer_id,
        remote_peer_id,
    } = two_online_peer_fixture();
    install_two_peer_npos_roster(&app, &local_peer_id, &remote_peer_id);
    let route = RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1));
    let authoritative = super::authoritative_lane_peers(app.as_ref(), route).authoritative;
    assert!(
        authoritative.is_empty(),
        "non-core NPoS routes should still require explicit public validator records"
    );
    assert!(
        !super::is_local_authoritative_for_route(app.as_ref(), route),
        "non-core NPoS routes should not treat commit topology peers as authoritative"
    );
    assert!(
        !super::should_execute_route_locally(app.as_ref(), route),
        "non-core routes should continue to fail closed without explicit bindings"
    );
}
struct AdminManagedLaneFixture {
    app: SharedAppState,
    nexus: iroha_config::parameters::actual::Nexus,
    local_validator: AccountId,
    remote_validator: AccountId,
    local_peer_id: PeerId,
    remote_peer_id: PeerId,
    additional_remote_authorities: Vec<(AccountId, PeerId)>,
    lane_id: LaneId,
    dataspace_id: DataSpaceId,
}
fn admin_managed_lane_fixture(local_votes_globally: bool) -> AdminManagedLaneFixture {
    let local_validator_keypair = checked_torii_test_ed25519_keypair(
        0x5a,
        "derive authoritative-lane local validator fixture key",
    );
    let remote_validator_keypair = checked_torii_test_ed25519_keypair(
        0x5b,
        "derive authoritative-lane remote validator fixture key",
    );
    let local_peer_keypair =
        checked_torii_test_bls_keypair(0x5c, "derive authoritative-lane local peer fixture key");
    let remote_peer_keypair =
        checked_torii_test_bls_keypair(0x5d, "derive authoritative-lane remote peer fixture key");
    let additional_remote_authorities = (0_u8..3)
        .map(|index| {
            let validator_keypair = checked_torii_test_ed25519_keypair(
                0x80 + index,
                "derive additional admin-lane validator fixture key",
            );
            let peer_keypair = checked_torii_test_bls_keypair(
                0x83 + index,
                "derive additional admin-lane peer fixture key",
            );
            (
                AccountId::new(validator_keypair.public_key().clone()),
                peer_keypair,
            )
        })
        .collect::<Vec<_>>();
    let local_validator = AccountId::new(local_validator_keypair.public_key().clone());
    let remote_validator = AccountId::new(remote_validator_keypair.public_key().clone());
    let local_peer_id = PeerId::from(local_peer_keypair.public_key().clone());
    let remote_peer_id = PeerId::from(remote_peer_keypair.public_key().clone());
    let lane_id = LaneId::new(1);
    let dataspace_id = DataSpaceId::new(1);
    let nexus = {
        let lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
            NonZeroU32::new(2).expect("non-zero lane count"),
            vec![
                iroha_data_model::nexus::LaneConfig::default(),
                iroha_data_model::nexus::LaneConfig {
                    id: lane_id,
                    dataspace_id,
                    alias: format!("lane-{}", lane_id.as_u32()),
                    visibility: iroha_data_model::nexus::LaneVisibility::Restricted,
                    ..iroha_data_model::nexus::LaneConfig::default()
                },
            ],
        )
        .expect("lane catalog");
        let dataspace_catalog = iroha_data_model::nexus::DataSpaceCatalog::new(vec![
            iroha_data_model::nexus::DataSpaceMetadata::default(),
            iroha_data_model::nexus::DataSpaceMetadata {
                id: dataspace_id,
                alias: "restricted".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("dataspace catalog");
        iroha_config::parameters::actual::Nexus {
            lane_config: iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog),
            configured_lane_catalog: lane_catalog.clone(),
            configured_dataspace_catalog: dataspace_catalog.clone(),
            lane_catalog,
            dataspace_catalog,
            ..iroha_config::parameters::actual::Nexus::default()
        }
    };
    let mut original_members = vec![
        (local_validator.clone(), local_peer_keypair.clone()),
        (remote_validator.clone(), remote_peer_keypair.clone()),
    ];
    original_members.extend(additional_remote_authorities.iter().cloned());
    let mut labels = vec![
        "local".to_owned(),
        "remote".to_owned(),
        "remote-2".to_owned(),
        "remote-3".to_owned(),
        "remote-4".to_owned(),
    ];
    if !local_votes_globally {
        // The receiver is an observer. Its original peer is registered through paid H2;
        // the exact four remote peers are the genuine permissioned genesis committee.
        let local = original_members.remove(0);
        let local_label = labels.remove(0);
        original_members.push(local);
        labels.push(local_label);
    }
    let mut app = native_ingress_with_registered_route_peers_for_test(
        World::default(),
        nexus.clone(),
        &original_members,
        &labels,
    );
    let app_mut = Arc::get_mut(&mut app).expect("unique app state");
    let (online_tx, online_rx) = tokio::sync::watch::channel(std::collections::HashSet::new());
    online_tx
        .send(std::collections::HashSet::from([
            Peer::new(
                "127.0.0.1:10001".parse().expect("valid local address"),
                local_peer_keypair.public_key().clone(),
            ),
            Peer::new(
                "127.0.0.1:10002".parse().expect("valid remote address"),
                remote_peer_keypair.public_key().clone(),
            ),
        ]))
        .expect("online peers update should succeed");
    app_mut.online_peers = OnlinePeersProvider::new(online_rx);
    app_mut.local_peer_id = Some(local_peer_id.clone());
    let additional_remote_authorities = additional_remote_authorities
        .into_iter()
        .map(|(validator, peer_keypair)| {
            (validator, PeerId::from(peer_keypair.public_key().clone()))
        })
        .collect();
    AdminManagedLaneFixture {
        app,
        nexus,
        local_validator,
        remote_validator,
        local_peer_id,
        remote_peer_id,
        additional_remote_authorities,
        lane_id,
        dataspace_id,
    }
}
fn exact_admin_committee_with_local(
    local_validator: &AccountId,
    local_peer_id: &PeerId,
    remote_validator: &AccountId,
    remote_peer_id: &PeerId,
    additional_remote_authorities: &[(AccountId, PeerId)],
) -> Vec<(AccountId, PeerId)> {
    let mut committee = vec![
        (local_validator.clone(), local_peer_id.clone()),
        (remote_validator.clone(), remote_peer_id.clone()),
    ];
    committee.extend(additional_remote_authorities.iter().take(2).cloned());
    assert_eq!(committee.len(), 4, "f=1 fixture committee must be 3f+1");
    committee
}
fn exact_remote_admin_committee(
    remote_validator: &AccountId,
    remote_peer_id: &PeerId,
    additional_remote_authorities: &[(AccountId, PeerId)],
) -> Vec<(AccountId, PeerId)> {
    let mut committee = vec![(remote_validator.clone(), remote_peer_id.clone())];
    committee.extend(additional_remote_authorities.iter().cloned());
    assert_eq!(committee.len(), 4, "f=1 fixture committee must be 3f+1");
    committee
}
#[cfg(feature = "connect")]
fn sorted_admin_peer_ids_for_test(committee: &[(AccountId, PeerId)]) -> Vec<PeerId> {
    let mut peers = committee
        .iter()
        .map(|(_, peer)| peer.clone())
        .collect::<Vec<_>>();
    peers.sort();
    assert_eq!(peers.len(), 4);
    peers
}
#[cfg(feature = "connect")]
fn assert_physical_and_global_route_sources_for_test(
    app: &SharedAppState,
    route: RoutingDecision,
    expected_physical: &[PeerId],
    expected_global: &[PeerId],
) {
    let physical = app
        .state
        .resolve_lane_committee(super::lane_authority_route(route))
        .expect("original physical admission committee");
    let global = app
        .state
        .resolve_route_authority(super::lane_authority_route(route))
        .expect("original scheduled global route committee");
    assert_eq!(
        physical.validators(),
        expected_physical,
        "physical admission retains original manifest or Nexus pin custody"
    );
    assert_eq!(
        global.validators(),
        expected_global,
        "Torii route retains the actual scheduled global committee independently of manifest pools"
    );
    assert_eq!(
        super::authoritative_lane_peers(app.as_ref(), route).authoritative,
        expected_global
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn authoritative_lane_peers_use_scheduled_global_committee_for_admin_managed_lane() {
    let AdminManagedLaneFixture {
        mut app,
        nexus,
        local_validator,
        remote_validator,
        local_peer_id,
        remote_peer_id,
        additional_remote_authorities,
        lane_id,
        dataspace_id,
    } = admin_managed_lane_fixture(true);
    let exact_committee = exact_admin_committee_with_local(
        &local_validator,
        &local_peer_id,
        &remote_validator,
        &remote_peer_id,
        &additional_remote_authorities,
    );
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = app_mut.state.as_ref();
        {
            let mut topology = state.commit_topology.block();
            topology.clear();
            topology.push(local_peer_id.clone());
            topology.push(remote_peer_id.clone());
            topology.commit();
        }
        install_lane_manifest_registry_for_test(state, &[(lane_id, exact_committee.clone())]);
        let state_view = app_mut.state.view();
        app_mut.queue.reconfigure_nexus(&nexus, &state_view, None);
    }
    let route = RoutingDecision::new(lane_id, dataspace_id);
    let expected_global = sorted_admin_peer_ids_for_test(&exact_committee);
    assert_physical_and_global_route_sources_for_test(
        &app,
        route,
        &expected_global,
        &expected_global,
    );
    let remote_manifest = exact_remote_admin_committee(
        &remote_validator,
        &remote_peer_id,
        &additional_remote_authorities,
    );
    let expected_native = sorted_admin_peer_ids_for_test(&remote_manifest);
    assert!(!expected_native.contains(&local_peer_id));
    install_lane_manifest_registry_for_test(&app.state, &[(lane_id, remote_manifest)]);
    assert_physical_and_global_route_sources_for_test(
        &app,
        route,
        &expected_native,
        &expected_global,
    );
    let authoritative = super::authoritative_lane_peers(app.as_ref(), route).authoritative;
    assert!(
        authoritative.contains(&local_peer_id),
        "restricted route retains its scheduled global local validator after manifest replacement"
    );
    assert!(
        authoritative.contains(&remote_peer_id),
        "restricted route retains its scheduled global remote validator"
    );
    assert_eq!(
        authoritative.len(),
        4,
        "f=1 scheduled global route authority must resolve to exactly 3f+1 validators"
    );
    assert!(
        super::is_local_authoritative_for_route(app.as_ref(), route),
        "permissioned global routing uses genuine genesis voters without staking records"
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn physical_route_keeps_scheduled_global_authority_across_native_autoscale_activation() {
    use iroha_data_model::sumeragi_lanes::{SumeragiLaneAutoscale, SumeragiLanePolicy};
    let local_keypair =
        checked_torii_test_ed25519_keypair(0x58, "derive authoritative-lane local fixture key");
    let authoritative_validator_keypair = checked_torii_test_ed25519_keypair(
        0x5e,
        "derive authoritative-lane manifest validator fixture key",
    );
    let authoritative_peer_keypair =
        checked_torii_test_bls_keypair(0x5f, "derive authoritative-lane manifest peer fixture key");
    let local_peer_id = PeerId::from(local_keypair.public_key().clone());
    let authoritative_validator =
        AccountId::new(authoritative_validator_keypair.public_key().clone());
    let authoritative_peer_id = PeerId::from(authoritative_peer_keypair.public_key().clone());
    let pinned_keypairs = (0x76_u8..=0x79)
        .map(|seed| {
            checked_torii_test_bls_keypair(seed, "derive activated autoscale peer fixture key")
        })
        .collect::<Vec<_>>();
    let mut pinned_peer_ids = pinned_keypairs
        .iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    pinned_peer_ids.sort();
    let lane_id = LaneId::new(1);
    let dataspace_id = DataSpaceId::UNIVERSAL;
    // The manual physical profile and the native elastic instance intentionally
    // share a numeric ID. Neither representation grants the other's authority
    // (sumeragi_lanes.md §5.1). No retired Nexus autoscale metadata is installed.
    let physical_profile = iroha_data_model::nexus::LaneConfig {
        id: lane_id,
        alias: "manual-physical-profile".to_owned(),
        ..iroha_data_model::nexus::LaneConfig::default()
    };
    let lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
        NonZeroU32::new(2).unwrap(),
        vec![
            iroha_data_model::nexus::LaneConfig::default(),
            physical_profile.clone(),
        ],
    )
    .expect("independent manual physical lane catalog");
    let nexus = iroha_config::parameters::actual::Nexus {
        configured_lane_catalog: lane_catalog.clone(),
        lane_config: iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog),
        lane_catalog,
        ..iroha_config::parameters::actual::Nexus::default()
    };
    let mut policy = SumeragiLanePolicy::for_chain(
        iroha_data_model::parameter::system::SumeragiParameters::default(),
        iroha_sumeragi::availability::recommended_data_availability_layout(),
    );
    policy.autoscale = Some(SumeragiLaneAutoscale {
        min_lane: lane_id,
        max_lane_exclusive: LaneId::new(2),
        dataspace: dataspace_id,
        committee_size: 4,
        per_lane_target_tps: 10,
        window: 6,
        scale_out_permille: 300,
        scale_in_permille: 150,
        cooldown: 3,
    });
    policy
        .validate()
        .expect("original finite native autoscale policy");
    let mut members = pinned_keypairs
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let validator = checked_torii_test_account_id(
                0x90 + u8::try_from(index).unwrap(),
                "derive independent pinned fixture validator account",
            );
            (validator, key.clone())
        })
        .collect::<Vec<_>>();
    members.push((
        authoritative_validator.clone(),
        authoritative_peer_keypair.clone(),
    ));
    let labels = vec![
        "pinned-0".to_owned(),
        "pinned-1".to_owned(),
        "pinned-2".to_owned(),
        "pinned-3".to_owned(),
        "authoritative".to_owned(),
    ];
    let (mut app, mut chain, genesis_key) =
        native_ingress_with_registered_route_peers_and_chain_for_test(
            World::default(),
            nexus,
            &members,
            &labels,
            vec![iroha_data_model::parameter::Parameter::Custom(
                policy.into_custom_parameter(),
            )],
        );
    {
        let unique = Arc::get_mut(&mut app).expect("unique real autoscale app fixture");
        let (online_tx, online_rx) =
            tokio::sync::watch::channel(std::collections::HashSet::from([
                Peer::new(
                    "127.0.0.1:10001".parse().unwrap(),
                    local_keypair.public_key().clone(),
                ),
                Peer::new(
                    "127.0.0.1:10002".parse().unwrap(),
                    authoritative_peer_keypair.public_key().clone(),
                ),
            ]));
        let _keep_online = online_tx;
        unique.online_peers = OnlinePeersProvider::new(online_rx);
        unique.local_peer_id = Some(local_peer_id.clone());
    }
    let mut physical_manifest = vec![(authoritative_validator, authoritative_peer_id.clone())];
    physical_manifest.extend(
        members
            .iter()
            .take(3)
            .map(|(validator, key)| (validator.clone(), PeerId::new(key.public_key().clone()))),
    );
    let physical_committee = sorted_admin_peer_ids_for_test(&physical_manifest);
    assert_ne!(
        physical_committee, pinned_peer_ids,
        "physical manifest and native pin are independent"
    );
    install_lane_manifest_registry_for_test(&app.state, &[(lane_id, physical_manifest)]);
    let route = RoutingDecision::new(lane_id, dataspace_id);
    assert_eq!(app.state.view().height(), 3);
    assert!(
        app.state
            .view()
            .world()
            .sumeragi_lanes()
            .lane(lane_id)
            .is_none(),
        "native lane cannot exist before its original six-interval load window"
    );
    assert_physical_and_global_route_sources_for_test(
        &app,
        route,
        &physical_committee,
        &pinned_peer_ids,
    );
    // Missing physical geometry and a mismatched physical dataspace remain refusals;
    // the legitimate manual profile is not deactivated by an absent native record.
    for inactive in [
        RoutingDecision::new(LaneId::new(2), dataspace_id),
        RoutingDecision::new(lane_id, DataSpaceId::new(1)),
    ] {
        assert!(
            super::authoritative_lane_peers(app.as_ref(), inactive)
                .authoritative
                .is_empty()
        );
        assert!(
            app.state
                .resolve_lane_committee(super::lane_authority_route(inactive))
                .is_err()
        );
        assert!(
            app.state
                .resolve_route_authority(super::lane_authority_route(inactive))
                .is_err()
        );
    }
    advance_registered_route_fixture_for_test(&mut chain, &genesis_key, 6);
    assert!(
        app.state
            .view()
            .world()
            .sumeragi_lanes()
            .lane(lane_id)
            .is_none(),
        "native creation must wait until H7"
    );
    advance_registered_route_fixture_for_test(&mut chain, &genesis_key, 7);
    let created = {
        let view = app.state.view();
        let record = view
            .world()
            .sumeragi_lanes()
            .lane(lane_id)
            .expect("actual autoscale step creates native lane at H7");
        assert_eq!(record.created_at, 7);
        assert_eq!(record.active_from, 9);
        assert_eq!(record.dataspace, dataspace_id);
        assert!(!record.admits_anchor(7));
        assert!(!record.admits_anchor(8));
        assert!(record.admits_anchor(9));
        let peers = record
            .committee
            .iter()
            .map(|member| member.peer.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            peers, pinned_peer_ids,
            "native creation pins the original four genuine global voters"
        );
        for member in &record.committee {
            let key = pinned_keypairs
                .iter()
                .find(|key| key.public_key() == member.peer.public_key())
                .expect("original native voter key");
            assert_eq!(
                member.pop,
                iroha_crypto::bls_normal_pop_prove(key.private_key())
                    .expect("original native voter PoP")
            );
        }
        assert_eq!(
            view.nexus()
                .lane_catalog
                .lanes()
                .iter()
                .find(|lane| lane.id == lane_id),
            Some(&physical_profile),
            "native step preserves the exact independent physical profile"
        );
        record.clone()
    };
    assert_physical_and_global_route_sources_for_test(
        &app,
        route,
        &physical_committee,
        &pinned_peer_ids,
    );
    advance_registered_route_fixture_for_test(&mut chain, &genesis_key, 9);
    assert_eq!(app.state.view().height(), 9);
    assert_eq!(
        app.state.view().world().sumeragi_lanes().lane(lane_id),
        Some(&created),
        "native activation retains the exact original creation record"
    );
    assert_physical_and_global_route_sources_for_test(
        &app,
        route,
        &physical_committee,
        &pinned_peer_ids,
    );
    install_lane_manifest_registry_for_test(
        &app.state,
        &[(
            lane_id,
            members
                .iter()
                .take(4)
                .map(|(validator, key)| (validator.clone(), PeerId::new(key.public_key().clone())))
                .collect(),
        )],
    );
    assert_physical_and_global_route_sources_for_test(
        &app,
        route,
        &pinned_peer_ids,
        &pinned_peer_ids,
    );
    assert_eq!(
        app.state.view().world().sumeragi_lanes().lane(lane_id),
        Some(&created),
        "mutable physical manifest cannot replace native custody"
    );
    {
        let mut topology = app.state.commit_topology.block();
        topology.clear();
        topology.push(local_peer_id);
        topology.push(authoritative_peer_id.clone());
        topology.commit();
    }
    assert_eq!(
        super::authoritative_lane_peers(app.as_ref(), route).authoritative,
        pinned_peer_ids,
        "scheduled genuine global committee remains authoritative across native activation and local transport changes"
    );
    assert!(
        !pinned_peer_ids.contains(&authoritative_peer_id),
        "fixture manifest authority remains disjoint from native/global committee"
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn scheduled_global_route_authority_ignores_local_commit_topology_filtering() {
    let AdminManagedLaneFixture {
        mut app,
        nexus,
        local_validator: _,
        remote_validator,
        local_peer_id,
        remote_peer_id,
        additional_remote_authorities,
        lane_id,
        dataspace_id,
    } = admin_managed_lane_fixture(false);
    let exact_remote_committee = exact_remote_admin_committee(
        &remote_validator,
        &remote_peer_id,
        &additional_remote_authorities,
    );
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = app_mut.state.as_ref();
        {
            let mut topology = state.commit_topology.block();
            topology.clear();
            topology.push(local_peer_id.clone());
            topology.commit();
        }
        install_lane_manifest_registry_for_test(
            state,
            &[(lane_id, exact_remote_committee.clone())],
        );
        let state_view = app_mut.state.view();
        app_mut.queue.reconfigure_nexus(&nexus, &state_view, None);
    }
    let route = RoutingDecision::new(lane_id, dataspace_id);
    let expected_global = sorted_admin_peer_ids_for_test(&exact_remote_committee);
    assert_physical_and_global_route_sources_for_test(
        &app,
        route,
        &expected_global,
        &expected_global,
    );
    let authoritative = super::authoritative_lane_peers(app.as_ref(), route);
    let candidates =
        super::torii_proxy_candidate_peer_ids(app.as_ref(), &local_peer_id, route, None, &[]);
    assert!(
        authoritative.authoritative.contains(&remote_peer_id),
        "scheduled global route keeps remote authorities even when local transport topology omits them"
    );
    assert_eq!(
        authoritative.authoritative.len(),
        4,
        "f=1 remote committee must retain exact 3f+1 authority outside local topology"
    );
    assert!(
        !super::is_local_authoritative_for_route(app.as_ref(), route),
        "a peer outside the scheduled global committee cannot become authoritative just because it is local"
    );
    assert!(
        !super::should_execute_route_locally(app.as_ref(), route),
        "restricted routes without scheduled global local authority still proxy"
    );
    assert_eq!(
        candidates.peers,
        vec![ToriiProxyCandidate::P2p(remote_peer_id)],
        "Torii proxy candidate discovery routes to the scheduled global remote authority"
    );
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn incoming_proxy_reads_and_fanout_are_terminal_when_route_ownership_is_stale() {
    let AdminManagedLaneFixture {
        mut app,
        nexus,
        local_validator: _,
        remote_validator,
        local_peer_id: _,
        remote_peer_id,
        additional_remote_authorities,
        lane_id,
        dataspace_id,
    } = admin_managed_lane_fixture(false);
    let exact_remote_committee = exact_remote_admin_committee(
        &remote_validator,
        &remote_peer_id,
        &additional_remote_authorities,
    );
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        let state = app_mut.state.as_ref();
        install_lane_manifest_registry_for_test(
            state,
            &[(lane_id, exact_remote_committee.clone())],
        );
        let state_view = app_mut.state.view();
        app_mut.queue.reconfigure_nexus(&nexus, &state_view, None);
    }
    let route = RoutingDecision::new(lane_id, dataspace_id);
    let expected_global = sorted_admin_peer_ids_for_test(&exact_remote_committee);
    assert_physical_and_global_route_sources_for_test(
        &app,
        route,
        &expected_global,
        &expected_global,
    );
    assert!(
        !super::should_execute_route_locally(app.as_ref(), route),
        "test requires a route the receiver would otherwise re-forward"
    );
    let verified_query = ToriiProxyRequestKindV1::SignedQueryRouteScan {
        query_bytes: Vec::new(),
        expected_route: ToriiRouteHintV1::from(route),
        response_format: ToriiProxyResponseFormatV1::Norito,
    };
    let read_request = ToriiProxyRequestKindV1::Read(super::torii_read_request(
        ToriiReadEndpointV1::AccountGet,
        ToriiFanoutRouteScopeV1::AllDataspaces,
        route,
        vec![
            checked_torii_test_account_id(
                0x67,
                "derive authoritative-lane proxied read account fixture key",
            )
            .to_string(),
        ],
        None,
        Vec::new(),
    ));
    let read_fanout = ToriiProxyRequestKindV1::ReadFanout(super::torii_read_fanout_request(
        ToriiReadEndpointV1::AccountGet,
        ToriiFanoutRouteScopeV1::AllDataspaces,
        ToriiReadFanoutMergeV1::Account,
        vec![ALICE_ID.to_string()],
        None,
        Vec::new(),
        ToriiProxyResponseFormatV1::Json,
    ));
    let signed_query = ToriiProxyRequestKindV1::SignedQuery {
        query_bytes: Vec::new(),
        expected_route: ToriiRouteHintV1::from(route),
        response_format: ToriiProxyResponseFormatV1::Norito,
    };
    assert!(
        super::should_execute_incoming_torii_proxy_request_locally(
            app.as_ref(),
            &verified_query,
            route,
        ),
        "signed route scans should execute on the ingress-selected receiver"
    );
    assert!(
        super::should_execute_incoming_torii_proxy_request_locally(
            app.as_ref(),
            &read_request,
            route,
        ),
        "proxied app-api reads should execute on the ingress-selected receiver"
    );
    assert!(
        super::should_execute_incoming_torii_proxy_request_locally(
            app.as_ref(),
            &read_fanout,
            route,
        ),
        "a stale/cyclic ownership view cannot re-forward an ingress-selected read fanout back to its sender"
    );
    assert!(
        !super::should_execute_incoming_torii_proxy_request_locally(
            app.as_ref(),
            &signed_query,
            route,
        ),
        "write-path signed queries must still honor local authority checks"
    );
}
#[cfg(all(feature = "app_api", feature = "connect"))]
async fn incoming_read_proxy_response_for_route(
    mut app: SharedAppState,
    route: RoutingDecision,
) -> Response {
    let ingress_peer_id = checked_torii_test_peer_id(
        0x67,
        "derive stale-route proxied read ingress peer fixture key",
    );
    Arc::get_mut(&mut app)
        .expect("stale-route fixture app must be uniquely owned")
        .local_peer_id = Some(ingress_peer_id.clone());
    let request = ToriiProxyRequestV1 {
        schema_version: TORII_PROXY_REQUEST_VERSION_V1,
        request_id: Hash::new(b"incoming-read-proxy-stale-route"),
        deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
        hop_count: 1,
        max_hops: 3,
        visited_peer_ids: vec![ingress_peer_id.clone()],
        request: ToriiProxyRequestKindV1::Read(super::torii_read_request(
            ToriiReadEndpointV1::AccountGet,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            route,
            vec![
                checked_torii_test_account_id(
                    0x68,
                    "derive stale-route proxied read account fixture key",
                )
                .to_string(),
            ],
            None,
            Vec::new(),
        )),
    };
    super::execute_incoming_torii_proxy_request(&app, request, Some(ingress_peer_id)).await
}
#[cfg(feature = "connect")]
async fn incoming_verified_query_proxy_response_for_route(
    app: SharedAppState,
    route: RoutingDecision,
) -> Response {
    incoming_signed_query_proxy_response_for_route(app, route, |authority| {
        iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::account::prelude::FindAccountById::new(authority.clone())
                .into(),
        )
    })
    .await
}
#[cfg(feature = "connect")]
async fn incoming_signed_query_proxy_response_for_route(
    app: SharedAppState,
    route: RoutingDecision,
    query: impl FnOnce(&AccountId) -> iroha_data_model::query::QueryRequest,
) -> Response {
    let key_pair =
        checked_torii_test_ed25519_keypair(0x69, "derive stale-route verified query key");
    let ingress_peer_id = PeerId::from(key_pair.public_key().clone());
    let authority = AccountId::new(key_pair.public_key().clone());
    let signed_query = authorize_query_for_test(query(&authority), authority).sign(&key_pair);
    let request = ToriiProxyRequestV1 {
        schema_version: TORII_PROXY_REQUEST_VERSION_V1,
        request_id: Hash::new(b"incoming-verified-query-proxy-stale-route"),
        deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
        hop_count: 1,
        max_hops: 3,
        visited_peer_ids: vec![ingress_peer_id],
        request: ToriiProxyRequestKindV1::SignedQueryRouteScan {
            query_bytes: iroha_version::codec::EncodeVersioned::encode_versioned(&signed_query),
            expected_route: ToriiRouteHintV1::from(route),
            response_format: ToriiProxyResponseFormatV1::Norito,
        },
    };
    super::execute_incoming_torii_proxy_request(&app, request, None).await
}
#[cfg(feature = "connect")]
fn assert_incoming_proxy_stale_route_rejection(response: &Response, route: RoutingDecision) {
    let expected_lane = route.lane_id.as_u32().to_string();
    let expected_dataspace = route.dataspace_id.as_u64().to_string();
    assert_route_unavailable_response(&response);
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-unavailable-reason"),
        Some("stale_route")
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-lane-id"),
        Some(expected_lane.as_str())
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-dataspace-id"),
        Some(expected_dataspace.as_str())
    );
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn incoming_read_proxy_rejects_retired_lane_hint() {
    let app = mk_app_state_for_tests();
    let route = RoutingDecision::new(LaneId::new(42), DataSpaceId::UNIVERSAL);
    let response = incoming_read_proxy_response_for_route(app, route).await;
    assert_incoming_proxy_stale_route_rejection(&response, route);
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn incoming_read_proxy_rejects_lane_dataspace_mismatch_hint() {
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        iroha_core::state::World::default(),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    configure_multiple_dataspace_routes_for_test(&mut app);
    let route = RoutingDecision::new(LaneId::new(1), DataSpaceId::UNIVERSAL);
    let response = incoming_read_proxy_response_for_route(app, route).await;
    assert_incoming_proxy_stale_route_rejection(&response, route);
}
