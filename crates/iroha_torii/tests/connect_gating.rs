//! Verify that Connect routes are stable while runtime configuration controls availability.
use axum::http::{Request, StatusCode, Uri};
use iroha_config::{base::WithOrigin, parameters::actual as A};
use iroha_core::{
    kiso::KisoHandle, kura::Kura, prelude::World, query::store::LiveQueryStore, queue::Queue,
    state::State,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::block::BlockHeader;
use iroha_primitives::addr::socket_addr;
use nonzero_ext::nonzero;
use std::sync::Arc;
use tower::ServiceExt;
fn request_with_loopback_connect_info(
    request: Request<axum::body::Body>,
) -> Request<axum::body::Body> {
    let mut request = request;
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            0,
        ))));
    request
}
async fn connect_aggregate_status(
    app: &axum::Router,
    cfg: &iroha_config::parameters::actual::Root,
) -> axum::response::Response {
    let uri = Uri::from_static("/v1/connect/status/aggregate");
    let headers = iroha_torii::operator_signed_request_headers(
        &cfg.common.key_pair,
        &iroha_torii::test_utils::signed_query_network_id(),
        &axum::http::Method::GET,
        &uri,
        &[],
    )
    .expect("sign Connect aggregate status request");
    let mut request = Request::builder()
        .uri(uri)
        .header(axum::http::header::ACCEPT, "application/json")
        .body(axum::body::Body::empty())
        .expect("Connect aggregate status request");
    *request.headers_mut() = headers;
    request.headers_mut().insert(
        axum::http::header::ACCEPT,
        "application/json".parse().unwrap(),
    );
    app.clone()
        .oneshot(request_with_loopback_connect_info(request))
        .await
        .expect("Connect aggregate status response")
}
async fn connect_aggregate_status_json(
    app: &axum::Router,
    cfg: &iroha_config::parameters::actual::Root,
) -> norito::json::Value {
    let response = connect_aggregate_status(app, cfg).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    norito::json::from_slice(&body).expect("status should be valid JSON")
}
#[cfg(feature = "ws_integration_tests")]
async fn connect_aggregate_status_payload(
    app: &axum::Router,
    cfg: &iroha_config::parameters::actual::Root,
) -> norito::json::Value {
    let response = connect_aggregate_status(app, cfg).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    norito::json::from_slice(&body).unwrap()
}
fn connect_status_policy(payload: &norito::json::Value) -> &norito::json::Value {
    payload.get("policy").unwrap_or(&norito::json::Value::Null)
}
struct ConnectStatusCounters {
    p2p_rebroadcasts_total: u64,
    p2p_rebroadcast_skipped_total: u64,
    relay_effective_strategy: String,
    relay_p2p_attached: bool,
}
fn connect_status_counters(payload: &norito::json::Value) -> ConnectStatusCounters {
    ConnectStatusCounters {
        p2p_rebroadcasts_total: payload
            .get("p2p_rebroadcasts_total")
            .and_then(norito::json::Value::as_u64)
            .expect("connect status should include p2p_rebroadcasts_total"),
        p2p_rebroadcast_skipped_total: payload
            .get("p2p_rebroadcast_skipped_total")
            .and_then(norito::json::Value::as_u64)
            .expect("connect status should include p2p_rebroadcast_skipped_total"),
        relay_effective_strategy: connect_status_policy(payload)
            .get("relay_effective_strategy")
            .and_then(norito::json::Value::as_str)
            .expect("connect status should include policy.relay_effective_strategy")
            .to_owned(),
        relay_p2p_attached: connect_status_policy(payload)
            .get("relay_p2p_attached")
            .and_then(norito::json::Value::as_bool)
            .expect("connect status should include policy.relay_p2p_attached"),
    }
}
fn relay_strategy(payload: &norito::json::Value) -> &str {
    connect_status_policy(payload)
        .get("relay_strategy")
        .and_then(norito::json::Value::as_str)
        .expect("connect status should include policy.relay_strategy")
}
struct AttachedConnectRelayStatus {
    relay_strategy: String,
    relay_effective_strategy: String,
    relay_p2p_attached: bool,
    p2p_rebroadcasts_total: u64,
    p2p_rebroadcast_skipped_total: u64,
}
fn attached_connect_relay_status(payload: &norito::json::Value) -> AttachedConnectRelayStatus {
    let relay_strategy = relay_strategy(payload).to_owned();
    let relay_effective_strategy = connect_status_policy(payload)
        .get("relay_effective_strategy")
        .and_then(norito::json::Value::as_str)
        .expect("connect status should include policy.relay_effective_strategy")
        .to_owned();
    let relay_p2p_attached = connect_status_policy(payload)
        .get("relay_p2p_attached")
        .and_then(norito::json::Value::as_bool)
        .expect("connect status should include policy.relay_p2p_attached");
    let p2p_rebroadcasts_total = payload
        .get("p2p_rebroadcasts_total")
        .and_then(norito::json::Value::as_u64)
        .expect("connect status should include p2p_rebroadcasts_total");
    let p2p_rebroadcast_skipped_total = payload
        .get("p2p_rebroadcast_skipped_total")
        .and_then(norito::json::Value::as_u64)
        .expect("connect status should include p2p_rebroadcast_skipped_total");
    AttachedConnectRelayStatus {
        relay_strategy,
        relay_effective_strategy,
        relay_p2p_attached,
        p2p_rebroadcasts_total,
        p2p_rebroadcast_skipped_total,
    }
}
async fn await_connect_p2p_attachment(
    app: &axum::Router,
    cfg: &iroha_config::parameters::actual::Root,
) -> norito::json::Value {
    for _ in 0..50 {
        let payload = connect_aggregate_status_json(app, cfg).await;
        if connect_status_policy(&payload)
            .get("relay_p2p_attached")
            .and_then(norito::json::Value::as_bool)
            .expect("connect status should include policy.relay_p2p_attached")
        {
            return payload;
        }
        tokio::time::sleep(core::time::Duration::from_millis(20)).await;
    }
    panic!("p2p should attach to connect bus")
}
fn connect_session_request_body(seed: u8) -> (String, String) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    let network_id = iroha_torii::test_utils::signed_query_network_id();
    let app_pk = [seed; 32];
    let nonce = [seed.wrapping_add(1); 16];
    let sid = iroha_torii_shared::connect_sdk::derive_session_id(&network_id, &app_pk, &nonce);
    let sid_b64 = B64.encode(sid);
    let body = norito::json::to_json(&iroha_torii::json_object(vec![
        ("sid", Some(sid_b64.clone())),
        ("network_id", Some(network_id.to_string())),
        ("app_pk", Some(B64.encode(app_pk))),
        ("nonce", Some(B64.encode(nonce))),
        ("node", Option::<String>::None),
    ]))
    .expect("Connect session JSON serialization");
    (sid_b64, body)
}
async fn create_connect_session_payload(
    app: &axum::Router,
    seed: u8,
) -> (String, norito::json::Value) {
    let (sid_fixed, request_body) = connect_session_request_body(seed);
    let response = app
        .clone()
        .oneshot(request_with_loopback_connect_info(
            Request::builder()
                .method("POST")
                .uri(Uri::from_static("/v1/connect/session"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(request_body))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    (sid_fixed, norito::json::from_slice(&bytes).unwrap())
}
#[cfg(feature = "ws_integration_tests")]
#[must_use = "Connect test servers must be shut down and joined"]
struct ConnectTestServer {
    runtime: iroha_torii::TestApiRouterRuntime,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}
#[cfg(feature = "ws_integration_tests")]
impl ConnectTestServer {
    async fn shutdown(self) {
        let ConnectTestServer {
            runtime,
            shutdown,
            task,
        } = self;
        let shutdown_sent = shutdown.send(()).is_ok();
        let server_result = task.await;
        runtime.shutdown().await;
        assert!(
            shutdown_sent,
            "Connect test server exited before graceful shutdown"
        );
        match server_result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("Connect test server failed: {error}"),
            Err(error) => panic!("Connect test server could not be joined: {error}"),
        }
    }
}
#[cfg(feature = "ws_integration_tests")]
fn spawn_test_server(
    listener: tokio::net::TcpListener,
    runtime: iroha_torii::TestApiRouterRuntime,
) -> ConnectTestServer {
    let app = runtime.router();
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .await
    });
    ConnectTestServer {
        runtime,
        shutdown,
        task,
    }
}
#[cfg(feature = "ws_integration_tests")]
async fn bind_connect_test_listener(
    test_name: &str,
) -> Option<(tokio::net::TcpListener, std::net::SocketAddr)> {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping {test_name}: {error}");
            return None;
        }
        Err(error) => panic!("failed to bind test listener: {error}"),
    };
    let address = listener.local_addr().unwrap();
    Some((listener, address))
}
#[cfg(feature = "ws_integration_tests")]
struct ConnectAppSession {
    sid: String,
    token_app: String,
    sid_bytes: [u8; 32],
}
#[cfg(feature = "ws_integration_tests")]
async fn create_connect_app_session(app: &axum::Router, seed: u8) -> ConnectAppSession {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    let (sid_fixed, payload) = create_connect_session_payload(app, seed).await;
    let sid = payload
        .get("sid")
        .and_then(norito::json::Value::as_str)
        .expect("sid")
        .to_owned();
    assert_eq!(sid, sid_fixed);
    let token_app = payload
        .get("token_app")
        .and_then(norito::json::Value::as_str)
        .expect("token_app")
        .to_owned();
    let mut sid_bytes = [0_u8; 32];
    let sid_vec = B64.decode(&sid).expect("decode sid");
    sid_bytes.copy_from_slice(&sid_vec);
    ConnectAppSession {
        sid,
        token_app,
        sid_bytes,
    }
}
#[cfg(feature = "ws_integration_tests")]
async fn open_connect_app_websocket(
    address: std::net::SocketAddr,
    session: &ConnectAppSession,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
    let url = format!("ws://{address}/v1/connect/ws?sid={}&role=app", session.sid);
    let mut request = url.into_client_request().expect("app ws request");
    request.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::AUTHORIZATION,
        format!("Bearer {}", session.token_app)
            .parse()
            .expect("app authorization header"),
    );
    let (websocket, response) = tokio_tungstenite::connect_async(request)
        .await
        .expect("app ws handshake ok");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    websocket
}
#[cfg(feature = "ws_integration_tests")]
fn connect_status_counters_or_defaults(
    payload: &norito::json::Value,
    relay_p2p_attached_default: bool,
) -> ConnectStatusCounters {
    ConnectStatusCounters {
        p2p_rebroadcasts_total: payload
            .get("p2p_rebroadcasts_total")
            .and_then(norito::json::Value::as_u64)
            .unwrap_or(0),
        p2p_rebroadcast_skipped_total: payload
            .get("p2p_rebroadcast_skipped_total")
            .and_then(norito::json::Value::as_u64)
            .unwrap_or(0),
        relay_effective_strategy: connect_status_policy(payload)
            .get("relay_effective_strategy")
            .and_then(norito::json::Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        relay_p2p_attached: connect_status_policy(payload)
            .get("relay_p2p_attached")
            .and_then(norito::json::Value::as_bool)
            .unwrap_or(relay_p2p_attached_default),
    }
}
#[cfg(feature = "ws_integration_tests")]
async fn wait_for_connect_relay_p2p_attachment(
    app: &axum::Router,
    cfg: &iroha_config::parameters::actual::Root,
) -> bool {
    for _ in 0..50 {
        let payload = connect_aggregate_status_payload(app, cfg).await;
        if connect_status_policy(&payload)
            .get("relay_p2p_attached")
            .and_then(norito::json::Value::as_bool)
            .unwrap_or(false)
        {
            return true;
        }
        tokio::time::sleep(core::time::Duration::from_millis(20)).await;
    }
    false
}
fn checked_connect_key_fixture() -> iroha_crypto::KeyPair {
    iroha_crypto::KeyPair::try_random().expect("generate checked connect fixture keypair")
}
fn checked_connect_transport_key_fixture() -> iroha_crypto::KeyPair {
    iroha_crypto::KeyPair::try_from_seed(
        b"iroha:torii:connect-gating:soranet-transport:v1".to_vec(),
        iroha_crypto::Algorithm::Ed25519,
    )
    .expect("generate dedicated connect SoraNet transport fixture keypair")
}
#[test]
fn connect_config_fixture_uses_checked_key_generation() {
    let key_pair = checked_connect_key_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("fixture connect public key has a valid algorithm");
    assert_eq!(algorithm, iroha_crypto::Algorithm::Ed25519);
    let transport_key_pair = checked_connect_transport_key_fixture();
    assert_eq!(
        transport_key_pair.algorithm(),
        iroha_crypto::Algorithm::Ed25519
    );
    assert_ne!(transport_key_pair.public_key(), key_pair.public_key());
}
fn minimal_actual_config(connect_enabled: bool) -> iroha_config::parameters::actual::Root {
    use iroha_config::parameters::defaults;
    use iroha_crypto::streaming::StreamingKeyMaterial;
    use iroha_data_model::peer::Peer;

    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();

    // Preserve every deliberate Connect-fixture departure from the shared minimal root.
    cfg.common.key_pair = checked_connect_key_fixture();
    cfg.common.soranet_transport_key_pair = checked_connect_transport_key_fixture();
    cfg.common.peer = Peer::new(
        socket_addr!(127.0.0.1:0),
        checked_connect_key_fixture().public_key().clone(),
    );
    cfg.common.trusted_peers = WithOrigin::inline(A::TrustedPeers {
        myself: Peer::new(
            socket_addr!(127.0.0.1:0),
            checked_connect_key_fixture().public_key().clone(),
        ),
        others: iroha_primitives::unique_vec::UniqueVec::new(),
        pops: std::collections::BTreeMap::new(),
    });
    cfg.network.lane_profile = A::LaneProfile::Core;
    cfg.genesis.public_key = checked_connect_key_fixture().public_key().clone();
    cfg.genesis.expected_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"Connect gating test genesis trust anchor",
    ));
    cfg.torii.connect = A::Connect {
        enabled: connect_enabled,
        ws_max_sessions: defaults::connect::WS_MAX_SESSIONS,
        ws_per_ip_max_sessions: defaults::connect::WS_PER_IP_MAX_SESSIONS,
        ws_rate_per_ip_per_min: defaults::connect::WS_RATE_PER_IP_PER_MIN,
        session_ttl: defaults::connect::SESSION_TTL,
        frame_max_bytes: defaults::connect::FRAME_MAX_BYTES,
        session_buffer_max_bytes: defaults::connect::SESSION_BUFFER_MAX_BYTES,
        ping_interval: defaults::connect::PING_INTERVAL,
        ping_miss_tolerance: defaults::connect::PING_MISS_TOLERANCE,
        ping_min_interval: defaults::connect::PING_MIN_INTERVAL,
        dedupe_ttl: defaults::connect::DEDUPE_TTL,
        dedupe_cap: defaults::connect::DEDUPE_CAP,
        relay_enabled: defaults::connect::RELAY_ENABLED,
        relay_strategy: A::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: defaults::connect::P2P_TTL_HOPS,
    };
    cfg.torii.sorafs_gateway = A::SorafsGateway::default();
    cfg.torii.webhook = A::Webhook::default();
    cfg.torii.zk_prover_reports_ttl_secs = defaults::torii::ZK_PROVER_REPORTS_TTL_SECS;
    cfg.kura.fsync_mode = iroha_config::kura::FsyncMode::Batched;
    cfg.tiered_state.enabled = false;
    cfg.tiered_state.hot_retained_keys = 0;
    cfg.tiered_state.max_snapshots = 0;
    cfg.settlement = A::Settlement::default();
    cfg.fraud_monitoring = A::FraudMonitoring {
        policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
            enabled: false,
            missing_assessment_permitted: false,
            required_minimum_band: None,
            attesters: Vec::new(),
            ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
        },
        service_endpoints: Vec::new(),
        connect_timeout: defaults::fraud_monitoring::CONNECT_TIMEOUT,
        request_timeout: defaults::fraud_monitoring::REQUEST_TIMEOUT,
    };
    cfg.gov.conviction_step_blocks = 1;
    cfg.gov.max_conviction = 1;
    cfg.gov.min_enactment_delay = 1;
    cfg.gov.window_span = 1;
    cfg.gov.approval_threshold_q_den = 1;
    cfg.accel.merkle_min_leaves_gpu = defaults::accel::MERKLE_MIN_LEAVES_GPU;
    cfg.concurrency.scheduler_min_threads = defaults::concurrency::SCHEDULER_MIN;
    cfg.concurrency.scheduler_max_threads = defaults::concurrency::SCHEDULER_MAX;
    cfg.concurrency.rayon_global_threads = defaults::concurrency::RAYON_GLOBAL;
    cfg.zk.fastpq.proof_sidecar_queue_cap = defaults::zk::fastpq::PROOF_SIDECAR_QUEUE_CAP;
    cfg.zk.fastpq.proof_sidecar_max_bytes = defaults::zk::fastpq::PROOF_SIDECAR_MAX_BYTES;
    cfg.zk.fastpq.proof_sidecar_max_retries = defaults::zk::fastpq::PROOF_SIDECAR_MAX_RETRIES;
    cfg.zk.fastpq.metal_max_in_flight = None;
    cfg.zk.fastpq.metal_threadgroup_width = None;
    cfg.zk.fastpq.metal_trace = defaults::zk::fastpq::METAL_TRACE;
    cfg.zk.fastpq.metal_debug_enum = defaults::zk::fastpq::METAL_DEBUG_ENUM;
    cfg.streaming.key_material =
        StreamingKeyMaterial::new(checked_connect_key_fixture()).expect("streaming key material");
    cfg.streaming.codec = A::StreamingCodec::from_defaults();
    cfg
}
fn build_torii(cfg: &iroha_config::parameters::actual::Root) -> iroha_torii::Torii {
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = Arc::new(State::new_for_testing(
        World::default(),
        kura.clone(),
        query,
    ));
    let (_mh, time_source) =
        iroha_primitives::time::TimeSource::new_mock(core::time::Duration::default());
    let queue_cfg = iroha_config::parameters::actual::Queue {
        capacity: nonzero!(1usize),
        capacity_per_user: nonzero!(1usize),
        transaction_time_to_live: core::time::Duration::from_secs(1),
        ..Default::default()
    };
    let events_sender: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(Queue::from_config(queue_cfg, events_sender));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = (peers_tx, time_source);
    let telemetry = iroha_torii::MaybeTelemetry::disabled();
    iroha_torii::Torii::new_with_handle(
        cfg.common.chain.clone(),
        iroha_torii::test_utils::signed_query_network_id(),
        kiso,
        cfg.torii.clone(),
        queue,
        tokio::sync::broadcast::channel(1).0,
        LiveQueryStore::start_test(),
        Kura::blank_kura_for_testing(),
        state,
        cfg.common.key_pair.clone(),
        iroha_torii::OnlinePeersProvider::new(peers_rx),
        None,
        iroha_torii::ToriiRuntimeDeps::new(
            build_identity_test_fixture::build_identity(),
            telemetry,
        ),
    )
    .expect("valid Torii Connect fixture")
}
#[tokio::test]
async fn connect_endpoints_report_typed_unavailability_when_disabled() {
    let cfg = minimal_actual_config(false);
    let torii = build_torii(&cfg);
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    // The WebSocket route remains mounted but rejects the upgrade while disabled.
    let resp = app
        .clone()
        .oneshot(request_with_loopback_connect_info(
            Request::builder()
                .uri(Uri::from_static("/v1/connect/ws?sid=AA&role=app"))
                .body(axum::body::Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    // Disabled admission runs before media parsing and body extraction. A
    // request body that would panic if polled must therefore remain untouched.
    let body = axum::body::Body::from_stream(futures::stream::poll_fn(
        |_cx| -> core::task::Poll<Option<Result<axum::body::Bytes, std::io::Error>>> {
            panic!("disabled Connect session body must not be polled")
        },
    ));
    let resp = app
        .clone()
        .oneshot(request_with_loopback_connect_info(
            Request::builder()
                .method("POST")
                .uri(Uri::from_static("/v1/connect/session"))
                .header(
                    axum::http::header::CONTENT_TYPE,
                    "invalid/media; value==bad",
                )
                .body(body)
                .unwrap(),
        ))
        .await
        .expect("disabled Connect pre-body response");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    // Ordinary REST routes return the shared typed error envelope.
    let resp = connect_aggregate_status(&app, &cfg).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .expect("connect disabled response body")
        .to_bytes();
    let error: norito::json::Value =
        norito::json::from_slice(&body).expect("typed Connect disabled error envelope");
    assert_eq!(
        error.get("code").and_then(norito::json::Value::as_str),
        Some("connect_disabled")
    );
    app.shutdown().await;
}
#[tokio::test]
async fn connect_status_present_when_enabled() {
    let cfg = minimal_actual_config(true);
    let torii = build_torii(&cfg);
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let unsigned = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(Uri::from_static("/v1/connect/status/aggregate"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);
    let ConnectStatusCounters {
        p2p_rebroadcasts_total,
        p2p_rebroadcast_skipped_total,
        relay_effective_strategy,
        relay_p2p_attached,
    } = connect_status_counters(&connect_aggregate_status_json(&app, &cfg).await);
    assert_eq!(
        p2p_rebroadcasts_total, 0,
        "fresh status snapshot should start with zero rebroadcasts"
    );
    assert_eq!(p2p_rebroadcast_skipped_total, 0);
    assert_eq!(relay_effective_strategy, "local_only");
    assert!(!relay_p2p_attached);
    app.shutdown().await;
}
#[tokio::test]
async fn connect_status_reports_exact_local_only_strategy() {
    let mut cfg = minimal_actual_config(true);
    cfg.torii.connect.relay_strategy = A::ConnectRelayStrategy::LocalOnly;
    let torii = build_torii(&cfg);
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let payload = connect_aggregate_status_json(&app, &cfg).await;
    assert_eq!(relay_strategy(&payload), "local_only");
    let ConnectStatusCounters {
        p2p_rebroadcasts_total,
        p2p_rebroadcast_skipped_total,
        relay_effective_strategy,
        relay_p2p_attached,
    } = connect_status_counters(&payload);
    assert_eq!(p2p_rebroadcasts_total, 0);
    assert_eq!(p2p_rebroadcast_skipped_total, 0);
    assert_eq!(relay_effective_strategy, "local_only");
    assert!(!relay_p2p_attached);
    app.shutdown().await;
}
#[tokio::test]
async fn connect_status_reports_broadcast_effective_when_p2p_attached() {
    let mut cfg = minimal_actual_config(true);
    cfg.torii.connect.relay_strategy = A::ConnectRelayStrategy::Broadcast;
    let torii = build_torii(&cfg).with_p2p(iroha_core::IrohaNetwork::closed_for_tests());
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let AttachedConnectRelayStatus {
        relay_strategy,
        relay_effective_strategy,
        relay_p2p_attached,
        p2p_rebroadcasts_total,
        p2p_rebroadcast_skipped_total,
    } = attached_connect_relay_status(&await_connect_p2p_attachment(&app, &cfg).await);
    assert_eq!(relay_strategy, "broadcast");
    assert_eq!(relay_effective_strategy, "broadcast");
    assert!(relay_p2p_attached);
    assert_eq!(p2p_rebroadcasts_total, 0);
    assert_eq!(p2p_rebroadcast_skipped_total, 0);
    app.shutdown().await;
}
#[tokio::test]
async fn connect_status_reports_local_only_when_relay_disabled_with_p2p_attached() {
    let mut cfg = minimal_actual_config(true);
    cfg.torii.connect.relay_enabled = false;
    cfg.torii.connect.relay_strategy = A::ConnectRelayStrategy::Broadcast;
    let torii = build_torii(&cfg).with_p2p(iroha_core::IrohaNetwork::closed_for_tests());
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let AttachedConnectRelayStatus {
        relay_strategy,
        relay_effective_strategy,
        relay_p2p_attached,
        p2p_rebroadcasts_total,
        p2p_rebroadcast_skipped_total,
    } = attached_connect_relay_status(&await_connect_p2p_attachment(&app, &cfg).await);
    assert_eq!(relay_strategy, "broadcast");
    assert_eq!(relay_effective_strategy, "local_only");
    assert!(relay_p2p_attached);
    assert_eq!(p2p_rebroadcasts_total, 0);
    assert_eq!(p2p_rebroadcast_skipped_total, 0);
    app.shutdown().await;
}
#[tokio::test]
async fn connect_session_delete_endpoint_removes_tokens() {
    let cfg = minimal_actual_config(true);
    let torii = build_torii(&cfg);
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let (_, payload) = create_connect_session_payload(&app, 0x24).await;
    let sid = payload
        .get("sid")
        .and_then(|x| x.as_str())
        .expect("sid present")
        .to_owned();
    let token_management = payload
        .get("token_management")
        .and_then(|x| x.as_str())
        .expect("token_management present")
        .to_owned();
    let delete_uri = format!("/v1/connect/session/{sid}");
    let missing_token_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(delete_uri.as_str())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_token_resp.status(), StatusCode::UNAUTHORIZED);
    let delete_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(delete_uri.as_str())
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {token_management}"),
                )
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);
    let delete_again = app
        .router()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(delete_uri.as_str())
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {token_management}"),
                )
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_again.status(), StatusCode::NOT_FOUND);
    app.shutdown().await;
}
#[tokio::test]
async fn connect_session_status_requires_management_token() {
    let cfg = minimal_actual_config(true);
    let torii = build_torii(&cfg);
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let (_, created) = create_connect_session_payload(&app, 0x34).await;
    let sid = created
        .get("sid")
        .and_then(|x| x.as_str())
        .expect("sid present");
    let token_management = created
        .get("token_management")
        .and_then(|x| x.as_str())
        .expect("token_management present");
    let status_uri = format!("/v1/connect/status?sid={sid}");
    let missing_sid_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(Uri::from_static("/v1/connect/status"))
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {token_management}"),
                )
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_sid_resp.status(), StatusCode::BAD_REQUEST);
    let missing_token_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(status_uri.as_str())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_token_resp.status(), StatusCode::UNAUTHORIZED);
    let status_resp = app
        .router()
        .oneshot(
            Request::builder()
                .uri(status_uri.as_str())
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {token_management}"),
                )
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status_resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(status_resp.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    let payload: norito::json::Value =
        norito::json::from_slice(&body).expect("session status should be JSON");
    assert_eq!(payload.get("sid").and_then(|x| x.as_str()), Some(sid));
    assert_eq!(
        payload.get("app_attached").and_then(|x| x.as_bool()),
        Some(false)
    );
    app.shutdown().await;
}
#[cfg(feature = "ws_integration_tests")]
#[tokio::test]
async fn connect_session_delete_rejects_ws_attach() {
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let cfg = minimal_actual_config(true);
    let torii = build_torii(&cfg);
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping connect_session_delete_rejects_ws_attach: {err}");
            app.shutdown().await;
            return;
        }
        Err(err) => panic!("failed to bind test listener: {err}"),
    };
    let addr = listener.local_addr().unwrap();
    let app2 = app.router();
    let server = spawn_test_server(listener, app);
    // Use a second router handle for in-process REST calls.
    let (sid_fixed, req_body) = connect_session_request_body(0x44);
    let create_resp = app2
        .clone()
        .oneshot(request_with_loopback_connect_info(
            Request::builder()
                .method("POST")
                .uri(Uri::from_static("/v1/connect/session"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(req_body))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::OK);
    let bytes = http_body_util::BodyExt::collect(create_resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let payload: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    let sid = payload
        .get("sid")
        .and_then(|x| x.as_str())
        .expect("sid present");
    assert_eq!(sid, sid_fixed);
    let token_app = payload
        .get("token_app")
        .and_then(|x| x.as_str())
        .expect("token_app");
    let token_management = payload
        .get("token_management")
        .and_then(|x| x.as_str())
        .expect("token_management");
    // Delete the session through REST and ensure it reports success.
    let delete_uri = format!("/v1/connect/session/{sid}");
    let delete_resp = app2
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(delete_uri.clone())
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {token_management}"),
                )
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);
    // Attempt to attach over WS using the stale token; expect 401.
    let url = format!("ws://{addr}/v1/connect/ws?sid={sid}&role=app");
    let mut request = url.into_client_request().expect("ws request");
    request.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::AUTHORIZATION,
        format!("Bearer {token_app}")
            .parse()
            .expect("authorization header"),
    );
    match tokio_tungstenite::connect_async(request).await {
        Ok(_) => panic!("ws handshake should fail after session deletion"),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        Err(err) => panic!("unexpected ws failure: {err:?}"),
    }
    server.shutdown().await;
}
#[cfg(feature = "ws_integration_tests")]
#[tokio::test]
async fn connect_ws_handshake_succeeds_when_enabled() {
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    // Build enabled config and Torii router
    let cfg = minimal_actual_config(true);
    let torii = build_torii(&cfg);
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    // Serve on an ephemeral port
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping connect_ws_handshake_succeeds_when_enabled: {err}");
            app.shutdown().await;
            return;
        }
        Err(err) => panic!("failed to bind test listener: {err}"),
    };
    let addr = listener.local_addr().unwrap();
    let app2 = app.router();
    let server = spawn_test_server(listener, app);
    // Create a session via in-process router call to obtain tokens and sid
    let (sid_fixed, req_body) = connect_session_request_body(0x52);
    let res = app2
        .clone()
        .oneshot(request_with_loopback_connect_info(
            Request::builder()
                .method("POST")
                .uri(Uri::from_static("/v1/connect/session"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(req_body))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = http_body_util::BodyExt::collect(res.into_body())
        .await
        .unwrap()
        .to_bytes();
    let v: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    let sid = v.get("sid").and_then(|x| x.as_str()).expect("sid");
    assert_eq!(sid, sid_fixed);
    let token_app = v
        .get("token_app")
        .and_then(|x| x.as_str())
        .expect("token_app");
    // Attempt WS connect using the provided sid/token
    let url = format!("ws://{addr}/v1/connect/ws?sid={sid}&role=app");
    let mut request = url.into_client_request().expect("ws request");
    request.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::AUTHORIZATION,
        format!("Bearer {token_app}")
            .parse()
            .expect("authorization header"),
    );
    let (_ws, resp) = tokio_tungstenite::connect_async(request)
        .await
        .expect("ws handshake ok");
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    drop(_ws);
    server.shutdown().await;
}
#[cfg(feature = "ws_integration_tests")]
#[tokio::test]
async fn connect_ws_accepts_protocol_token() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::header};
    let cfg = minimal_actual_config(true);
    let torii = build_torii(&cfg);
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping connect_ws_accepts_protocol_token: {err}");
            app.shutdown().await;
            return;
        }
        Err(err) => panic!("failed to bind test listener: {err}"),
    };
    let addr = listener.local_addr().unwrap();
    let app2 = app.router();
    let server = spawn_test_server(listener, app);
    let (sid_fixed, req_body) = connect_session_request_body(0x62);
    let res = app2
        .clone()
        .oneshot(request_with_loopback_connect_info(
            Request::builder()
                .method("POST")
                .uri(Uri::from_static("/v1/connect/session"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(req_body))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = http_body_util::BodyExt::collect(res.into_body())
        .await
        .unwrap()
        .to_bytes();
    let v: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    let sid = v.get("sid").and_then(|x| x.as_str()).expect("sid");
    assert_eq!(sid, sid_fixed);
    let token_app = v
        .get("token_app")
        .and_then(|x| x.as_str())
        .expect("token_app");
    let url = format!("ws://{addr}/v1/connect/ws?sid={sid}&role=app");
    let mut request = url.into_client_request().expect("ws request");
    let encoded = B64.encode(token_app.as_bytes());
    request.headers_mut().insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        format!("iroha-connect.token.v1.{encoded}")
            .parse()
            .expect("protocol header"),
    );
    let (_ws, resp) = tokio_tungstenite::connect_async(request)
        .await
        .expect("ws handshake ok");
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    drop(_ws);
    server.shutdown().await;
}
#[cfg(feature = "ws_integration_tests")]
#[tokio::test]
async fn connect_ws_closes_on_role_direction_mismatch() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use futures::{SinkExt, StreamExt};
    use iroha_torii_shared::connect as proto;
    use tokio::net::TcpListener;
    use tokio::time::{Duration, sleep, timeout};
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
    let cfg = minimal_actual_config(true);
    let torii = build_torii(&cfg);
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping connect_ws_closes_on_role_direction_mismatch: {err}");
            app.shutdown().await;
            return;
        }
        Err(err) => panic!("failed to bind test listener: {err}"),
    };
    let addr = listener.local_addr().unwrap();
    let app2 = app.router();
    let server = spawn_test_server(listener, app);
    let (sid_fixed, req_body) = connect_session_request_body(0x92);
    let res = app2
        .clone()
        .oneshot(request_with_loopback_connect_info(
            Request::builder()
                .method("POST")
                .uri(Uri::from_static("/v1/connect/session"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(req_body))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = http_body_util::BodyExt::collect(res.into_body())
        .await
        .unwrap()
        .to_bytes();
    let v: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    let sid = v.get("sid").and_then(|x| x.as_str()).expect("sid");
    assert_eq!(sid, sid_fixed);
    let token_app = v
        .get("token_app")
        .and_then(|x| x.as_str())
        .expect("token_app");
    let mut sid_bytes = [0u8; 32];
    let sid_vec = B64.decode(sid).expect("decode sid");
    sid_bytes.copy_from_slice(&sid_vec);
    // Attach as app, then send a mismatched direction (WalletToApp).
    let url = format!("ws://{addr}/v1/connect/ws?sid={sid}&role=app");
    let mut request = url.into_client_request().expect("ws request");
    request.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::AUTHORIZATION,
        format!("Bearer {token_app}")
            .parse()
            .expect("authorization header"),
    );
    let (mut ws, resp) = tokio_tungstenite::connect_async(request)
        .await
        .expect("ws handshake ok");
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    let mismatch = proto::ConnectFrameV1 {
        sid: sid_bytes,
        dir: proto::Dir::WalletToApp,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 1 }),
    };
    let payload = proto::encode_connect_frame_bare(&mismatch).expect("encode frame");
    ws.send(Message::Binary(payload.into()))
        .await
        .expect("send mismatch frame");
    let mut saw_connect_close = false;
    let mut saw_ws_close = false;
    for _ in 0..5 {
        let maybe_msg = timeout(Duration::from_millis(400), ws.next()).await;
        let Some(msg) = maybe_msg.unwrap_or(None) else {
            continue;
        };
        match msg {
            Ok(Message::Binary(bytes)) => {
                if let Ok(frame) = proto::decode_connect_frame_bare(&bytes) {
                    if let proto::FrameKind::Control(proto::ConnectControlV1::Close {
                        reason,
                        ..
                    }) = frame.kind
                    {
                        if reason == "connect_role_direction_mismatch" {
                            saw_connect_close = true;
                            break;
                        }
                    }
                }
            }
            Ok(Message::Close(_)) => {
                saw_ws_close = true;
                break;
            }
            Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed) => {
                saw_ws_close = true;
                break;
            }
            _ => {}
        }
    }
    assert!(
        saw_connect_close || saw_ws_close,
        "expected websocket termination after role/direction mismatch"
    );
    // Poll status until mismatch closure is reflected.
    let mut mismatch_total = 0u64;
    let mut sessions_total = u64::MAX;
    for _ in 0..20 {
        let status = connect_aggregate_status(&app2, &cfg).await;
        assert_eq!(status.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(status.into_body())
            .await
            .unwrap()
            .to_bytes();
        let status_json: norito::json::Value = norito::json::from_slice(&body).unwrap();
        mismatch_total = status_json
            .get("role_direction_mismatch_total")
            .and_then(norito::json::Value::as_u64)
            .unwrap_or(0);
        sessions_total = status_json
            .get("sessions_total")
            .and_then(norito::json::Value::as_u64)
            .unwrap_or(u64::MAX);
        if mismatch_total >= 1 && sessions_total == 0 {
            break;
        }
        sleep(Duration::from_millis(25)).await;
    }
    assert!(mismatch_total >= 1, "mismatch counter should increment");
    assert_eq!(sessions_total, 0, "session should be terminated");
    drop(ws);
    server.shutdown().await;
}
#[cfg(feature = "ws_integration_tests")]
#[tokio::test]
async fn connect_ws_duplicate_frame_does_not_close_session() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use futures::{SinkExt, StreamExt};
    use iroha_torii_shared::connect as proto;
    use tokio::net::TcpListener;
    use tokio::time::{Duration, timeout};
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
    let cfg = minimal_actual_config(true);
    let torii = build_torii(&cfg);
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping connect_ws_duplicate_frame_does_not_close_session: {err}");
            app.shutdown().await;
            return;
        }
        Err(err) => panic!("failed to bind test listener: {err}"),
    };
    let addr = listener.local_addr().unwrap();
    let app2 = app.router();
    let server = spawn_test_server(listener, app);
    let (sid_fixed, req_body) = connect_session_request_body(0xA3);
    let res = app2
        .clone()
        .oneshot(request_with_loopback_connect_info(
            Request::builder()
                .method("POST")
                .uri(Uri::from_static("/v1/connect/session"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(req_body))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = http_body_util::BodyExt::collect(res.into_body())
        .await
        .unwrap()
        .to_bytes();
    let v: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    let sid = v.get("sid").and_then(|x| x.as_str()).expect("sid");
    assert_eq!(sid, sid_fixed);
    let token_app = v
        .get("token_app")
        .and_then(|x| x.as_str())
        .expect("token_app");
    let token_wallet = v
        .get("token_wallet")
        .and_then(|x| x.as_str())
        .expect("token_wallet");
    let mut sid_bytes = [0u8; 32];
    let sid_vec = B64.decode(sid).expect("decode sid");
    sid_bytes.copy_from_slice(&sid_vec);
    // Connect app role.
    let app_url = format!("ws://{addr}/v1/connect/ws?sid={sid}&role=app");
    let mut app_req = app_url.into_client_request().expect("app ws request");
    app_req.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::AUTHORIZATION,
        format!("Bearer {token_app}")
            .parse()
            .expect("app authorization header"),
    );
    let (mut app_ws, app_resp) = tokio_tungstenite::connect_async(app_req)
        .await
        .expect("app ws handshake ok");
    assert_eq!(app_resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    // Connect wallet role.
    let wallet_url = format!("ws://{addr}/v1/connect/ws?sid={sid}&role=wallet");
    let mut wallet_req = wallet_url.into_client_request().expect("wallet ws request");
    wallet_req.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::AUTHORIZATION,
        format!("Bearer {token_wallet}")
            .parse()
            .expect("wallet authorization header"),
    );
    let (mut wallet_ws, wallet_resp) = tokio_tungstenite::connect_async(wallet_req)
        .await
        .expect("wallet ws handshake ok");
    assert_eq!(wallet_resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    let seq1 = proto::ConnectFrameV1 {
        sid: sid_bytes,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 41 }),
    };
    app_ws
        .send(Message::Binary(
            proto::encode_connect_frame_bare(&seq1)
                .expect("encode seq1")
                .into(),
        ))
        .await
        .expect("send seq1");
    // Wallet should receive first frame.
    let first = timeout(Duration::from_millis(500), wallet_ws.next())
        .await
        .expect("wallet recv timeout")
        .expect("wallet recv closed")
        .expect("wallet recv error");
    let first_frame = match first {
        Message::Binary(bytes) => proto::decode_connect_frame_bare(&bytes).expect("decode first"),
        other => panic!("expected binary frame, got {other:?}"),
    };
    assert_eq!(first_frame.seq, 1);
    // Send duplicate seq=1; dedupe should drop it and keep session alive.
    app_ws
        .send(Message::Binary(
            proto::encode_connect_frame_bare(&seq1)
                .expect("encode duplicate")
                .into(),
        ))
        .await
        .expect("send duplicate seq1");
    assert!(
        timeout(Duration::from_millis(200), wallet_ws.next())
            .await
            .is_err(),
        "duplicate frame should not be delivered to wallet"
    );
    assert!(
        timeout(Duration::from_millis(200), app_ws.next())
            .await
            .is_err(),
        "duplicate frame should not close app websocket"
    );
    let seq2 = proto::ConnectFrameV1 {
        sid: sid_bytes,
        dir: proto::Dir::AppToWallet,
        seq: 2,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 42 }),
    };
    app_ws
        .send(Message::Binary(
            proto::encode_connect_frame_bare(&seq2)
                .expect("encode seq2")
                .into(),
        ))
        .await
        .expect("send seq2");
    let second = timeout(Duration::from_millis(500), wallet_ws.next())
        .await
        .expect("wallet recv seq2 timeout")
        .expect("wallet recv seq2 closed")
        .expect("wallet recv seq2 error");
    let second_frame = match second {
        Message::Binary(bytes) => proto::decode_connect_frame_bare(&bytes).expect("decode second"),
        other => panic!("expected binary frame, got {other:?}"),
    };
    assert_eq!(second_frame.seq, 2);
    let status = connect_aggregate_status(&app2, &cfg).await;
    assert_eq!(status.status(), StatusCode::OK);
    let status_body = http_body_util::BodyExt::collect(status.into_body())
        .await
        .unwrap()
        .to_bytes();
    let status_json: norito::json::Value = norito::json::from_slice(&status_body).unwrap();
    let dedupe_drops = status_json
        .get("dedupe_drops_total")
        .and_then(norito::json::Value::as_u64)
        .unwrap_or(0);
    let sequence_violation_closes = status_json
        .get("sequence_violation_closes_total")
        .and_then(norito::json::Value::as_u64)
        .unwrap_or(0);
    assert!(dedupe_drops >= 1, "expected duplicate drop to be counted");
    assert_eq!(
        sequence_violation_closes, 0,
        "duplicate frame must not trigger sequence-violation close"
    );
    drop(app_ws);
    drop(wallet_ws);
    server.shutdown().await;
}
#[cfg(feature = "ws_integration_tests")]
#[tokio::test]
async fn connect_ws_broadcast_relay_updates_p2p_rebroadcast_counter() {
    use futures::SinkExt;
    use iroha_torii_shared::connect as proto;
    use tokio::time::{Duration, sleep};
    use tokio_tungstenite::tungstenite::Message;
    let mut cfg = minimal_actual_config(true);
    cfg.torii.connect.relay_strategy = A::ConnectRelayStrategy::Broadcast;
    cfg.torii.connect.p2p_ttl_hops = 1;
    let torii = build_torii(&cfg).with_p2p(iroha_core::IrohaNetwork::closed_for_tests());
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let Some((listener, addr)) =
        bind_connect_test_listener("connect_ws_broadcast_relay_updates_p2p_rebroadcast_counter")
            .await
    else {
        app.shutdown().await;
        return;
    };
    let app2 = app.router();
    let server = spawn_test_server(listener, app);
    let session = create_connect_app_session(&app2, 0xB4).await;
    // Wait until async bus attachment reports active P2P relay wiring.
    let mut relay_p2p_attached = wait_for_connect_relay_p2p_attachment(&app2, &cfg).await;
    assert!(relay_p2p_attached, "connect relay should attach P2P bus");
    let mut app_ws = open_connect_app_websocket(addr, &session).await;
    let seq1 = proto::ConnectFrameV1 {
        sid: session.sid_bytes,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 7 }),
    };
    app_ws
        .send(Message::Binary(
            proto::encode_connect_frame_bare(&seq1)
                .expect("encode seq1")
                .into(),
        ))
        .await
        .expect("send seq1");
    let mut rebroadcasts = 0;
    let mut skipped = 0;
    let mut relay_effective_strategy = String::new();
    relay_p2p_attached = false;
    for _ in 0..50 {
        let status = connect_aggregate_status_payload(&app2, &cfg).await;
        let counters = connect_status_counters_or_defaults(&status, false);
        rebroadcasts = counters.p2p_rebroadcasts_total;
        skipped = counters.p2p_rebroadcast_skipped_total;
        relay_effective_strategy = counters.relay_effective_strategy;
        relay_p2p_attached = counters.relay_p2p_attached;
        if rebroadcasts >= 1 {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(rebroadcasts >= 1, "expected at least one p2p rebroadcast");
    assert_eq!(
        skipped, 0,
        "p2p attached relay should not count skipped sends"
    );
    assert_eq!(relay_effective_strategy, "broadcast");
    assert!(relay_p2p_attached);
    drop(app_ws);
    server.shutdown().await;
}
#[cfg(feature = "ws_integration_tests")]
#[tokio::test]
async fn connect_ws_broadcast_without_p2p_increments_skipped_rebroadcast_counter() {
    use futures::SinkExt;
    use iroha_torii_shared::connect as proto;
    use tokio::time::{Duration, sleep};
    use tokio_tungstenite::tungstenite::Message;
    let mut cfg = minimal_actual_config(true);
    cfg.torii.connect.relay_strategy = A::ConnectRelayStrategy::Broadcast;
    cfg.torii.connect.p2p_ttl_hops = 1;
    let torii = build_torii(&cfg);
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let Some((listener, addr)) = bind_connect_test_listener(
        "connect_ws_broadcast_without_p2p_increments_skipped_rebroadcast_counter",
    )
    .await
    else {
        app.shutdown().await;
        return;
    };
    let app2 = app.router();
    let server = spawn_test_server(listener, app);
    let session = create_connect_app_session(&app2, 0xC5).await;
    let mut app_ws = open_connect_app_websocket(addr, &session).await;
    let seq1 = proto::ConnectFrameV1 {
        sid: session.sid_bytes,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 8 }),
    };
    app_ws
        .send(Message::Binary(
            proto::encode_connect_frame_bare(&seq1)
                .expect("encode seq1")
                .into(),
        ))
        .await
        .expect("send seq1");
    let mut rebroadcasts = 0;
    let mut skipped = 0;
    let mut relay_effective_strategy = String::new();
    let mut relay_p2p_attached = true;
    for _ in 0..50 {
        let status = connect_aggregate_status_payload(&app2, &cfg).await;
        let counters = connect_status_counters_or_defaults(&status, true);
        rebroadcasts = counters.p2p_rebroadcasts_total;
        skipped = counters.p2p_rebroadcast_skipped_total;
        relay_effective_strategy = counters.relay_effective_strategy;
        relay_p2p_attached = counters.relay_p2p_attached;
        if skipped >= 1 {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(rebroadcasts, 0);
    assert!(
        skipped >= 1,
        "expected missing-p2p rebroadcast skips to be counted"
    );
    assert_eq!(relay_effective_strategy, "local_only");
    assert!(!relay_p2p_attached);
    drop(app_ws);
    server.shutdown().await;
}
#[cfg(feature = "ws_integration_tests")]
#[tokio::test]
async fn connect_ws_local_only_with_p2p_does_not_rebroadcast() {
    use futures::SinkExt;
    use iroha_torii_shared::connect as proto;
    use tokio::time::{Duration, sleep};
    use tokio_tungstenite::tungstenite::Message;
    let mut cfg = minimal_actual_config(true);
    cfg.torii.connect.relay_strategy = A::ConnectRelayStrategy::LocalOnly;
    let torii = build_torii(&cfg).with_p2p(iroha_core::IrohaNetwork::closed_for_tests());
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let Some((listener, addr)) =
        bind_connect_test_listener("connect_ws_local_only_with_p2p_does_not_rebroadcast").await
    else {
        app.shutdown().await;
        return;
    };
    let app2 = app.router();
    let server = spawn_test_server(listener, app);
    let session = create_connect_app_session(&app2, 0xD6).await;
    // Wait for async P2P bus attachment before sending frames.
    let mut relay_p2p_attached = wait_for_connect_relay_p2p_attachment(&app2, &cfg).await;
    assert!(relay_p2p_attached, "connect relay should attach P2P bus");
    let mut app_ws = open_connect_app_websocket(addr, &session).await;
    let seq1 = proto::ConnectFrameV1 {
        sid: session.sid_bytes,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 9 }),
    };
    app_ws
        .send(Message::Binary(
            proto::encode_connect_frame_bare(&seq1)
                .expect("encode seq1")
                .into(),
        ))
        .await
        .expect("send seq1");
    let mut rebroadcasts = 0;
    let mut skipped = 0;
    let mut relay_effective_strategy = String::new();
    relay_p2p_attached = false;
    for _ in 0..50 {
        let status = connect_aggregate_status_payload(&app2, &cfg).await;
        let counters = connect_status_counters_or_defaults(&status, false);
        rebroadcasts = counters.p2p_rebroadcasts_total;
        skipped = counters.p2p_rebroadcast_skipped_total;
        relay_effective_strategy = counters.relay_effective_strategy;
        relay_p2p_attached = counters.relay_p2p_attached;
        if rebroadcasts > 0 || skipped > 0 {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(rebroadcasts, 0);
    assert_eq!(skipped, 0);
    assert_eq!(relay_effective_strategy, "local_only");
    assert!(relay_p2p_attached);
    drop(app_ws);
    server.shutdown().await;
}
#[cfg(feature = "ws_integration_tests")]
#[tokio::test]
async fn connect_ws_relay_disabled_with_p2p_does_not_rebroadcast() {
    use futures::SinkExt;
    use iroha_torii_shared::connect as proto;
    use tokio::time::{Duration, sleep};
    use tokio_tungstenite::tungstenite::Message;
    let mut cfg = minimal_actual_config(true);
    cfg.torii.connect.relay_enabled = false;
    cfg.torii.connect.relay_strategy = A::ConnectRelayStrategy::Broadcast;
    let torii = build_torii(&cfg).with_p2p(iroha_core::IrohaNetwork::closed_for_tests());
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let Some((listener, addr)) =
        bind_connect_test_listener("connect_ws_relay_disabled_with_p2p_does_not_rebroadcast").await
    else {
        app.shutdown().await;
        return;
    };
    let app2 = app.router();
    let server = spawn_test_server(listener, app);
    let session = create_connect_app_session(&app2, 0xE7).await;
    // Wait for async P2P bus attachment before sending frames.
    let mut relay_p2p_attached = wait_for_connect_relay_p2p_attachment(&app2, &cfg).await;
    assert!(relay_p2p_attached, "connect relay should attach P2P bus");
    let mut app_ws = open_connect_app_websocket(addr, &session).await;
    let seq1 = proto::ConnectFrameV1 {
        sid: session.sid_bytes,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 10 }),
    };
    app_ws
        .send(Message::Binary(
            proto::encode_connect_frame_bare(&seq1)
                .expect("encode seq1")
                .into(),
        ))
        .await
        .expect("send seq1");
    let mut rebroadcasts = 0;
    let mut skipped = 0;
    let mut relay_effective_strategy = String::new();
    relay_p2p_attached = false;
    for _ in 0..50 {
        let status = connect_aggregate_status_payload(&app2, &cfg).await;
        let counters = connect_status_counters_or_defaults(&status, false);
        rebroadcasts = counters.p2p_rebroadcasts_total;
        skipped = counters.p2p_rebroadcast_skipped_total;
        relay_effective_strategy = counters.relay_effective_strategy;
        relay_p2p_attached = counters.relay_p2p_attached;
        if rebroadcasts > 0 || skipped > 0 {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(rebroadcasts, 0);
    assert_eq!(skipped, 0);
    assert_eq!(relay_effective_strategy, "local_only");
    assert!(relay_p2p_attached);
    drop(app_ws);
    server.shutdown().await;
}
#[cfg(feature = "ws_integration_tests")]
#[tokio::test]
async fn connect_ws_rejects_query_token() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use tokio::net::TcpListener;
    let cfg = minimal_actual_config(true);
    let torii = build_torii(&cfg);
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping connect_ws_rejects_query_token: {err}");
            app.shutdown().await;
            return;
        }
        Err(err) => panic!("failed to bind test listener: {err}"),
    };
    let addr = listener.local_addr().unwrap();
    let server = spawn_test_server(listener, app);
    let sid = B64.encode([0x72u8; 32]);
    let url = format!("ws://{addr}/v1/connect/ws?sid={sid}&role=app&token=deadbeef");
    let err = tokio_tungstenite::connect_async(&url)
        .await
        .expect_err("ws handshake should reject query token");
    let status = match err {
        tokio_tungstenite::tungstenite::Error::Http(resp) => resp.status(),
        other => panic!("unexpected error: {other:?}"),
    };
    assert_eq!(status, StatusCode::BAD_REQUEST);
    server.shutdown().await;
}
include!("connect_gating_disabled_ws_test.rs");

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
