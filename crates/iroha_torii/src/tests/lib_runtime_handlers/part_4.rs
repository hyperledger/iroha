#[cfg(feature = "connect")]
#[tokio::test]
async fn signed_query_proxy_does_not_resend_after_complete_rejection() {
    let first_peer_id =
        checked_torii_test_peer_id(0x95, "derive retryable first proxy peer fixture key");
    let second_peer_id =
        checked_torii_test_peer_id(0x96, "derive retryable second proxy peer fixture key");
    let route = RoutingDecision::new(LaneId::new(3), DataSpaceId::new(3));
    let request =
        signed_query_proxy_request_for_test(Hash::new(b"signed-query-complete-rejection"), route);
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attempts_ref = attempts.clone();
    let response = super::execute_torii_proxy_request_across_candidates(
        tokio::time::Instant::now(),
        vec![
            ToriiProxyCandidate::P2p(first_peer_id.clone()),
            ToriiProxyCandidate::P2p(second_peer_id.clone()),
        ],
        route,
        request,
        TORII_PROXY_REQUEST_MAX_ENCODED_BYTES_V1,
        move |candidate, _request| {
            let first_peer_id = first_peer_id.clone();
            let attempts = attempts_ref.clone();
            async move {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let peer_id = candidate.peer_id().clone();
                if peer_id == first_peer_id {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    return Ok(ToriiProxyHttpResponseV1 {
                        status_code: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                        headers: vec![iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                            name: "x-iroha-reject-code".to_owned(),
                            value: b"route_unavailable".to_vec(),
                        }],
                        body: b"retry".to_vec(),
                    });
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
                Ok(ToriiProxyHttpResponseV1 {
                    status_code: StatusCode::OK.as_u16(),
                    headers: Vec::new(),
                    body: b"retry-then-ok".to_vec(),
                })
            }
        },
        |_request_id| async move {},
    )
    .await;
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = torii_body_bytes(response, "response body should be readable").await;
    assert_eq!(body.as_ref(), b"retry");
}
#[cfg(feature = "connect")]
#[derive(Clone, Copy)]
enum RouteUnavailableProxyCase {
    NoCandidates,
    TransportErrors,
}
#[cfg(feature = "connect")]
async fn run_route_unavailable_proxy_case(case: RouteUnavailableProxyCase) {
    let (route, request_id, candidates, failure_message) = match case {
        RouteUnavailableProxyCase::NoCandidates => (
            RoutingDecision::new(LaneId::new(4), DataSpaceId::new(5)),
            Hash::new(b"torii-proxy-no-candidates"),
            Vec::new(),
            "execute should not be called without candidates",
        ),
        RouteUnavailableProxyCase::TransportErrors => (
            RoutingDecision::new(LaneId::new(8), DataSpaceId::new(9)),
            Hash::new(b"torii-proxy-all-transport-errors"),
            vec![ToriiProxyCandidate::P2p(checked_torii_test_peer_id(
                0x98,
                "derive transport error proxy peer fixture key",
            ))],
            "transport unavailable",
        ),
    };
    let request = signed_query_proxy_request_for_test(request_id.clone(), route);
    let completed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let completed_ref = completed.clone();
    let response = super::execute_torii_proxy_request_across_candidates(
        tokio::time::Instant::now(),
        candidates,
        route,
        request,
        TORII_PROXY_REQUEST_MAX_ENCODED_BYTES_V1,
        move |_candidate, _request| async move {
            Err::<ToriiProxyHttpResponseV1, ToriiProxyAttemptError>(
                ToriiProxyAttemptError::before_dispatch(failure_message),
            )
        },
        move |completed_request_id| {
            let completed = completed_ref.clone();
            async move {
                completed
                    .lock()
                    .expect("completion tracker should lock")
                    .push(completed_request_id);
            }
        },
    )
    .await;
    assert_route_unavailable_response(&response);
    assert_eq!(
        completed
            .lock()
            .expect("completion tracker should lock")
            .as_slice(),
        &[request_id]
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn execute_torii_proxy_request_across_candidates_returns_route_unavailable_without_candidates()
 {
    run_route_unavailable_proxy_case(RouteUnavailableProxyCase::NoCandidates).await;
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn execute_torii_proxy_request_across_candidates_returns_last_retryable_response() {
    let peer_id = checked_torii_test_peer_id(0x97, "derive last retryable proxy peer fixture key");
    let route = RoutingDecision::new(LaneId::new(6), DataSpaceId::new(7));
    let request =
        signed_query_proxy_request_for_test(Hash::new(b"torii-proxy-last-retryable"), route);
    let response = super::execute_torii_proxy_request_across_candidates(
        tokio::time::Instant::now(),
        vec![ToriiProxyCandidate::P2p(peer_id)],
        route,
        request,
        TORII_PROXY_REQUEST_MAX_ENCODED_BYTES_V1,
        |_candidate, _request| async move {
            Ok(ToriiProxyHttpResponseV1 {
                status_code: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                headers: vec![iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                    name: "x-iroha-reject-code".to_owned(),
                    value: b"route_unavailable".to_vec(),
                }],
                body: b"retry-later".to_vec(),
            })
        },
        |_request_id| async move {},
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-transport"),
        Some("p2p_proxy")
    );
    let body = torii_body_bytes(response, "response body should be readable").await;
    assert_eq!(body.as_ref(), b"retry-later");
}
#[cfg(feature = "connect")]
fn generic_proxy_request_for_test(request_id: Hash) -> ToriiProxyRequestV1 {
    ToriiProxyRequestV1 {
        schema_version: TORII_PROXY_REQUEST_VERSION_V1,
        request_id,
        deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
        hop_count: 1,
        max_hops: 3,
        visited_peer_ids: Vec::new(),
        request: ToriiProxyRequestKindV1::HostedHttp(ToriiHostedHttpProxyRequestV1 {
            service_name: "capacity-failover".to_owned(),
            service_version: "v1".to_owned(),
            replica_slot: 0,
            request_path: "/health".to_owned(),
            method: "GET".to_owned(),
            query_string: None,
            headers: Vec::new(),
            body: Vec::new(),
            remote_ip: None,
        }),
    }
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn generic_proxy_retries_exact_capacity_429_on_next_candidate() {
    let first_peer_id =
        checked_torii_test_peer_id(0x98, "derive capacity-limited proxy peer fixture key");
    let second_peer_id =
        checked_torii_test_peer_id(0x99, "derive healthy fallback proxy peer fixture key");
    let route = RoutingDecision::new(LaneId::new(8), DataSpaceId::new(9));
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attempts_ref = attempts.clone();
    let first_peer_id_for_attempt = first_peer_id.clone();
    let response = super::execute_torii_proxy_request_across_candidates(
        tokio::time::Instant::now(),
        vec![
            ToriiProxyCandidate::P2p(first_peer_id),
            ToriiProxyCandidate::P2p(second_peer_id),
        ],
        route,
        generic_proxy_request_for_test(Hash::new(b"generic-proxy-capacity-failover")),
        TORII_PROXY_REQUEST_MAX_ENCODED_BYTES_V1,
        move |candidate, _request| {
            let attempts = attempts_ref.clone();
            let first_peer_id = first_peer_id_for_attempt.clone();
            async move {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if candidate.peer_id() == &first_peer_id {
                    return Ok(ToriiProxyHttpResponseV1 {
                        status_code: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                        headers: vec![iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                            name: "x-iroha-reject-code".to_owned(),
                            value: b"proxy_capacity_exceeded".to_vec(),
                        }],
                        body: b"candidate proxy slot is occupied".to_vec(),
                    });
                }
                Ok(ToriiProxyHttpResponseV1 {
                    status_code: StatusCode::OK.as_u16(),
                    headers: Vec::new(),
                    body: b"healthy-fallback".to_vec(),
                })
            }
        },
        |_request_id| async move {},
    )
    .await;

    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(response.status(), StatusCode::OK);
    let body = torii_body_bytes(response, "healthy fallback response should be readable").await;
    assert_eq!(body.as_ref(), b"healthy-fallback");
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn generic_proxy_does_not_retry_an_unstructured_429() {
    let first_peer_id =
        checked_torii_test_peer_id(0x9A, "derive rate-limited proxy peer fixture key");
    let second_peer_id =
        checked_torii_test_peer_id(0x9B, "derive unused fallback proxy peer fixture key");
    let route = RoutingDecision::new(LaneId::new(10), DataSpaceId::new(11));
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attempts_ref = attempts.clone();
    let response = super::execute_torii_proxy_request_across_candidates(
        tokio::time::Instant::now(),
        vec![
            ToriiProxyCandidate::P2p(first_peer_id),
            ToriiProxyCandidate::P2p(second_peer_id),
        ],
        route,
        generic_proxy_request_for_test(Hash::new(b"generic-proxy-definitive-429")),
        TORII_PROXY_REQUEST_MAX_ENCODED_BYTES_V1,
        move |_candidate, _request| {
            let attempts = attempts_ref.clone();
            async move {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(ToriiProxyHttpResponseV1 {
                    status_code: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                    headers: Vec::new(),
                    body: b"rate-limited".to_vec(),
                })
            }
        },
        |_request_id| async move {},
    )
    .await;

    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = torii_body_bytes(response, "definitive 429 response should be readable").await;
    assert_eq!(body.as_ref(), b"rate-limited");
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn backpressured_busy_rejection_cannot_block_proxy_response_dispatch() {
    let app = mk_app_state_for_tests();
    let network = iroha_core::IrohaNetwork::actor_backpressured_for_tests();
    let busy_peer_key = checked_torii_test_bls_keypair(
        0xc5,
        "derive backpressured busy-rejection peer fixture key",
    );
    let busy_peer = Peer::new(
        "127.0.0.1:23001".parse().expect("valid busy peer address"),
        busy_peer_key.public_key().clone(),
    );
    let busy_request_id = Hash::new(b"backpressured-busy-rejection");
    let reject_code = "proxy_capacity_exceeded";
    let mut body = Vec::new();
    norito::core::to_bytes_in(
        &ErrorEnvelope::new(
            reject_code,
            "Torii proxy memory capacity is exhausted".to_owned(),
        ),
        &mut body,
    )
    .expect("fixed capacity-response fixture must encode");
    let busy_post = iroha_p2p::Post {
        peer_id: busy_peer.id().clone(),
        priority: iroha_p2p::Priority::High,
        data: iroha_core::NetworkMessage::ToriiProxyResponse(Box::new(ToriiProxyResponseV1 {
            schema_version: TORII_PROXY_RESPONSE_VERSION_V1,
            request_id: busy_request_id,
            response: ToriiProxyHttpResponseV1 {
                status_code: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                headers: vec![
                    iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                        name: "content-type".to_owned(),
                        value: crate::utils::NORITO_MIME_TYPE.as_bytes().to_vec(),
                    },
                    iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                        name: "x-iroha-reject-code".to_owned(),
                        value: reject_code.as_bytes().to_vec(),
                    },
                ],
                body,
            },
        })),
    };
    match network.post_best_effort_recoverable(busy_post) {
        Err(iroha_p2p::network::NetworkPostAdmissionError::Backpressured { message }) => {
            assert_eq!(message.peer_id, *busy_peer.id());
        }
        other => {
            panic!("valid BLS capacity response must reach exact actor backpressure: {other:?}")
        }
    }
    let capacity_rejection_completed_inline: () =
        super::reject_incoming_torii_proxy_request_capacity(
            &network,
            &busy_peer,
            busy_request_id,
            super::torii_proxy_test_deadline_unix_ms(),
        );
    let () = capacity_rejection_completed_inline;
    let responder_key = checked_torii_test_ed25519_keypair(
        0xc6,
        "derive response-pump liveness responder fixture key",
    );
    let responder_peer_id = PeerId::from(responder_key.public_key().clone());
    let request_id = Hash::new(b"response-after-backpressured-busy-rejection");
    let expected = ToriiProxyHttpResponseV1 {
        status_code: StatusCode::OK.as_u16(),
        headers: Vec::new(),
        body: b"response-pump-remains-live".to_vec(),
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let _waiter_token = super::register_torii_proxy_pending_waiter(
        &app,
        (request_id, responder_peer_id.clone()),
        tx,
        1024,
    );
    super::process_incoming_torii_proxy_response(
        &app,
        responder_peer_id,
        ToriiProxyResponseV1 {
            schema_version: TORII_PROXY_RESPONSE_VERSION_V1,
            request_id,
            response: expected.clone(),
        },
    )
    .await;
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), rx)
            .await
            .expect("response pump must not remain blocked behind busy-rejection admission")
            .expect("pending response receiver must stay open"),
        expected
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn backpressured_response_admission_obeys_local_egress_deadline() {
    let network = iroha_core::IrohaNetwork::actor_backpressured_for_tests();
    let target_key =
        checked_torii_test_bls_keypair(0xc7, "derive local egress-deadline target fixture key");
    let target = PeerId::from(target_key.public_key().clone());
    let request_id = Hash::new(b"backpressured-response-local-egress-deadline");
    let post = iroha_p2p::Post {
        peer_id: target,
        priority: iroha_p2p::Priority::High,
        data: iroha_core::NetworkMessage::ToriiProxyResponse(Box::new(ToriiProxyResponseV1 {
            schema_version: TORII_PROXY_RESPONSE_VERSION_V1,
            request_id,
            response: ToriiProxyHttpResponseV1 {
                status_code: StatusCode::OK.as_u16(),
                headers: Vec::new(),
                body: Vec::new(),
            },
        })),
    };
    let post = match network.post_best_effort_recoverable(post) {
        Err(iroha_p2p::network::NetworkPostAdmissionError::Backpressured { message }) => message,
        other => {
            panic!("valid BLS response fixture must reach exact actor backpressure: {other:?}")
        }
    };
    let local_deadline = tokio::time::Instant::now() + Duration::from_millis(20);
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        super::post_torii_proxy_control_until_deadline(
            &network,
            post,
            super::torii_proxy_test_deadline_unix_ms(),
            local_deadline,
        ),
    )
    .await
    .expect("local egress deadline must stop backpressured response admission");
    let error = result.expect_err("a permanently backpressured actor cannot accept the response");
    assert!(
        error.contains("local admission deadline"),
        "the local monotonic owner, not the wider skew-tolerant wire horizon, must terminate admission: {error}"
    );
}
#[cfg(feature = "connect")]
#[test]
fn proxy_response_admission_rejects_non_bls_target_before_actor_backpressure() {
    let network = iroha_core::IrohaNetwork::actor_backpressured_for_tests();
    let target_key =
        checked_torii_test_ed25519_keypair(0xc7, "derive invalid relay target fixture key");
    let target = PeerId::from(target_key.public_key().clone());
    let request_id = Hash::new(b"proxy-response-invalid-relay-target");
    let post = iroha_p2p::Post {
        peer_id: target.clone(),
        priority: iroha_p2p::Priority::High,
        data: iroha_core::NetworkMessage::ToriiProxyResponse(Box::new(ToriiProxyResponseV1 {
            schema_version: TORII_PROXY_RESPONSE_VERSION_V1,
            request_id,
            response: ToriiProxyHttpResponseV1 {
                status_code: StatusCode::OK.as_u16(),
                headers: Vec::new(),
                body: Vec::new(),
            },
        })),
    };
    let message = match network.post_best_effort_recoverable(post) {
        Err(iroha_p2p::network::NetworkPostAdmissionError::Rejected { message, reason }) => {
            assert_eq!(
                reason,
                iroha_p2p::network::NetworkActorAdmissionRejection::WireLength
            );
            message
        }
        other => {
            panic!("non-BLS relay target must fail exact wire admission before capacity: {other:?}")
        }
    };
    assert_eq!(message.peer_id, target);
    assert_eq!(message.priority, iroha_p2p::Priority::High);
    let iroha_core::NetworkMessage::ToriiProxyResponse(response) = message.data else {
        panic!("wire rejection must return the original proxy response");
    };
    assert_eq!(response.request_id, request_id);
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn execute_torii_proxy_request_across_candidates_returns_route_unavailable_after_transport_errors()
 {
    run_route_unavailable_proxy_case(RouteUnavailableProxyCase::TransportErrors).await;
}
#[cfg(feature = "telemetry")]
fn sample_privacy_event_dto() -> RecordSoranetPrivacyEventDto {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after UNIX epoch")
        .as_secs();
    RecordSoranetPrivacyEventDto {
        event: SoranetPrivacyEventV1 {
            timestamp_unix: now_unix,
            mode: SoranetPrivacyModeV1::Entry,
            kind: SoranetPrivacyEventKindV1::HandshakeSuccess(
                SoranetPrivacyEventHandshakeSuccessV1 {
                    rtt_ms: Some(12),
                    active_circuits_after: Some(3),
                },
            ),
        },
        source: None,
    }
}
#[cfg(feature = "telemetry")]
fn sample_privacy_share_dto(app: &SharedAppState) -> RecordSoranetPrivacyShareDto {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after UNIX epoch")
        .as_secs();
    let bucket_start = (now_unix / 60) * 60;
    let operator = privacy_operator(app).0;
    let collector_id =
        iroha_data_model::soranet::privacy_metrics::derive_soranet_privacy_collector_id(
            &operator.0,
        );
    let mut share = SoranetPrivacyPrioShareV1::new(collector_id, bucket_start, 60);
    share.mode = SoranetPrivacyModeV1::Entry;
    share.handshake_accept_share = 5;
    share.active_circuits_sum_share = 30;
    share.active_circuits_sample_share = 5;
    share.active_circuits_max_observed = Some(7);
    share.verified_bytes_share = 1_024;
    RecordSoranetPrivacyShareDto {
        share,
        forwarded_by: None,
    }
}
#[test]
#[cfg(feature = "telemetry")]
fn privacy_event_dto_native_norito_roundtrip() {
    let mut expected = sample_privacy_event_dto();
    expected.source = Some("relay-a".to_owned());
    let encoded = crate::frame_test_support::assert_current_frame(
        &expected,
        "iroha_torii::routing::RecordSoranetPrivacyEventDto",
    );
    let decoded: RecordSoranetPrivacyEventDto =
        norito::decode_from_bytes(&encoded).expect("decode privacy event request from Norito");
    assert_eq!(decoded.event, expected.event);
    assert_eq!(decoded.source, expected.source);
}
#[test]
#[cfg(feature = "telemetry")]
fn privacy_share_dto_native_norito_roundtrip() {
    let app = mk_app_state_for_tests();
    let mut expected = sample_privacy_share_dto(&app);
    expected.forwarded_by = Some("collector-a".to_owned());
    let encoded = crate::frame_test_support::assert_current_frame(
        &expected,
        "iroha_torii::routing::RecordSoranetPrivacyShareDto",
    );
    let decoded: RecordSoranetPrivacyShareDto =
        norito::decode_from_bytes(&encoded).expect("decode privacy share request from Norito");
    assert_eq!(decoded.share, expected.share);
    assert_eq!(decoded.forwarded_by, expected.forwarded_by);
}
#[cfg(feature = "telemetry")]
fn privacy_operator(
    app: &SharedAppState,
) -> axum::extract::Extension<operator_signatures::AuthenticatedOperatorPublicKey> {
    axum::extract::Extension(operator_signatures::AuthenticatedOperatorPublicKey(
        app.da_receipt_signer.public_key().clone(),
    ))
}
#[tokio::test]
#[cfg(feature = "telemetry")]
async fn privacy_ingest_rejects_when_disabled() {
    let app = mk_app_state_for_tests();
    let dto = sample_privacy_event_dto();
    let response = super::test_handler_post_soranet_privacy_event_with_ingress(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 0))),
        privacy_operator(&app),
        NoritoJson(dto),
    )
    .await
    .expect("handler executes");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let metrics = app.telemetry.metrics();
    let disabled = metrics
        .soranet_privacy_ingest_reject_total
        .get_metric_with_label_values(&["event", "disabled"])
        .unwrap()
        .get();
    assert!(disabled >= 1, "disabled counter should increment");
}
#[tokio::test]
#[cfg(feature = "telemetry")]
async fn privacy_ingest_denies_without_allowlist() {
    let mut app = mk_app_state_for_tests();
    {
        let app_mut =
            std::sync::Arc::get_mut(&mut app).expect("unique Arc for privacy configuration");
        app_mut.soranet_privacy_ingest.enabled = true;
        app_mut.soranet_privacy_allow_nets = Arc::new(Vec::new());
    }
    let response = super::test_handler_post_soranet_privacy_event_with_ingress(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        privacy_operator(&app),
        NoritoJson(sample_privacy_event_dto()),
    )
    .await
    .expect("handler executes");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let metrics = app.telemetry.metrics();
    let blocked = metrics
        .soranet_privacy_ingest_reject_total
        .get_metric_with_label_values(&["event", "namespace_blocked"])
        .unwrap()
        .get();
    assert!(blocked >= 1, "namespace block counter should increment");
}
#[tokio::test]
#[cfg(feature = "telemetry")]
async fn privacy_ingest_enforces_operator_namespace_and_rate() {
    let mut app = mk_app_state_for_tests();
    {
        let app_mut =
            std::sync::Arc::get_mut(&mut app).expect("unique Arc for privacy configuration");
        app_mut.soranet_privacy_ingest.enabled = true;
        app_mut.soranet_privacy_ingest.allow_cidrs =
            vec!["127.0.0.1/32".to_string(), "::1/128".to_string()];
        app_mut.soranet_privacy_ingest.rate_per_sec =
            Some(std::num::NonZeroU32::new(1).expect("nonzero"));
        app_mut.soranet_privacy_ingest.burst = Some(std::num::NonZeroU32::new(1).expect("nonzero"));
        app_mut.soranet_privacy_allow_nets = Arc::new(crate::limits::parse_cidrs(
            &app_mut.soranet_privacy_ingest.allow_cidrs,
        ));
        app_mut.soranet_privacy_rate_limiter = crate::limits::RateLimiter::new(
            app_mut
                .soranet_privacy_ingest
                .rate_per_sec
                .map(std::num::NonZeroU32::get),
            app_mut
                .soranet_privacy_ingest
                .burst
                .map(std::num::NonZeroU32::get),
        );
    }
    let dto = sample_privacy_event_dto();
    // Retired bearer credentials are rejected even after exact operator authentication.
    let mut retired_headers = HeaderMap::new();
    retired_headers.insert(
        "x-soranet-privacy-token",
        HeaderValue::from_static("retired-secret"),
    );
    let resp = super::test_handler_post_soranet_privacy_event_with_ingress(
        State(app.clone()),
        retired_headers,
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        privacy_operator(&app),
        NoritoJson(dto.clone()),
    )
    .await
    .expect("handler executes");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let metrics = app.telemetry.metrics();
    let retired = metrics
        .soranet_privacy_ingest_reject_total
        .get_metric_with_label_values(&["event", "retired_token"])
        .unwrap()
        .get();
    assert!(retired >= 1);
    // Wrong namespace
    let resp = super::test_handler_post_soranet_privacy_event_with_ingress(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 0))),
        privacy_operator(&app),
        NoritoJson(dto.clone()),
    )
    .await
    .expect("handler executes");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // Happy path
    let ok_resp = super::test_handler_post_soranet_privacy_event_with_ingress(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        privacy_operator(&app),
        NoritoJson(dto.clone()),
    )
    .await
    .expect("handler executes");
    assert_eq!(ok_resp.status(), StatusCode::ACCEPTED);
    // Rate limit on second immediate call
    let limited_resp = super::test_handler_post_soranet_privacy_event_with_ingress(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        privacy_operator(&app),
        NoritoJson(dto),
    )
    .await
    .expect("handler executes");
    assert_eq!(limited_resp.status(), StatusCode::TOO_MANY_REQUESTS);
}
#[tokio::test]
#[cfg(feature = "telemetry")]
async fn privacy_ingest_denies_without_namespace_allowlist() {
    let mut app = mk_app_state_for_tests();
    {
        let app_mut =
            std::sync::Arc::get_mut(&mut app).expect("unique Arc for privacy configuration");
        app_mut.soranet_privacy_ingest.enabled = true;
        app_mut.soranet_privacy_ingest.allow_cidrs.clear();
        app_mut.soranet_privacy_allow_nets = Arc::new(Vec::new());
    }
    let dto = sample_privacy_event_dto();
    let resp = super::test_handler_post_soranet_privacy_event_with_ingress(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        privacy_operator(&app),
        NoritoJson(dto),
    )
    .await
    .expect("handler executes");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let metrics = app.telemetry.metrics();
    let blocked = metrics
        .soranet_privacy_ingest_reject_total
        .get_metric_with_label_values(&["event", "namespace_blocked"])
        .unwrap()
        .get();
    assert!(
        blocked >= 1,
        "namespace rejection counter should increment for missing allow-list"
    );
}
#[tokio::test]
#[cfg(feature = "telemetry")]
async fn privacy_ingest_authenticates_before_body_decode() {
    let mut app = mk_app_state_for_tests();
    {
        let app_mut =
            std::sync::Arc::get_mut(&mut app).expect("unique Arc for privacy configuration");
        app_mut.soranet_privacy_ingest.enabled = true;
        app_mut.soranet_privacy_ingest.allow_cidrs = vec!["127.0.0.1/32".to_owned()];
        app_mut.soranet_privacy_allow_nets = Arc::new(crate::limits::parse_cidrs(
            &app_mut.soranet_privacy_ingest.allow_cidrs,
        ));
    }
    const ROUTES: &[iroha_torii_shared::route_catalog::RouteDescriptor] =
        &[route_catalog::telemetry::SORANET_PRIVACY_EVENT];
    let descriptor = &ROUTES[0];
    let mut builder = RouterBuilder::new(
        app.clone(),
        RouteCatalog::new(ROUTES),
        compiled_route_features(),
    )
    .expect("privacy route catalog is valid");
    builder.route(
        descriptor,
        catalog_post(super::handler_post_soranet_privacy_event)
            .layer(DefaultBodyLimit::max(
                super::SORANET_PRIVACY_INGEST_MAX_BODY_BYTES,
            ))
            .authenticated_soranet_privacy_collector(app.clone(), "event"),
    );
    let (router, _) = builder.finish().expect("privacy route mounts exactly once");
    let router = router.with_state(app.clone());
    let mut request = Request::builder()
        .method(HttpMethod::POST)
        .uri(descriptor.path())
        .header("content-type", "application/json")
        .header("x-soranet-privacy-token", "retired-secret")
        .body(Body::from("{"))
        .expect("malformed request");
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            0,
        ))));
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("privacy route response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = b"{";
    let uri = descriptor
        .path()
        .parse::<crate::Uri>()
        .expect("privacy route URI");
    let signed_headers = operator_signatures::signed_request_headers(
        &app.da_receipt_signer,
        app.state.network_id_ref(),
        &crate::Method::POST,
        &uri,
        body,
    )
    .expect("sign malformed privacy request");
    let mut signed_request = Request::builder()
        .method(HttpMethod::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.as_slice()))
        .expect("signed malformed request");
    signed_request.headers_mut().extend(signed_headers);
    signed_request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            0,
        ))));
    let response = router
        .oneshot(signed_request)
        .await
        .expect("signed privacy route response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
#[tokio::test]
#[cfg(feature = "telemetry")]
async fn privacy_ingest_authentication_enforces_route_body_limit() {
    let mut app = mk_app_state_for_tests();
    assert!(
        app.transaction_max_content_len > super::SORANET_PRIVACY_INGEST_MAX_BODY_BYTES,
        "test must distinguish the privacy limit from Torii's global operator limit"
    );
    {
        let app_mut =
            std::sync::Arc::get_mut(&mut app).expect("unique Arc for privacy configuration");
        app_mut.soranet_privacy_ingest.enabled = true;
        app_mut.soranet_privacy_ingest.allow_cidrs = vec!["127.0.0.1/32".to_owned()];
        app_mut.soranet_privacy_allow_nets = Arc::new(crate::limits::parse_cidrs(
            &app_mut.soranet_privacy_ingest.allow_cidrs,
        ));
    }
    const ROUTES: &[iroha_torii_shared::route_catalog::RouteDescriptor] =
        &[route_catalog::telemetry::SORANET_PRIVACY_EVENT];
    let descriptor = &ROUTES[0];
    let mut builder = RouterBuilder::new(
        app.clone(),
        RouteCatalog::new(ROUTES),
        compiled_route_features(),
    )
    .expect("privacy route catalog is valid");
    builder.route(
        descriptor,
        catalog_post(|| async { StatusCode::NO_CONTENT })
            .layer(DefaultBodyLimit::max(
                super::SORANET_PRIVACY_INGEST_MAX_BODY_BYTES,
            ))
            .authenticated_soranet_privacy_collector(app.clone(), "event"),
    );
    let (router, _) = builder.finish().expect("privacy route mounts exactly once");
    let uri = descriptor
        .path()
        .parse::<crate::Uri>()
        .expect("privacy route URI");
    let router = router.with_state(app.clone());
    let exact_body = vec![b'x'; super::SORANET_PRIVACY_INGEST_MAX_BODY_BYTES];
    let exact_headers = operator_signatures::signed_request_headers(
        &app.da_receipt_signer,
        app.state.network_id_ref(),
        &crate::Method::POST,
        &uri,
        &exact_body,
    )
    .expect("sign exact-limit privacy request");
    let mut exact_request = Request::builder()
        .method(HttpMethod::POST)
        .uri(uri.clone())
        .body(Body::from(exact_body))
        .expect("exact-limit signed request");
    exact_request.headers_mut().extend(exact_headers);
    exact_request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            0,
        ))));
    let exact_response = router
        .clone()
        .oneshot(exact_request)
        .await
        .expect("exact-limit privacy route response");
    assert_eq!(exact_response.status(), StatusCode::NO_CONTENT);

    let body = vec![b'x'; super::SORANET_PRIVACY_INGEST_MAX_BODY_BYTES + 1];
    let signed_headers = operator_signatures::signed_request_headers(
        &app.da_receipt_signer,
        app.state.network_id_ref(),
        &crate::Method::POST,
        &uri,
        &body,
    )
    .expect("sign oversized privacy request");
    let mut request = Request::builder()
        .method(HttpMethod::POST)
        .uri(uri)
        .body(Body::from(body))
        .expect("oversized signed request");
    request.headers_mut().extend(signed_headers);
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            0,
        ))));
    let response = router
        .oneshot(request)
        .await
        .expect("oversized privacy route response");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
#[tokio::test]
#[cfg(feature = "telemetry")]
async fn privacy_ingest_blocks_without_allowlist() {
    let mut app = mk_app_state_for_tests();
    {
        let app_mut =
            std::sync::Arc::get_mut(&mut app).expect("unique Arc for privacy configuration");
        app_mut.soranet_privacy_ingest.enabled = true;
        app_mut.soranet_privacy_allow_nets = Arc::new(Vec::new());
        app_mut.soranet_privacy_rate_limiter = crate::limits::RateLimiter::new(None, None);
    }
    let resp = super::test_handler_post_soranet_privacy_event_with_ingress(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        privacy_operator(&app),
        NoritoJson(sample_privacy_event_dto()),
    )
    .await
    .expect("handler executes");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let metrics = app.telemetry.metrics();
    let namespace_blocked = metrics
        .soranet_privacy_ingest_reject_total
        .get_metric_with_label_values(&["event", "namespace_blocked"])
        .unwrap()
        .get();
    assert!(
        namespace_blocked >= 1,
        "namespace reject counter must increment"
    );
}
#[tokio::test]
#[cfg(feature = "telemetry")]
async fn privacy_share_binds_collector_id_to_authenticated_operator() {
    let mut app = mk_app_state_for_tests();
    {
        let app_mut =
            std::sync::Arc::get_mut(&mut app).expect("unique Arc for privacy configuration");
        app_mut.soranet_privacy_ingest.enabled = true;
        app_mut.soranet_privacy_ingest.allow_cidrs = vec!["127.0.0.1/32".to_string()];
        app_mut.soranet_privacy_allow_nets = Arc::new(crate::limits::parse_cidrs(
            &app_mut.soranet_privacy_ingest.allow_cidrs,
        ));
        app_mut.soranet_privacy_rate_limiter = crate::limits::RateLimiter::new(None, None);
    }
    let mut mismatched = sample_privacy_share_dto(&app);
    mismatched.share.collector_id[0] ^= 1;
    let response = super::test_handler_post_soranet_privacy_share_with_ingress(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        privacy_operator(&app),
        NoritoJson(mismatched),
    )
    .await
    .expect("handler executes");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = super::test_handler_post_soranet_privacy_share_with_ingress(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        privacy_operator(&app),
        NoritoJson(sample_privacy_share_dto(&app)),
    )
    .await
    .expect("handler executes");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}
#[tokio::test]
#[cfg(feature = "telemetry")]
async fn privacy_share_ingest_enforces_policy() {
    let mut app = mk_app_state_for_tests();
    {
        let app_mut =
            std::sync::Arc::get_mut(&mut app).expect("unique Arc for privacy configuration");
        app_mut.soranet_privacy_ingest.enabled = true;
        app_mut.soranet_privacy_ingest.allow_cidrs =
            vec!["127.0.0.1/32".to_string(), "::1/128".to_string()];
        app_mut.soranet_privacy_ingest.rate_per_sec =
            Some(std::num::NonZeroU32::new(1).expect("nonzero"));
        app_mut.soranet_privacy_ingest.burst = Some(std::num::NonZeroU32::new(1).expect("nonzero"));
        app_mut.soranet_privacy_allow_nets = Arc::new(crate::limits::parse_cidrs(
            &app_mut.soranet_privacy_ingest.allow_cidrs,
        ));
        app_mut.soranet_privacy_rate_limiter = crate::limits::RateLimiter::new(
            app_mut
                .soranet_privacy_ingest
                .rate_per_sec
                .map(std::num::NonZeroU32::get),
            app_mut
                .soranet_privacy_ingest
                .burst
                .map(std::num::NonZeroU32::get),
        );
    }
    let share_dto = sample_privacy_share_dto(&app);
    // Retired bearer credential -> 400, even with an authenticated operator.
    let mut retired_headers = HeaderMap::new();
    retired_headers.insert("x-api-token", HeaderValue::from_static("retired-secret"));
    let resp = super::test_handler_post_soranet_privacy_share_with_ingress(
        State(app.clone()),
        retired_headers,
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        privacy_operator(&app),
        NoritoJson(share_dto.clone()),
    )
    .await
    .expect("handler executes");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // Wrong namespace -> 403
    let resp = super::test_handler_post_soranet_privacy_share_with_ingress(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 0))),
        privacy_operator(&app),
        NoritoJson(share_dto.clone()),
    )
    .await
    .expect("handler executes");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // Happy path -> 202
    let ok = super::test_handler_post_soranet_privacy_share_with_ingress(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        privacy_operator(&app),
        NoritoJson(share_dto.clone()),
    )
    .await
    .expect("handler executes");
    assert_eq!(ok.status(), StatusCode::ACCEPTED);
    // Rate limit -> 429
    let limited = super::test_handler_post_soranet_privacy_share_with_ingress(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        privacy_operator(&app),
        NoritoJson(share_dto),
    )
    .await
    .expect("handler executes");
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    let metrics = app.telemetry.metrics();
    let retired = metrics
        .soranet_privacy_ingest_reject_total
        .get_metric_with_label_values(&["share", "retired_token"])
        .unwrap()
        .get();
    assert!(retired >= 1);
    let namespace = metrics
        .soranet_privacy_ingest_reject_total
        .get_metric_with_label_values(&["share", "namespace_blocked"])
        .unwrap()
        .get();
    assert!(namespace >= 1);
}
#[tokio::test]
async fn runtime_metrics_and_node_capabilities_ok() {
    let app = mk_app_state_for_tests();
    let headers = HeaderMap::new();
    let metrics_resp = super::handler_runtime_metrics(
        State(app.clone()),
        headers.clone(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static("application/json"),
        )),
    )
    .await
    .expect("ok");
    assert_eq!(metrics_resp.status(), axum::http::StatusCode::OK);
    let metrics_bytes = torii_body_bytes(metrics_resp, "body").await;
    let metrics: crate::runtime::RuntimeMetricsResponse =
        norito::json::from_slice(&metrics_bytes).expect("decode json");
    assert_eq!(metrics.abi_version, 1);
    let caps_resp = super::handler_node_capabilities(
        State(app.clone()),
        headers,
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static("application/json"),
        )),
    )
    .await
    .expect("ok");
    assert_eq!(caps_resp.status(), axum::http::StatusCode::OK);
    let caps_bytes = torii_body_bytes(caps_resp, "body").await;
    let caps: crate::runtime::NodeCapabilitiesResponse =
        norito::json::from_slice(&caps_bytes).expect("decode json");
    assert_eq!(caps.abi_version, 1);
    assert_eq!(
        caps.data_model_version,
        iroha_data_model::DATA_MODEL_VERSION
    );
    assert_eq!(caps.signed_transaction_schema_hash_hex.len(), 32);
    assert_eq!(
        caps.signed_transaction_schema_hash_hex,
        hex::encode(norito::schema::identity::frame_hash::<
            iroha_data_model::transaction::SignedTransaction,
        >())
    );
    assert!(caps.crypto.sm.acceleration.scalar);
    assert!(caps.query.aggregate.v1);
    assert!(caps.query.aggregate.exact_results);
    assert_eq!(caps.query.aggregate.supported_resources, {
        #[cfg(feature = "app_api")]
        {
            crate::collections::aggregate_collections()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        }
        #[cfg(not(feature = "app_api"))]
        {
            Vec::<String>::new()
        }
    });
    assert!(caps.query.projection.checkpoint_contract_v1);
    assert!(!caps.query.projection.da_v1_enabled);
    assert_eq!(
        caps.query.projection.shard_catalog_v1,
        cfg!(feature = "app_api")
    );
    assert_eq!(
        caps.query.projection.archive_export_v1,
        cfg!(feature = "app_api")
    );
    assert_eq!(caps.query.projection.archive_version, 1);
    assert_eq!(caps.query.projection.blob_class_custom_id, 1001);
    assert_eq!(
        caps.query.projection.codec,
        "application/x-iroha-query-shard+norito+zstd"
    );
    assert_eq!(
        caps.query.projection.rowset_codec,
        "application/x-iroha-query-shard-rowset+norito"
    );
    assert_eq!(caps.query.projection.compression, "zstd");
    assert_eq!(caps.query.projection.default_partition_count, 4096);
    assert!(
        caps.query
            .projection
            .metadata_keys
            .contains(&"query_projection.locator".to_string())
    );
    #[cfg(feature = "app_api")]
    {
        assert_eq!(
            caps.query.projection.export_supported_resources,
            crate::collections::PROJECTION_EXPORT_COLLECTIONS
                .map(str::to_owned)
                .to_vec()
        );
    }
    #[cfg(not(feature = "app_api"))]
    assert!(caps.query.projection.export_supported_resources.is_empty());
    assert!(
        caps.query
            .projection
            .latest_checkpoint_indexed_height
            .is_none()
    );
    assert!(
        caps.query
            .projection
            .latest_checkpoint_block_hash_hex
            .is_none()
    );
    assert!(
        !caps.crypto.sm.allowed_signing.is_empty(),
        "allowed_signing must advertise at least one algorithm"
    );
    let checkpoint_absent = super::handler_node_query_projection_checkpoint(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        None,
    )
    .await
    .expect("ok");
    assert_eq!(
        checkpoint_absent.status(),
        axum::http::StatusCode::NOT_FOUND
    );
}
#[tokio::test]
async fn node_query_projection_checkpoint_handler_returns_persisted_payload() {
    let app = mk_app_state_for_tests();
    let expected_hash =
        iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
            iroha_crypto::Hash::new([0x6A; iroha_crypto::Hash::LENGTH]),
        );
    app.state.persist_query_projection_checkpoint(Some(
            iroha_core::query::projection_checkpoint::QueryProjectionCheckpoint::from_index_status(
                iroha_core::query::index_status::QueryIndexStatus {
                    indexed_height: 55,
                    indexed_block_hash: Some(expected_hash),
                },
                1_714_000_555,
                vec![iroha_core::query::projection_checkpoint::QueryProjectionCheckpointShard {
                    resource:
                        iroha_core::query::projection_checkpoint::QueryProjectionResourceKind::Accounts,
                    partition_id: 3,
                    asset_definition_id: None,
                    manifest_digest: iroha_data_model::da::types::BlobDigest::new([0x11; 32]),
                    storage_ticket: iroha_data_model::da::types::StorageTicketId::new([0x22; 32]),
                    blob_hash: iroha_data_model::da::types::BlobDigest::new([0x33; 32]),
                }],
            ),
        ));
    let response = super::handler_node_query_projection_checkpoint(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            axum::http::HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        )),
    )
    .await
    .expect("ok");
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response.headers().get(axum::http::header::CONTENT_TYPE),
        Some(&axum::http::HeaderValue::from_static(
            crate::utils::NORITO_MIME_TYPE,
        ))
    );
    let body = torii_body_bytes(response, "body").await;
    let checkpoint: crate::runtime::NodeProjectionCheckpointResponse =
        norito::decode_from_bytes(&body).expect("decode requested Norito response");
    let canonical = crate::frame_test_support::assert_current_frame(
        &checkpoint,
        "iroha_torii::runtime::NodeProjectionCheckpointResponse",
    );
    assert_eq!(canonical.as_slice(), body.as_ref());
    assert_eq!(checkpoint.indexed_height, 55);
    assert_eq!(
        checkpoint.indexed_block_hash_hex,
        Some(hex::encode(expected_hash.as_ref()))
    );
    assert_eq!(checkpoint.shards.len(), 1);
    assert_eq!(checkpoint.shards[0].resource, "accounts");
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn node_query_projection_shard_catalog_handler_returns_catalog_payload() {
    let app = mk_app_state_for_tests();
    let response = super::handler_node_query_projection_shard_catalog(
        State(app),
        AxPath("accounts".to_owned()),
        AxQuery(crate::runtime::NodeProjectionShardCatalogQuery {
            asset_definition_id: None,
            offset: Some(0),
            limit: Some(32),
        }),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            axum::http::HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        )),
    )
    .await
    .expect("ok");
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response.headers().get(axum::http::header::CONTENT_TYPE),
        Some(&axum::http::HeaderValue::from_static(
            crate::utils::NORITO_MIME_TYPE,
        ))
    );
    let body = torii_body_bytes(response, "body").await;
    let catalog: crate::runtime::NodeProjectionShardCatalogResponse =
        norito::decode_from_bytes(&body).expect("decode requested Norito response");
    let canonical = crate::frame_test_support::assert_current_frame(
        &catalog,
        "iroha_torii::runtime::NodeProjectionShardCatalogResponse",
    );
    assert_eq!(canonical.as_slice(), body.as_ref());
    assert_eq!(catalog.resource, "accounts");
    assert_eq!(catalog.limit, 32);
    assert_eq!(catalog.offset, 0);
    assert!(catalog.total_entries >= catalog.entries.len() as u64);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn node_query_projection_shard_export_handler_returns_binary_archive() {
    let app = mk_app_state_for_tests();
    let response = super::handler_node_query_projection_shard_export(
        State(app),
        AxPath(("accounts".to_owned(), 0)),
        AxQuery(crate::runtime::NodeProjectionShardExportQuery {
            asset_definition_id: None,
        }),
        HeaderMap::new(),
        crate::loopback_connect_info(),
    )
    .await
    .expect("ok");
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .map(axum::http::HeaderValue::as_bytes),
        Some(b"application/octet-stream".as_slice())
    );
    let bytes = torii_body_bytes(response, "body").await;
    let archive: iroha_core::query::projection_shard::QueryProjectionShardArchive =
        norito::decode_from_bytes(&bytes).expect("decode archive");
    assert_eq!(
        archive.resource,
        iroha_core::query::projection_checkpoint::QueryProjectionResourceKind::Accounts
    );
    assert_eq!(archive.partition_id, 0);
}
#[tokio::test]
async fn core_info_handlers_ok() {
    let app = mk_app_state_for_tests();
    let headers = HeaderMap::new();
    // configuration
    let resp = super::handler_get_configuration(
        State(app.clone()),
        headers.clone(),
        crate::loopback_connect_info(),
    )
    .await
    .expect("ok")
    .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let config_bytes = torii_body_bytes(resp, "config body").await;
    let config: Configuration =
        norito::json::from_slice(&config_bytes).expect("decode config payload");
    assert!(
        !config
            .network
            .soranet_handshake
            .descriptor_commit_hex
            .is_empty(),
        "handshake descriptor should be present in config payload"
    );
    assert!(
        config.network.soranet_handshake.pow.puzzle.memory_kib > 0,
        "mandatory puzzle parameters should be advertised in configuration payload"
    );
    // peers
    let mut peer_headers = headers.clone();
    peer_headers.insert(
        axum::http::header::ACCEPT,
        axum::http::HeaderValue::from_static("application/json"),
    );
    let resp = super::handler_peers(
        State(app.clone()),
        peer_headers,
        crate::loopback_connect_info(),
    )
    .await
    .expect("ok")
    .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let peer_bytes = torii_body_bytes(resp, "peers body").await;
    let peers: HashSet<Peer> = norito::json::from_slice(&peer_bytes).expect("peers JSON");
    assert!(peers.is_empty());
    // Ordinary process health does not evaluate wallet or asset readiness.
    let resp = super::handler_health(
        State(app.clone()),
        headers,
        axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
    )
    .await
    .expect("ok")
    .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    assert_eq!(
        torii_body_bytes(resp, "health body").await.as_ref(),
        b"Healthy"
    );
}
#[tokio::test]
async fn time_handlers_ok() {
    let app = mk_app_state_for_tests();
    let headers = HeaderMap::new();
    let resp = super::handler_time_now(
        State(app.clone()),
        headers.clone(),
        crate::loopback_connect_info(),
    )
    .await
    .expect("ok")
    .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let resp = super::handler_time_status(State(app), headers, crate::loopback_connect_info())
        .await
        .expect("ok")
        .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
}
#[cfg(all(feature = "app_api", feature = "push"))]
fn push_test_identity(seed: u8) -> (KeyPair, AccountId) {
    let key_pair = checked_torii_test_keypair(
        vec![seed; 32],
        iroha_crypto::Algorithm::Ed25519,
        "derive push fixture key",
    );
    let account_id = AccountId::new(key_pair.public_key().clone());
    (key_pair, account_id)
}
#[cfg(all(feature = "app_api", feature = "push"))]
fn push_test_config() -> iroha_config::parameters::actual::Push {
    iroha_config::parameters::actual::Push {
        enabled: true,
        fcm_project_id: Some("project".to_string()),
        fcm_service_account_path: Some(std::path::PathBuf::from("/tmp/service-account.json")),
        ..Default::default()
    }
}
#[cfg(all(feature = "app_api", feature = "push"))]
fn mk_push_request(account_id: &AccountId, token: &str) -> push::RegisterDeviceRequest {
    push::RegisterDeviceRequest {
        account_id: account_id.to_string(),
        platform: "FCM".to_string(),
        token: token.to_string(),
        topics: Some(vec!["orders".into()]),
    }
}
#[cfg(all(feature = "app_api", feature = "push"))]
fn signed_push_json<T>(
    account_id: &AccountId,
    key_pair: &KeyPair,
    method: Method,
    uri: axum::http::Uri,
    value: T,
) -> (Method, axum::http::Uri, HeaderMap, axum::body::Bytes)
where
    T: norito::json::JsonSerialize,
{
    let body = norito::json::to_vec(&value).expect("encode push body");
    let mut headers = signed_app_headers(account_id, key_pair, &method, &uri, body.as_ref());
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    (method, uri, headers, axum::body::Bytes::from(body))
}
#[cfg(all(feature = "app_api", feature = "push"))]
async fn extract_error(resp: AxResponse) -> ErrorEnvelope {
    let bytes = torii_body_bytes(resp, "error body").await;
    norito::decode_from_bytes(&bytes).expect("decode error envelope")
}
#[cfg(all(feature = "app_api", feature = "push"))]
#[tokio::test]
async fn push_registration_rejected_when_disabled() {
    let (key_pair, account_id) = push_test_identity(1);
    let app = mk_app_state_for_tests_with_world(world_with_account(&account_id));
    let req = mk_push_request(&account_id, "t-disabled");
    let uri: axum::http::Uri = "/v1/notify/devices".parse().expect("uri");
    let (method, uri, headers, body) =
        signed_push_json(&account_id, &key_pair, Method::POST, uri, req);
    let resp =
        super::handler_push_register_device(State(app.clone()), method, uri, headers, body).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let err = extract_error(resp).await;
    assert_eq!(err.code(), "push_disabled");
    assert!(
        app.push.is_none(),
        "push bridge should be absent by default"
    );
}
#[cfg(all(feature = "app_api", feature = "push"))]
#[tokio::test]
async fn push_registration_requires_credentials() {
    let (key_pair, account_id) = push_test_identity(2);
    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    let app = mk_app_state_for_tests_with_world_and_push(
        world_with_account(&account_id),
        iroha_config::parameters::actual::Push {
            enabled: true,
            ..Default::default()
        },
    );
    let req = mk_push_request(&account_id, "t-missing-creds");
    let uri: axum::http::Uri = "/v1/notify/devices".parse().expect("uri");
    let (method, uri, headers, body) =
        signed_push_json(&account_id, &key_pair, Method::POST, uri, req);
    let resp =
        super::handler_push_register_device(State(app.clone()), method, uri, headers, body).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let err = extract_error(resp).await;
    assert_eq!(err.code(), "push_missing_credentials");
    let bridge = app.push.as_ref().expect("push bridge configured");
    assert_eq!(bridge.device_count(), 0);
}
#[cfg(all(feature = "app_api", feature = "push"))]
#[tokio::test]
async fn push_registration_succeeds_with_credentials() {
    let (key_pair, account_id) = push_test_identity(3);
    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    let app = mk_app_state_for_tests_with_world_and_push(
        world_with_account(&account_id),
        push_test_config(),
    );
    let req = mk_push_request(&account_id, "t-success");
    let uri: axum::http::Uri = "/v1/notify/devices".parse().expect("uri");
    let (method, uri, headers, body) =
        signed_push_json(&account_id, &key_pair, Method::POST, uri, req);
    let resp =
        super::handler_push_register_device(State(app.clone()), method, uri, headers, body).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let bridge = app.push.as_ref().expect("push bridge configured");
    assert_eq!(bridge.device_count(), 1);
}
#[cfg(all(feature = "app_api", feature = "push"))]
#[tokio::test]
async fn push_registration_accepts_account_alias_and_stores_canonical_i105() {
    let (key_pair, canonical_account) = push_test_identity(4);
    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    let app = mk_app_state_for_tests_with_world_and_push(
        world_with_account(&canonical_account),
        push_test_config(),
    );
    let mut req = mk_push_request(&canonical_account, "t-alias");
    bind_account_alias_for_test(&app, &canonical_account, "wallet@universal");
    req.account_id = "wallet@universal".to_string();
    let uri: axum::http::Uri = "/v1/notify/devices".parse().expect("uri");
    let (method, uri, headers, body) =
        signed_push_json(&canonical_account, &key_pair, Method::POST, uri, req);
    let rejected =
        super::handler_push_register_device(State(app.clone()), method, uri, headers, body).await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let error = extract_error(rejected).await;
    assert_eq!(error.code(), "invalid_account");
    assert_eq!(
        app.push
            .as_ref()
            .expect("push bridge configured")
            .device_count(),
        0
    );
    let resolved = routing::resolve_account_alias_with_exact_permission_for_test(
        &app.state,
        &canonical_account,
        "wallet@universal",
    );
    assert_eq!(resolved, canonical_account);
    let mut req = mk_push_request(&resolved, "t-alias");
    req.account_id = resolved.to_string();
    let uri: axum::http::Uri = "/v1/notify/devices".parse().expect("uri");
    let (method, uri, headers, body) =
        signed_push_json(&canonical_account, &key_pair, Method::POST, uri, req);
    let resp =
        super::handler_push_register_device(State(app.clone()), method, uri, headers, body).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let bridge = app.push.as_ref().expect("push bridge configured");
    let device = bridge
        .registered_device("t-alias")
        .expect("registered device should exist");
    assert_eq!(device.account_id, canonical_account.to_string());
}
#[cfg(all(feature = "app_api", feature = "push"))]
#[tokio::test]
async fn push_device_writes_authenticate_before_media_and_body_decode() {
    let (_key_pair, account_id) = push_test_identity(5);
    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    let app = mk_app_state_for_tests_with_world_and_push(
        world_with_account(&account_id),
        push_test_config(),
    );
    let register = super::handler_push_register_device(
        State(app.clone()),
        Method::POST,
        "/v1/notify/devices".parse().expect("uri"),
        HeaderMap::new(),
        axum::body::Bytes::from_static(b"{malformed"),
    )
    .await;
    let unregister = super::handler_push_unregister_device(
        State(app),
        Method::DELETE,
        "/v1/notify/devices".parse().expect("uri"),
        HeaderMap::new(),
        axum::body::Bytes::from_static(b"{malformed"),
    )
    .await;
    for response in [register, unregister] {
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let error = extract_error(response).await;
        assert_eq!(error.code(), "push_auth_required");
    }
}
#[cfg(all(feature = "app_api", feature = "push"))]
#[tokio::test]
async fn push_registration_rejects_body_account_mismatch_without_mutation() {
    let (signer_keys, signer) = push_test_identity(0x51);
    let (_other_keys, other) = push_test_identity(0x52);
    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id).build(&signer);
    let world = World::with(
        [domain],
        [
            Account::new(signer.clone()).build(&signer),
            Account::new(other.clone()).build(&signer),
        ],
        [],
    );
    let app = mk_app_state_for_tests_with_world_and_push(world, push_test_config());
    let request = mk_push_request(&other, "t-mismatch");
    let uri: axum::http::Uri = "/v1/notify/devices".parse().expect("uri");
    let (method, uri, headers, body) =
        signed_push_json(&signer, &signer_keys, Method::POST, uri, request);
    let response =
        super::handler_push_register_device(State(app.clone()), method, uri, headers, body).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let error = extract_error(response).await;
    assert_eq!(error.code(), "push_account_mismatch");
    assert_eq!(
        app.push
            .as_ref()
            .expect("push bridge configured")
            .device_count(),
        0
    );
}
#[cfg(all(feature = "app_api", feature = "push"))]
#[tokio::test]
async fn push_unregister_removes_device() {
    let (key_pair, account_id) = push_test_identity(6);
    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    let app = mk_app_state_for_tests_with_world_and_push(
        world_with_account(&account_id),
        push_test_config(),
    );
    let uri: axum::http::Uri = "/v1/notify/devices".parse().expect("uri");
    let req = mk_push_request(&account_id, "t-remove");
    let (method, signed_uri, headers, body) = signed_push_json(
        &account_id,
        &key_pair,
        Method::POST,
        uri.clone(),
        req.clone(),
    );
    let resp =
        super::handler_push_register_device(State(app.clone()), method, signed_uri, headers, body)
            .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let (method, signed_uri, headers, body) =
        signed_push_json(&account_id, &key_pair, Method::DELETE, uri, req);
    let resp = super::handler_push_unregister_device(
        State(app.clone()),
        method,
        signed_uri,
        headers,
        body,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let bridge = app.push.as_ref().expect("push bridge configured");
    assert_eq!(bridge.device_count(), 0);
}
fn make_signed_block(
    height: u64,
    prev_hash: Option<HashOf<BlockHeader>>,
) -> (SignedBlock, HashOf<TransactionEntrypoint>) {
    let keypair = checked_torii_test_ed25519_keypair(0x24, "derive Torii block-header fixture key");
    let authority = AccountId::new(keypair.public_key().clone());
    let tx = checked_torii_test_transaction(
        TransactionBuilder::new(
            signed_query_test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        ),
        &keypair,
        "sign Torii block-header fixture transaction",
    );
    let entry_hash = tx.hash_as_entrypoint();
    let header = BlockHeader::new(NonZeroU64::new(height).unwrap(), prev_hash, None, 0, 0);
    let mut builder = iroha_data_model::block::builder::BlockBuilder::new(header);
    builder.push_transaction(tx);
    let mut block = builder.build_with_signature(0, keypair.private_key());
    crate::test_utils::attach_fixture_execution_outputs(
        &mut block,
        vec![
            iroha_data_model::block::execution_output::ExecutionOutputV1::Network(
                iroha_data_model::block::execution_output::NetworkExecutionOutputV1 {
                    input_index: 0,
                    result: iroha_data_model::transaction::TransactionResult::new(Ok(vec![])),
                    completions: vec![],
                },
            ),
        ],
    );
    (block, entry_hash)
}
struct PersistedDataTriggerCompletionBlock {
    block: SignedBlock,
    tx_hash: HashOf<SignedTransaction>,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
    trigger_execution_hash: HashOf<TransactionEntrypoint>,
    trigger_id: TriggerId,
}
fn make_persisted_data_trigger_completion_block(
    height: u64,
    prev_hash: Option<HashOf<BlockHeader>>,
) -> PersistedDataTriggerCompletionBlock {
    use iroha_data_model::block::execution_output::{
        ExecutionOutputV1, InvocationCompletionV1, NetworkExecutionOutputV1,
    };
    let (mut block, entrypoint_hash) = make_signed_block(height, prev_hash);
    let tx_hash = block.external_transactions().next().unwrap().hash();
    let trigger_execution_hash = block
        .network_entrypoint_at(0)
        .unwrap()
        .execution_call_hash();
    let trigger_id: TriggerId = "persisted_data_trigger".parse().unwrap();
    let step = DataTriggerStep {
        id: trigger_id.clone(),
        instructions: ExecutionStep(ConstVec::new_empty()),
    };
    crate::test_utils::attach_fixture_execution_outputs(
        &mut block,
        vec![ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
            input_index: 0,
            result: iroha_data_model::transaction::TransactionResult::new(Ok(vec![step])),
            completions: vec![InvocationCompletionV1 {
                trigger_id: trigger_id.clone(),
                callback_index: 0,
                outcome: TriggerCompletedOutcome::Success,
            }],
        })],
    );
    PersistedDataTriggerCompletionBlock {
        block,
        tx_hash,
        entrypoint_hash,
        trigger_execution_hash,
        trigger_id,
    }
}

fn make_sealed_reveal_block(
    height: u64,
    prev_hash: Option<HashOf<BlockHeader>>,
) -> (SignedBlock, HashOf<TransactionEntrypoint>) {
    let keypair =
        checked_torii_test_ed25519_keypair(0x26, "derive Torii sealed-reveal fixture key");
    let network_id = signed_query_test_network_id();
    let authority = AccountId::new(keypair.public_key().clone());
    let tx = checked_torii_test_transaction(
        TransactionBuilder::new(
            network_id,
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        ),
        &keypair,
        "sign Torii sealed-reveal fixture transaction",
    );
    let salt = [0xA7; 32];
    let commitment = compute_sealed_transaction_commitment(&network_id, &tx, salt, height + 2);
    let reveal = SealedTransactionReveal::new(commitment, tx.clone(), salt);
    let entrypoint = TransactionEntrypoint::SealedReveal(reveal);
    let entry_hash = entrypoint.hash();
    let header = BlockHeader::new(NonZeroU64::new(height).unwrap(), prev_hash, None, 0, 0);
    let mut builder = iroha_data_model::block::builder::BlockBuilder::new(header);
    let TransactionEntrypoint::SealedReveal(reveal) = entrypoint else {
        unreachable!()
    };
    builder.push_sealed_transaction_reveal(reveal);
    let mut block = builder.build_with_signature(0, keypair.private_key());
    crate::test_utils::attach_fixture_execution_outputs(
        &mut block,
        vec![
            iroha_data_model::block::execution_output::ExecutionOutputV1::Network(
                iroha_data_model::block::execution_output::NetworkExecutionOutputV1 {
                    input_index: 0,
                    result: iroha_data_model::transaction::TransactionResult::new(Ok(vec![])),
                    completions: vec![],
                },
            ),
        ],
    );
    (block, entry_hash)
}
fn store_block(app: &SharedAppState, block: SignedBlock) -> HashOf<BlockHeader> {
    let hash = block.hash();
    app.kura
        .store_block(
            iroha_data_model::block::SharedSignedBlock::try_new(
                block,
                &app.state.ivm_execution_budget(),
            )
            .expect("fund original fixture block"),
        )
        .expect("store block");
    hash
}
#[expect(
    clippy::large_types_passed_by_value,
    reason = "The fixture transfers its header into the committed header cache."
)]
fn record_committed_block_hash_for_test(
    app: &SharedAppState,
    header: BlockHeader,
    block_hash: HashOf<BlockHeader>,
) {
    let mut block_hashes = app.state.block_hashes.block();
    block_hashes.push_for_tests(block_hash);
    block_hashes.commit_for_tests();
    app.state.update_latest_block_header_cache_for_tests(header);
}
fn make_empty_signed_block(
    height: u64,
    prev_hash: Option<HashOf<BlockHeader>>,
    creation_time_ms: u64,
) -> SignedBlock {
    let keypair = checked_torii_test_ed25519_keypair(0x27, "derive Torii empty-header fixture key");
    let header = BlockHeader::new(
        NonZeroU64::new(height).unwrap(),
        prev_hash,
        None,
        creation_time_ms,
        0,
    );
    let mut block = iroha_data_model::block::builder::BlockBuilder::new(header)
        .build_with_signature(0, keypair.private_key());
    crate::test_utils::attach_fixture_execution_outputs(&mut block, vec![]);
    block
}

pub fn record_latest_committed_header_for_test(
    app: &SharedAppState,
    height: u64,
    creation_time_ms: u64,
) {
    let durable_blocks_count = app
        .kura
        .exact_durable_blocks_count()
        .expect("test Kura durable boundary must remain readable");
    assert_eq!(
        app.state.committed_height(),
        durable_blocks_count,
        "test block hash journal must match durable Kura height before appending headers"
    );
    let durable_height = u64::try_from(durable_blocks_count).expect("durable height fits into u64");
    assert!(
        height > durable_height,
        "latest test header height must advance durable Kura height"
    );
    let mut prev_hash = NonZeroUsize::new(durable_height.try_into().expect("height fits usize"))
        .and_then(|height| {
            app.kura
                .get_block(height, &app.state.ivm_execution_budget())
                .expect("admit existing fixture block")
        })
        .map(|block| block.hash());
    let mut block_hashes = app.state.block_hashes.block();
    let mut latest_header = None;
    for next_height in durable_height.saturating_add(1)..=height {
        let timestamp = if next_height == height {
            creation_time_ms
        } else {
            0
        };
        let block = make_empty_signed_block(next_height, prev_hash, timestamp);
        latest_header = Some(block.header());
        let hash = store_block(app, block);
        block_hashes.push_for_tests(hash);
        prev_hash = Some(hash);
    }
    block_hashes.commit_for_tests();
    if let Some(header) = latest_header {
        app.state.update_latest_block_header_cache_for_tests(header);
    }
}
