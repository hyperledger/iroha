#[cfg(feature = "connect")]
#[tokio::test]
async fn torii_proxy_snapshot_roundtrips_status_headers_and_body() {
    let mut response = Response::new(Body::from("proxied-body"));
    *response.status_mut() = StatusCode::ACCEPTED;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain"),
    );
    response.headers_mut().insert(
        axum::http::HeaderName::from_static("x-iroha-routed-by"),
        HeaderValue::from_static("proxy"),
    );
    let snapshot = super::response_to_torii_proxy_snapshot(response, usize::MAX).await;
    let restored = super::torii_proxy_snapshot_to_response(snapshot);
    let headers = restored.headers().clone();
    assert_eq!(restored.status(), StatusCode::ACCEPTED);
    assert_eq!(
        headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/plain")
    );
    assert_eq!(
        headers
            .get("x-iroha-routed-by")
            .and_then(|value| value.to_str().ok()),
        Some("proxy")
    );
    let body = axum::body::to_bytes(restored.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    assert_eq!(body.as_ref(), b"proxied-body");
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn torii_proxy_snapshot_caps_buffered_response_bodies() {
    for max_body_bytes in [1, 4] {
        let response = Response::new(Body::from("proxied-body"));
        let snapshot = super::response_to_torii_proxy_snapshot(response, max_body_bytes).await;
        assert_eq!(snapshot.status_code, StatusCode::BAD_GATEWAY.as_u16());
        assert_eq!(snapshot.body.len(), max_body_bytes);
        super::validate_torii_proxy_snapshot_bounds(&snapshot, max_body_bytes)
            .expect("bounded body diagnostic must remain a valid proxy snapshot");
    }
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn torii_proxy_snapshot_does_not_format_arbitrary_body_errors() {
    #[derive(Debug)]
    struct PanicOnDisplay;
    impl core::fmt::Display for PanicOnDisplay {
        fn fmt(&self, _formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            panic!("proxy snapshot boundary must not format an arbitrary body error")
        }
    }
    impl std::error::Error for PanicOnDisplay {}

    let stream = futures::stream::once(async {
        Result::<axum::body::Bytes, PanicOnDisplay>::Err(PanicOnDisplay)
    });
    let response = Response::new(Body::from_stream(stream));
    let snapshot = super::response_to_torii_proxy_snapshot(response, 8).await;
    assert_eq!(snapshot.status_code, StatusCode::BAD_GATEWAY.as_u16());
    assert_eq!(snapshot.body, b"proxied ");
    super::validate_torii_proxy_snapshot_bounds(&snapshot, 8)
        .expect("fixed body-error diagnostic must remain bounded");
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn torii_proxy_snapshot_caps_header_bound_failure_bodies() {
    for max_body_bytes in [1, 4] {
        let mut response = Response::new(Body::empty());
        for index in 0..=super::TORII_PROXY_MAX_HEADERS_V1 {
            let name =
                axum::http::HeaderName::from_bytes(format!("x-proxy-bound-{index}").as_bytes())
                    .expect("valid test header name");
            response
                .headers_mut()
                .insert(name, HeaderValue::from_static("value"));
        }
        let snapshot = super::response_to_torii_proxy_snapshot(response, max_body_bytes).await;
        assert_eq!(snapshot.status_code, StatusCode::BAD_GATEWAY.as_u16());
        assert!(snapshot.headers.is_empty());
        assert_eq!(snapshot.body.len(), max_body_bytes);
        super::validate_torii_proxy_snapshot_bounds(&snapshot, max_body_bytes)
            .expect("bounded header diagnostic must remain a valid proxy snapshot");
    }
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn torii_proxy_snapshot_restore_drops_invalid_headers_and_status() {
    let snapshot = ToriiProxyHttpResponseV1 {
        status_code: 99,
        headers: vec![
            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                name: "x-valid-proxy-header".to_owned(),
                value: b"kept".to_vec(),
            },
            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                name: "bad header".to_owned(),
                value: b"dropped".to_vec(),
            },
            iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                name: "x-invalid-value".to_owned(),
                value: b"bad\nvalue".to_vec(),
            },
        ],
        body: b"restored".to_vec(),
    };
    let restored = super::torii_proxy_snapshot_to_response(snapshot);
    assert_eq!(restored.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        restored
            .headers()
            .get("x-valid-proxy-header")
            .and_then(|value| value.to_str().ok()),
        Some("kept")
    );
    assert!(restored.headers().get("bad header").is_none());
    assert!(restored.headers().get("x-invalid-value").is_none());
    let body = axum::body::to_bytes(restored.into_body(), usize::MAX)
        .await
        .expect("restored body");
    assert_eq!(body.as_ref(), b"restored");
}
#[cfg(feature = "connect")]
#[test]
fn torii_proxy_header_conversion_preserves_duplicates_and_skips_invalid() {
    let mut headers = HeaderMap::new();
    headers.append(
        axum::http::HeaderName::from_static("x-repeat"),
        HeaderValue::from_static("one"),
    );
    headers.append(
        axum::http::HeaderName::from_static("x-repeat"),
        HeaderValue::from_static("two"),
    );
    headers.insert(
        axum::http::HeaderName::from_static("x-single"),
        HeaderValue::from_static("kept"),
    );
    let mut proxy_headers = super::header_map_to_torii_proxy_headers(&headers);
    proxy_headers.push(iroha_core::torii_proxy::ToriiProxyHeaderV1 {
        name: "bad header".to_owned(),
        value: b"dropped".to_vec(),
    });
    proxy_headers.push(iroha_core::torii_proxy::ToriiProxyHeaderV1 {
        name: "x-bad-value".to_owned(),
        value: b"bad\r\nvalue".to_vec(),
    });
    let restored = super::torii_proxy_headers_to_header_map(&proxy_headers);
    let repeated = restored
        .get_all("x-repeat")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>();
    assert_eq!(repeated, vec!["one", "two"]);
    assert_eq!(
        restored
            .get("x-single")
            .and_then(|value| value.to_str().ok()),
        Some("kept")
    );
    assert!(restored.get("bad header").is_none());
    assert!(restored.get("x-bad-value").is_none());
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn torii_proxy_snapshot_accepts_exact_limit_and_preserves_headers() {
    let mut response = Response::new(Body::from("four"));
    *response.status_mut() = StatusCode::CREATED;
    response.headers_mut().insert(
        axum::http::HeaderName::from_static("x-proxy-test"),
        HeaderValue::from_static("kept"),
    );
    let snapshot = super::response_to_torii_proxy_snapshot(response, 4).await;
    assert_eq!(snapshot.status_code, StatusCode::CREATED.as_u16());
    assert_eq!(snapshot.body, b"four");
    assert!(
        snapshot
            .headers
            .iter()
            .any(|header| { header.name == "x-proxy-test" && header.value.as_slice() == b"kept" }),
        "exact-limit responses should keep proxied headers"
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn reqwest_torii_proxy_snapshot_caps_buffered_bridge_response_bodies() {
    let upstream = axum::Router::new().route(
        "/oversized",
        axum::routing::get(|| async { Response::new(Body::from("proxied-body")) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let addr = listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream.into_make_service())
            .await
            .expect("serve upstream");
    });
    let response = reqwest::get(format!("http://{addr}/oversized"))
        .await
        .expect("fetch upstream response");
    assert_eq!(response.content_length(), Some(12));
    let error = match super::reqwest_response_to_torii_proxy_snapshot(response, 4).await {
        Ok(_) => panic!("expected capped response error"),
        Err(error) => error,
    };
    upstream_task.abort();
    assert_eq!(
        error, "authoritative HTTP bridge response Content-Length exceeds the 4-byte limit",
        "declared oversized bodies must fail before buffering"
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn reqwest_torii_proxy_snapshot_accepts_exact_limit_bridge_response() {
    let upstream = axum::Router::new().route(
        "/exact",
        axum::routing::get(|| async {
            let mut response = Response::new(Body::from("four"));
            *response.status_mut() = StatusCode::PARTIAL_CONTENT;
            response.headers_mut().insert(
                axum::http::HeaderName::from_static("x-upstream-test"),
                HeaderValue::from_static("kept"),
            );
            response
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let addr = listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream.into_make_service())
            .await
            .expect("serve upstream");
    });
    let response = reqwest::get(format!("http://{addr}/exact"))
        .await
        .expect("fetch upstream response");
    let snapshot = super::reqwest_response_to_torii_proxy_snapshot(response, 4)
        .await
        .expect("exact-limit response should be accepted");
    upstream_task.abort();
    assert_eq!(snapshot.status_code, StatusCode::PARTIAL_CONTENT.as_u16());
    assert_eq!(snapshot.body, b"four");
    assert!(
        snapshot.headers.iter().any(|header| {
            header.name == "x-upstream-test" && header.value.as_slice() == b"kept"
        }),
        "exact-limit bridge responses should keep proxied headers"
    );
}
#[cfg(feature = "connect")]
#[test]
fn torii_proxy_response_body_limit_caps_hosted_http_and_submission_responses() {
    let mut app = mk_app_state_for_tests();
    let app_mut = Arc::get_mut(&mut app).expect("unique app state");
    app_mut.soracloud_public_max_response_bytes = 0;
    app_mut.transaction_max_content_len = 1;
    let route = RoutingDecision::new(LaneId::new(9), DataSpaceId::new(12));
    let hosted_request = ToriiProxyRequestKindV1::HostedHttp(ToriiHostedHttpProxyRequestV1 {
        service_name: "svc".to_owned(),
        service_version: "v1".to_owned(),
        replica_slot: 1,
        request_path: "/health".to_owned(),
        method: "GET".to_owned(),
        query_string: None,
        headers: Vec::new(),
        body: Vec::new(),
        remote_ip: None,
    });
    let query_request = ToriiProxyRequestKindV1::SignedQueryRouteScan {
        query_bytes: Vec::new(),
        expected_route: ToriiRouteHintV1::from(route),
        response_format: ToriiProxyResponseFormatV1::Norito,
    };
    let single_route_query_request = ToriiProxyRequestKindV1::SignedQuery {
        query_bytes: Vec::new(),
        expected_route: ToriiRouteHintV1::from(route),
        response_format: ToriiProxyResponseFormatV1::Norito,
    };
    let fanout_request = ToriiProxyRequestKindV1::SignedQueryFanout {
        query_bytes: Vec::new(),
        response_format: ToriiProxyResponseFormatV1::Norito,
    };
    let query_envelope =
        QueryFanoutMemoryEnvelope::for_body_admission(app.query_fanout_working_set_bytes)
            .expect("test query memory geometry should fit");
    let key = checked_torii_test_ed25519_keypair(0xaa, "native proxy response budget");
    let transaction = signed_log_transaction_for_test(
        *app.state.network_id_ref(),
        AccountId::new(key.public_key().clone()),
        "native submission response budget",
        &key,
    );
    let submit_request = ToriiProxyRequestKindV1::SubmitTransaction {
        transaction: TransactionEntrypoint::External(transaction),
        expected_plan: ToriiRoutingPlanHintV1::from(RoutingPlan::single(route)),
    };
    assert_eq!(
        super::torii_proxy_response_body_limit(app.as_ref(), &hosted_request),
        1,
        "hosted HTTP proxy responses clamp zero config to a one-byte cap"
    );
    assert_eq!(
        super::torii_proxy_response_body_limit(app.as_ref(), &query_request),
        query_envelope.route_body_bytes,
        "one route-scan snapshot must fit the admitted raw-route phase"
    );
    assert_eq!(
        super::torii_proxy_response_body_limit(app.as_ref(), &single_route_query_request),
        query_envelope.route_body_bytes,
        "one remote single-route query must stay inside its held raw-route phase"
    );
    assert_eq!(
        super::torii_proxy_response_body_limit(app.as_ref(), &fanout_request),
        query_envelope.final_body_bytes,
        "a final fanout snapshot must fit the admitted final-body phase"
    );
    assert_eq!(
        super::torii_proxy_response_body_limit(app.as_ref(), &submit_request),
        TORII_PROXY_RETRYABLE_RETAINED_BODY_BYTES_V1,
        "native submission responses retain a bounded protocol budget even when the public transaction cap is smaller"
    );
}
#[cfg(feature = "connect")]
#[test]
fn torii_proxy_retry_policy_only_retries_gateway_class_statuses() {
    assert!(super::should_retry_torii_proxy_status(
        StatusCode::BAD_GATEWAY
    ));
    assert!(super::should_retry_torii_proxy_status(
        StatusCode::SERVICE_UNAVAILABLE
    ));
    assert!(super::should_retry_torii_proxy_status(
        StatusCode::GATEWAY_TIMEOUT
    ));
    assert!(!super::should_retry_torii_proxy_status(
        StatusCode::TOO_MANY_REQUESTS
    ));
    assert!(!super::should_retry_torii_proxy_status(
        StatusCode::INTERNAL_SERVER_ERROR
    ));
}
#[cfg(feature = "connect")]
#[test]
fn generic_torii_proxy_retry_policy_requires_exact_capacity_429() {
    let snapshot = |status: StatusCode, reject_codes: &[&str]| ToriiProxyHttpResponseV1 {
        status_code: status.as_u16(),
        headers: reject_codes
            .iter()
            .map(|code| iroha_core::torii_proxy::ToriiProxyHeaderV1 {
                name: "x-iroha-reject-code".to_owned(),
                value: code.as_bytes().to_vec(),
            })
            .collect(),
        body: Vec::new(),
    };

    assert!(super::should_retry_generic_torii_proxy_snapshot(&snapshot(
        StatusCode::TOO_MANY_REQUESTS,
        &["proxy_capacity_exceeded"]
    )));
    assert!(!super::should_retry_generic_torii_proxy_snapshot(
        &snapshot(StatusCode::TOO_MANY_REQUESTS, &[])
    ));
    assert!(!super::should_retry_generic_torii_proxy_snapshot(
        &snapshot(StatusCode::TOO_MANY_REQUESTS, &["rate_limited"])
    ));
    assert!(!super::should_retry_generic_torii_proxy_snapshot(
        &snapshot(
            StatusCode::TOO_MANY_REQUESTS,
            &["proxy_capacity_exceeded", "proxy_capacity_exceeded"]
        )
    ));
    assert!(super::should_retry_generic_torii_proxy_snapshot(&snapshot(
        StatusCode::SERVICE_UNAVAILABLE,
        &[]
    )));
}
#[cfg(feature = "connect")]
#[test]
fn torii_proxy_hosted_http_request_kind_uses_route_timeout() {
    let hosted_request = ToriiProxyRequestKindV1::HostedHttp(ToriiHostedHttpProxyRequestV1 {
        service_name: "svc".to_owned(),
        service_version: "v1".to_owned(),
        replica_slot: 1,
        request_path: "/health".to_owned(),
        method: "GET".to_owned(),
        query_string: Some("ready=true".to_owned()),
        headers: Vec::new(),
        body: Vec::new(),
        remote_ip: Some("127.0.0.1".to_owned()),
    });
    assert_eq!(
        super::torii_proxy_attempt_timeout(&hosted_request),
        DEFAULT_ROUTE_TIMEOUT
    );
    assert_eq!(
        super::torii_proxy_request_kind_name(&hosted_request),
        "hosted_http"
    );
}
#[cfg(feature = "connect")]
#[test]
fn torii_proxy_attempt_timeout_uses_route_budget_for_queries() {
    let route = RoutingDecision::new(LaneId::new(9), DataSpaceId::new(12));
    let query_request = ToriiProxyRequestKindV1::SignedQueryRouteScan {
        query_bytes: Vec::new(),
        expected_route: ToriiRouteHintV1::from(route),
        response_format: ToriiProxyResponseFormatV1::Norito,
    };
    assert_eq!(
        super::torii_proxy_attempt_timeout(&query_request),
        DEFAULT_ROUTE_TIMEOUT
    );
    assert_eq!(
        super::torii_proxy_request_kind_name(&query_request),
        "signed_query_route_scan"
    );
    let keypair =
        checked_torii_test_ed25519_keypair(0xfc, "derive proxy submit timeout fixture key");
    let authority = AccountId::new(keypair.public_key().clone());
    let tx = TransactionBuilder::new(
        signed_query_test_network_id(),
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(keypair.private_key());
    let transaction = iroha_data_model::transaction::TransactionEntrypoint::External(tx);
    let expected_plan = ToriiRoutingPlanHintV1::from(RoutingPlan::single(route));
    let submit_request = ToriiProxyRequestKindV1::SubmitTransaction {
        transaction,
        expected_plan,
    };
    assert_eq!(
        super::torii_proxy_attempt_timeout(&submit_request),
        DEFAULT_ROUTE_TIMEOUT
    );
    assert_eq!(
        super::torii_proxy_request_kind_name(&submit_request),
        "submit_transaction"
    );
    let process_session = Hash::new(b"torii-proxy-request-id-test-session");
    let ingress_peer = PeerId::from(keypair.public_key().clone());
    for request in [&query_request, &submit_request] {
        crate::frame_test_support::assert_current_frame(
            request,
            "iroha_core::torii_proxy::ToriiProxyRequestKindV1",
        );
        assert_eq!(
            <super::BorrowedToriiProxyRequestIdPreimage<'static> as norito::NoritoSchema>::nominal_name(),
            "iroha_torii::BorrowedToriiProxyRequestIdPreimage<'_>",
        );
        assert_eq!(
            norito::schema::identity::frame_hash::<
                super::BorrowedToriiProxyRequestIdPreimage<'static>,
            >(),
            norito::schema::identity::frame_hash::<super::OwnedToriiProxyRequestIdPreimage>(),
        );
        let owned = norito::to_bytes(&(
            "torii:proxy:v1",
            process_session.clone(),
            ingress_peer.clone(),
            7_u64,
            request.clone(),
        ))
        .expect("canonical owned request-id preimage");
        let borrowed = norito::to_bytes(&super::BorrowedToriiProxyRequestIdPreimage {
            process_session_id: &process_session,
            local_peer_id: &ingress_peer,
            sequence: 7,
            request,
        })
        .expect("borrowed request-id preimage");
        assert_eq!(
            borrowed, owned,
            "borrowed request-id preimage must match the canonical owned frame"
        );
    }
    assert_ne!(
        super::torii_proxy_request_id_for_session_sequence(
            &process_session,
            &ingress_peer,
            7,
            &submit_request,
        ),
        super::torii_proxy_request_id_for_session_sequence(
            &Hash::new(b"torii-proxy-request-id-restarted-session"),
            &ingress_peer,
            7,
            &submit_request,
        ),
        "a receipt from an earlier process session must not match a request after restart"
    );
    let other_ingress_peer = PeerId::from(
        checked_torii_test_ed25519_keypair(
            0xfb,
            "derive alternate proxy request-id ingress fixture key",
        )
        .public_key()
        .clone(),
    );
    assert_ne!(
        super::torii_proxy_request_id_for_session_sequence(
            &process_session,
            &ingress_peer,
            7,
            &submit_request,
        ),
        super::torii_proxy_request_id_for_session_sequence(
            &process_session,
            &other_ingress_peer,
            7,
            &submit_request,
        ),
        "different ingress peers must not share proxy request identities"
    );
    let first_app = mk_app_state_for_tests();
    let second_app = mk_app_state_for_tests();
    assert_ne!(
        first_app.torii_proxy_session_id, second_app.torii_proxy_session_id,
        "independent AppState instances must use independent OS-random proxy sessions"
    );
    let first_process_request_id =
        super::next_torii_proxy_request_id(&first_app, &ingress_peer, &submit_request)
            .expect("first process sequence must be available");
    let second_process_request_id =
        super::next_torii_proxy_request_id(&second_app, &ingress_peer, &submit_request)
            .expect("second process sequence must be available");
    assert_ne!(
        first_process_request_id, second_process_request_id,
        "restart/process-session separation must hold even at the same sequence"
    );
    first_app
        .torii_proxy_sequence
        .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
    assert!(
        super::next_torii_proxy_request_id(&first_app, &ingress_peer, &submit_request,).is_err(),
        "request sequence exhaustion must fail closed instead of wrapping"
    );
}
#[cfg(feature = "connect")]
#[test]
fn torii_proxy_authenticated_deadline_rejects_expiry_and_excess_horizon() {
    const NOW_UNIX_MS: u64 = 1_900_000_000_000;
    let max_horizon_ms = u64::try_from(super::TORII_PROXY_MAX_DEADLINE_HORIZON.as_millis())
        .expect("fixed proxy deadline horizon fits u64 milliseconds");
    assert_eq!(
        super::torii_proxy_remaining_budget(NOW_UNIX_MS + 1, NOW_UNIX_MS),
        Ok(Duration::from_millis(1))
    );
    assert_eq!(
        super::torii_proxy_remaining_budget(NOW_UNIX_MS + max_horizon_ms, NOW_UNIX_MS),
        Ok(super::TORII_PROXY_MAX_DEADLINE_HORIZON)
    );
    assert_eq!(
        super::TORII_PROXY_MAX_DEADLINE_HORIZON,
        super::TORII_PROXY_EXECUTION_BUDGET + super::TORII_PROXY_DEADLINE_CLOCK_SKEW_ALLOWANCE,
        "the accepted future horizon must be the fixed execution budget plus the audited operator-signature skew allowance"
    );
    assert_eq!(
        super::TORII_PROXY_DEADLINE_CLOCK_SKEW_ALLOWANCE,
        Duration::from_secs(
            iroha_config::parameters::defaults::torii::operator_signatures::MAX_CLOCK_SKEW_SECS,
        ),
        "proxy deadline skew must stay source-coupled to the authenticated HTTP signature contract"
    );
    let sender_deadline = NOW_UNIX_MS
        + u64::try_from(super::TORII_PROXY_EXECUTION_BUDGET.as_millis())
            .expect("fixed proxy execution budget fits u64 milliseconds");
    let receiver_now = NOW_UNIX_MS
        - u64::try_from(super::TORII_PROXY_DEADLINE_CLOCK_SKEW_ALLOWANCE.as_millis())
            .expect("fixed proxy clock-skew allowance fits u64 milliseconds");
    let skew_edge_remaining = super::torii_proxy_remaining_budget(sender_deadline, receiver_now)
        .expect("a fresh sender at the authenticated negative-skew edge must be admitted");
    assert_eq!(skew_edge_remaining, super::TORII_PROXY_MAX_DEADLINE_HORIZON);
    assert_eq!(
        skew_edge_remaining
            .saturating_sub(super::TORII_PROXY_RESPONSE_EGRESS_RESERVE)
            .min(super::TORII_PROXY_EXECUTION_BUDGET),
        super::TORII_PROXY_EXECUTION_BUDGET,
        "clock-skew admission must not extend the receiver's local monotonic execution lifetime"
    );
    assert!(super::torii_proxy_remaining_budget(NOW_UNIX_MS, NOW_UNIX_MS).is_err());
    assert!(super::torii_proxy_remaining_budget(NOW_UNIX_MS - 1, NOW_UNIX_MS).is_err());
    assert!(
        super::torii_proxy_remaining_budget(NOW_UNIX_MS + max_horizon_ms + 1, NOW_UNIX_MS).is_err()
    );
}

#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread")]
async fn certified_transaction_batch_invalid_later_signature_does_not_admit_prefix() {
    let (app, key, _, _) = lifecycle_ordinary_fixture(true);
    let tx1 = lifecycle_ordinary_transaction(
        &app,
        &key,
        vec![Log::new(Level::INFO, "valid prefix".into()).into()],
    );
    let valid_second = lifecycle_ordinary_transaction(
        &app,
        &key,
        vec![Log::new(Level::INFO, "invalid later".into()).into()],
    );
    let tx2 = transaction_with_invalid_signature_for_test(valid_second);
    let error = super::handler_post_transactions_batch(
        State(app.clone()),
        HeaderMap::new(),
        transaction_batch_body_for_test(
            [&tx1, &tx2]
                .into_iter()
                .map(iroha_version::codec::EncodeVersioned::encode_versioned)
                .collect(),
        ),
    )
    .await
    .expect_err("invalid later signature rejects before any dispatch");
    let response = error.into_response();
    assert_eq!(
        torii_response_header(&response, "x-iroha-reject-code"),
        Some(SignatureRejectionCode::InvalidSignature.as_str())
    );
    assert_eq!(app.queue.active_len(), 0);
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn torii_delegated_reads_reject_online_only_observers() {
    let mut app = mk_app_state_for_tests_with_world(world_with_account(&ALICE_ID));
    let observer_key = checked_torii_test_ed25519_keypair(0xb9, "online observer fixture");
    let observer = PeerId::from(observer_key.public_key().clone());
    let local = checked_torii_test_peer_id(0xba, "authorized local ingress fixture");
    let current = checked_torii_test_peer_id(0xbb, "authorized current ingress fixture");
    let previous = checked_torii_test_peer_id(0xbc, "authorized previous ingress fixture");
    let (_online_tx, online_rx) = tokio::sync::watch::channel(HashSet::from([Peer::new(
        "127.0.0.1:18104".parse().expect("observer address"),
        observer_key.public_key().clone(),
    )]));
    {
        let app = Arc::get_mut(&mut app).expect("unique observer fixture");
        app.online_peers = OnlinePeersProvider::new(online_rx);
        app.local_peer_id = Some(local.clone());
        let mut topology = app.state.commit_topology.block();
        topology.push(current.clone());
        topology.commit();
        let mut topology = app.state.prev_commit_topology.block();
        topology.push(previous.clone());
        topology.commit();
    }
    assert!(!super::torii_proxy_authenticated_peer_is_trusted(
        app.as_ref(),
        &observer
    ));
    for trusted in [&local, &current, &previous] {
        assert!(super::torii_proxy_authenticated_peer_is_trusted(
            app.as_ref(),
            trusted
        ));
    }
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let scope = ToriiFanoutRouteScopeV1::VisibleAccount {
        caller_account_id: Some(ALICE_ID.to_string()),
    };
    let body =
        norito::json::to_vec(&norito::json!({"authority": (ALICE_ID.to_string()), "items": []}))
            .expect("view body");
    let read = super::torii_read_request(
        ToriiReadEndpointV1::ContractViewBatchPost,
        scope.clone(),
        route,
        Vec::new(),
        None,
        body.clone(),
    );
    let fanout = iroha_core::torii_proxy::ToriiReadFanoutProxyRequestV1 {
        endpoint: ToriiReadEndpointV1::AccountGet,
        route_scope: scope,
        merge: iroha_core::torii_proxy::ToriiReadFanoutMergeV1::Account,
        path_args: vec![ALICE_ID.to_string()],
        query_string: None,
        body: Vec::new(),
        response_format: ToriiProxyResponseFormatV1::Json,
    };
    for kind in [
        ToriiProxyRequestKindV1::Read(read.clone()),
        ToriiProxyRequestKindV1::ReadFanout(fanout),
    ] {
        for sender in [None, Some(observer.clone())] {
            let request = ToriiProxyRequestV1 {
                schema_version: TORII_PROXY_REQUEST_VERSION_V1,
                request_id: Hash::new(b"untrusted-read-observer"),
                deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
                hop_count: 1,
                max_hops: TORII_PROXY_DEFAULT_MAX_HOPS,
                visited_peer_ids: vec![observer.clone()],
                request: kind.clone(),
            };
            let response = super::execute_incoming_torii_proxy_request(&app, request, sender).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                response
                    .headers()
                    .get("x-iroha-reject-code")
                    .and_then(|value| value.to_str().ok()),
                Some("untrusted_proxy_ingress")
            );
        }
    }
    let request = ToriiProxyRequestV1 {
        schema_version: TORII_PROXY_REQUEST_VERSION_V1,
        request_id: Hash::new(b"authorized-read-ingress"),
        deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
        hop_count: 1,
        max_hops: TORII_PROXY_DEFAULT_MAX_HOPS,
        visited_peer_ids: vec![local.clone()],
        request: ToriiProxyRequestKindV1::Read(read),
    };
    let response = super::execute_incoming_torii_proxy_request(&app, request, Some(local)).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "authorized ingress must reach ordinary empty-batch validation"
    );
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn incoming_torii_proxy_rejects_malformed_v1_hop_chain_before_dispatch() {
    let mut app = mk_app_state_for_tests_with_world(world_with_account(&ALICE_ID));
    let sender = PeerId::new(
        checked_torii_test_ed25519_keypair(
            0xd9,
            "derive malformed-hop authenticated sender fixture key",
        )
        .public_key()
        .clone(),
    );
    let local_peer = PeerId::new(
        checked_torii_test_ed25519_keypair(0xda, "derive malformed-hop local peer fixture key")
            .public_key()
            .clone(),
    );
    Arc::get_mut(&mut app)
        .expect("malformed-hop fixture app must be uniquely owned")
        .local_peer_id = Some(local_peer.clone());
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let base_request = ToriiProxyRequestV1 {
        schema_version: TORII_PROXY_REQUEST_VERSION_V1,
        request_id: Hash::new(b"malformed-v1-hop-chain"),
        deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
        hop_count: 1,
        max_hops: TORII_PROXY_DEFAULT_MAX_HOPS,
        visited_peer_ids: vec![sender.clone()],
        request: ToriiProxyRequestKindV1::Read(super::torii_read_request(
            ToriiReadEndpointV1::AccountGet,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            route,
            vec![ALICE_ID.to_string()],
            None,
            Vec::new(),
        )),
    };
    let mut malformed = Vec::new();
    let mut zero_hops = base_request.clone();
    zero_hops.hop_count = 0;
    malformed.push(("zero_hops", zero_hops, Some(sender.clone())));
    let mut oversized_budget = base_request.clone();
    oversized_budget.max_hops = TORII_PROXY_DEFAULT_MAX_HOPS.saturating_add(1);
    malformed.push(("oversized_budget", oversized_budget, Some(sender.clone())));
    let mut length_mismatch = base_request.clone();
    length_mismatch.hop_count = 2;
    malformed.push(("length_mismatch", length_mismatch, Some(sender.clone())));
    let mut duplicate_history = base_request.clone();
    duplicate_history.hop_count = 2;
    duplicate_history.visited_peer_ids.push(sender.clone());
    malformed.push(("duplicate_history", duplicate_history, Some(sender.clone())));
    malformed.push((
        "sender_mismatch",
        base_request.clone(),
        Some(local_peer.clone()),
    ));
    let mut receiver_revisit = base_request.clone();
    receiver_revisit.hop_count = 2;
    receiver_revisit.visited_peer_ids = vec![local_peer.clone(), sender.clone()];
    malformed.push((
        "receiver_revisit_before_local_dispatch",
        receiver_revisit,
        Some(sender.clone()),
    ));
    for (label, request, authenticated_sender) in malformed {
        let response =
            super::execute_incoming_torii_proxy_request(&app, request, authenticated_sender).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{label} must fail before read dispatch"
        );
        assert_eq!(app.queue.active_len(), 0);
    }
    let mut revisit = base_request;
    revisit.visited_peer_ids = vec![local_peer];
    let response = super::forward_incoming_torii_proxy_request(&app, &sender, route, revisit).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(app.queue.active_len(), 0);
}
#[cfg(feature = "connect")]
#[test]
fn effective_proxy_routing_decision_prefers_receiver_recomputed_route() {
    let ingress_hint = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let resolved_route = RoutingDecision::new(LaneId::new(2), DataSpaceId::new(10));
    assert_eq!(
        super::effective_proxy_routing_decision("verified_query", resolved_route, ingress_hint),
        resolved_route
    );
}
#[cfg(feature = "connect")]
#[test]
fn proxy_signed_query_decode_requires_valid_signature_and_exact_bytes() {
    let key_pair =
        checked_torii_test_ed25519_keypair(0xfd, "derive signed proxy query fixture key");
    let authority = AccountId::new(key_pair.public_key().clone());
    let signed_query = signed_find_triggers_query_for_test(authority.clone(), &key_pair);
    let query_bytes = iroha_version::codec::EncodeVersioned::encode_versioned(&signed_query);
    let admission = signed_query_test_admission();
    let limits =
        super::QueryFanoutMemoryEnvelope::decode_limits_for(query_bytes.len(), 1024 * 1024)
            .expect("test proxy decode limits");
    let Err(capacity_response) = super::decode_verified_proxy_signed_query(
        &query_bytes,
        "test proxy",
        admission.as_ref(),
        norito::DecodeLimits::new(0, 0, 0, 0, 0),
        super::ProxySignedQueryReplayScope::Client,
    ) else {
        panic!("a proxy signed query must obey its decode allocation ceiling");
    };
    assert_eq!(capacity_response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let verified = super::decode_verified_proxy_signed_query(
        &query_bytes,
        "test proxy",
        admission.as_ref(),
        limits,
        super::ProxySignedQueryReplayScope::Client,
    )
    .expect("the original signed query should verify");
    assert_eq!(verified.authority, authority);
    let mut forged_authority =
        <SignedQuery as iroha_version::codec::DecodeVersioned>::decode_all_versioned(&query_bytes)
            .expect("signed proxy query should round-trip");
    forged_authority.payload.authority = AccountId::new(
        checked_torii_test_ed25519_keypair(
            0xfe,
            "derive forged signed proxy query authority fixture key",
        )
        .public_key()
        .clone(),
    );
    assert!(
        super::decode_verified_proxy_signed_query(
            &iroha_version::codec::EncodeVersioned::encode_versioned(&forged_authority),
            "test proxy",
            admission.as_ref(),
            limits,
            super::ProxySignedQueryReplayScope::Client,
        )
        .is_err(),
        "a peer cannot replace the client authority after signing",
    );
    let mut forged_request = signed_query;
    forged_request.payload.request = iroha_data_model::query::QueryRequest::Start(
        build_find_active_trigger_ids_query_for_test(),
    );
    assert!(
        super::decode_verified_proxy_signed_query(
            &iroha_version::codec::EncodeVersioned::encode_versioned(&forged_request),
            "test proxy",
            admission.as_ref(),
            limits,
            super::ProxySignedQueryReplayScope::Client,
        )
        .is_err(),
        "a peer cannot replace the signed query payload",
    );
    let mut trailing = query_bytes;
    trailing.push(0);
    let Err(response) = super::decode_verified_proxy_signed_query(
        &trailing,
        "test proxy",
        admission.as_ref(),
        limits,
        super::ProxySignedQueryReplayScope::Client,
    ) else {
        panic!("trailing proxy query bytes must fail exact decoding");
    };
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
#[cfg(feature = "connect")]
#[test]
fn signed_proxy_route_scan_rejects_client_continuations_and_route_tampering() {
    let key_pair =
        checked_torii_test_ed25519_keypair(0xf9, "derive signed proxy continuation fixture key");
    let authority = AccountId::new(key_pair.public_key().clone());
    let cursor = iroha_data_model::query::parameters::ForwardCursor {
        query: "00".repeat(32),
        cursor: std::num::NonZeroU64::new(1).expect("one is non-zero"),
        gas_budget: None,
    };
    let continuation = authorize_query_for_test(
        iroha_data_model::query::QueryRequest::Continue(cursor),
        authority.clone(),
    )
    .sign(&key_pair);
    let admission = signed_query_test_admission();
    let continuation_bytes = iroha_version::codec::EncodeVersioned::encode_versioned(&continuation);
    let limits =
        super::QueryFanoutMemoryEnvelope::decode_limits_for(continuation_bytes.len(), 1024 * 1024)
            .expect("test route-scan decode limits");
    let request = super::decode_verified_proxy_signed_query(
        &continuation_bytes,
        "test route scan",
        admission.as_ref(),
        limits,
        super::ProxySignedQueryReplayScope::RouteScanDeferred,
    )
    .expect("the client continuation signature should be valid");
    let response = super::reject_proxy_client_continuation(&request, "signed route scan")
        .expect_err("client-provided proxy continuations must fail closed");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let authorized = RoutingDecision::new(LaneId::new(3), DataSpaceId::new(10));
    let tampered = RoutingDecision::new(LaneId::new(4), DataSpaceId::new(12));
    let response = super::validate_proxy_signed_query_route(&authority, &[authorized], tampered)
        .expect_err("a peer cannot replace the authorized route hint");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
#[cfg(feature = "connect")]
#[test]
fn effective_proxy_signed_query_routing_decision_prefers_receiver_recomputed_route() {
    let ingress_hint = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let resolved_route = RoutingDecision::new(LaneId::new(2), DataSpaceId::new(10));
    assert_eq!(
        super::effective_proxy_signed_query_routing_decision(resolved_route, ingress_hint),
        resolved_route
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn signed_query_proxy_does_not_retry_after_ambiguous_dispatch() {
    let first_peer_id = PeerId::from(
        checked_torii_test_ed25519_keypair(0x91, "derive retry first proxy peer fixture key")
            .public_key()
            .clone(),
    );
    let second_peer_id = PeerId::from(
        checked_torii_test_ed25519_keypair(0x92, "derive retry second proxy peer fixture key")
            .public_key()
            .clone(),
    );
    let route = RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1));
    let request = ToriiProxyRequestV1 {
        schema_version: TORII_PROXY_REQUEST_VERSION_V1,
        request_id: Hash::new(b"signed-query-ambiguous-dispatch"),
        deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
        hop_count: 1,
        max_hops: 3,
        visited_peer_ids: Vec::new(),
        request: ToriiProxyRequestKindV1::SignedQueryRouteScan {
            query_bytes: Vec::new(),
            expected_route: ToriiRouteHintV1::from(route),
            response_format: ToriiProxyResponseFormatV1::Norito,
        },
    };
    let attempts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let attempts_ref = attempts.clone();
    let first_peer_id_for_closure = first_peer_id.clone();
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
            let attempts = attempts_ref.clone();
            let first_peer_id = first_peer_id_for_closure.clone();
            async move {
                let peer_id = candidate.peer_id().clone();
                attempts
                    .lock()
                    .expect("attempt tracker should lock")
                    .push(peer_id.clone());
                if peer_id == first_peer_id {
                    return Err(ToriiProxyAttemptError::after_dispatch(
                        "authority response was lost after request dispatch",
                    ));
                }
                Ok(ToriiProxyHttpResponseV1 {
                    status_code: StatusCode::OK.as_u16(),
                    headers: Vec::new(),
                    body: b"proxy-ok".to_vec(),
                })
            }
        },
        |_request_id| async move {},
    )
    .await;
    assert_eq!(
        attempts
            .lock()
            .expect("attempt tracker should lock")
            .as_slice(),
        &[first_peer_id]
    );
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("signed_query_outcome_unknown")
    );
}

#[cfg(all(feature = "connect", feature = "app_api"))]
#[tokio::test]
async fn prepared_current_admission_rejects_actual_multiroute_payload_before_custody() {
    let domains = [
        DomainId::try_new("first", "universal").unwrap(),
        DomainId::try_new("second", "secondary").unwrap(),
    ];
    let world = World::with(
        domains
            .iter()
            .cloned()
            .map(|id| Domain::new(id).build(&ALICE_ID)),
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [],
    );
    let app =
        mk_app_state_for_tests_with_world_and_nexus(world, multiple_dataspace_nexus_for_test());
    for domain in &domains {
        bind_domain_name_for_test(&app, &domain.to_string());
    }
    let transaction = TransactionBuilder::new(
        *app.state.network_id_ref(),
        ALICE_ID.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(domains.into_iter().map(|domain| {
        iroha_data_model::isi::SetKeyValue::domain(
            domain,
            "prepared".parse().unwrap(),
            iroha_primitives::json::Json::new(true),
        )
    }))
    .sign(ALICE_KEYPAIR.private_key());
    let plan = app
        .queue
        .route_payload_plan_with_state(transaction.payload(), app.state.as_ref())
        .expect("actual two-domain route resolves");
    assert!(
        !matches!(plan, RoutingPlan::Single(_)),
        "fixture must exercise actual multi-route classification"
    );
    let before = app.queue.active_len();
    let error = routing::validate_current_prepared_transaction_payload(
        transaction.payload(),
        app.queue.as_ref(),
        app.state.as_ref(),
    )
    .expect_err("multi-route preparation cannot promise supported execution");
    assert!(matches!(
        error,
        Error::AppQueryValidation {
            code: "prepared_transaction_route_unsupported",
            ..
        }
    ));
    assert_eq!(app.queue.active_len(), before);
}

#[cfg(feature = "connect")]
#[tokio::test]
async fn prepared_current_admission_retains_exact_local_pending_identity() {
    let (app, key, _, _) = lifecycle_ordinary_fixture(true);
    let transaction = lifecycle_ordinary_transaction(
        &app,
        &key,
        vec![Log::new(Level::INFO, "prepared current application".to_owned()).into()],
    );
    let wire = transaction.encode_wire_v1().unwrap();
    assert_eq!(
        routing::prepared_submit_outcome(&app, &transaction).unwrap(),
        None
    );
    let response =
        routing::submit_current_prepared_transaction(&app, transaction.clone(), &app.telemetry)
            .await
            .expect("ordinary prepared admission");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(app.queue.active_len(), 1);
    let retained = lifecycle_pending_wire(&app);
    assert!(
        !retained.is_empty(),
        "accepted preparation retains local pending custody"
    );
    assert_eq!(
        routing::prepared_submit_outcome(&app, &transaction).unwrap(),
        Some("Pending")
    );
    assert_eq!(
        lifecycle_pending_wire(&app),
        retained,
        "read-only recovery must not append another transaction"
    );
    let view = app.state.view();
    let queued = app.queue.all_transactions(&view).collect::<Vec<_>>();
    assert_eq!(queued.len(), 1);
    assert_eq!(
        queued[0].external().unwrap().encode_wire_v1().unwrap(),
        wire
    );
}

#[cfg(feature = "connect")]
#[tokio::test]
async fn current_pending_identity_never_bypasses_signature_or_network_authentication() {
    let (app, key, _, _) = lifecycle_ordinary_fixture(true);
    let transaction = lifecycle_ordinary_transaction(
        &app,
        &key,
        vec![Log::new(Level::INFO, "native pending authentication".into()).into()],
    );
    let accepted = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &transaction)
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let original = lifecycle_pending_wire(&app);
    assert_eq!(original.len(), 1);
    let forged = transaction_with_invalid_signature_for_test(transaction.clone());
    assert_eq!(
        forged.hash(),
        transaction.hash(),
        "a matching payload hash cannot authenticate its signature"
    );
    let error = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &forged)
        .await
        .expect_err("pending hash cannot bypass the outer signature");
    assert!(matches!(
        error,
        Error::AcceptTransaction(AcceptTransactionFail::SignatureVerification(_))
    ));
    let foreign = TransactionBuilder::new(
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"foreign native ingress genesis",
        ))),
        AccountId::new(key.public_key().clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "foreign network".into())])
    .sign(key.private_key());
    let error = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &foreign)
        .await
        .expect_err("independently foreign network input must fail");
    assert!(matches!(
        error,
        Error::AcceptTransaction(AcceptTransactionFail::TransactionDomainMismatch(_))
    ));
    assert_eq!(lifecycle_pending_wire(&app), original);
    assert_eq!(app.queue.active_len(), 1);
    assert!(
        !app.state
            .has_committed_entrypoint(transaction.hash_as_entrypoint())
    );
}

#[cfg(feature = "connect")]
#[tokio::test]
async fn current_native_ingress_revalidates_expiry_and_current_signing_policy() {
    let (app, key, _, _) = lifecycle_ordinary_fixture(true);
    let transaction = lifecycle_ordinary_transaction(
        &app,
        &key,
        vec![Log::new(Level::INFO, "native policy admission".into()).into()],
    );
    let accepted = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &transaction)
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let original = lifecycle_pending_wire(&app);
    let mut builder = TransactionBuilder::from_payload(transaction.payload().clone()).unwrap();
    builder.set_creation_time(Duration::from_millis(1));
    builder.set_ttl(Duration::from_secs(1));
    let expired = builder.sign(key.private_key());
    let error = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &expired)
        .await
        .expect_err("expired input cannot acquire fresh custody");
    assert!(matches!(
        error,
        Error::AcceptTransaction(AcceptTransactionFail::TransactionExpired { .. })
    ));
    let policy = iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
        Algorithm::Secp256k1,
    ])
    .expect("explicit committed policy excludes this Ed25519 signer");
    let next_height = app
        .state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let mut block = app.state.block(BlockHeader::new(
        NonZeroU64::new(next_height).expect("non-zero fixture height"),
        None,
        None,
        0,
        0,
    ));
    let mut policy_transaction = block.transaction();
    policy_transaction
        .world_mut_for_testing()
        .parameters_mut_for_testing()
        .set_parameter(
            policy
                .into_parameter()
                .expect("canonical replacement policy"),
        )
        .expect("replace original committed policy");
    policy_transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit replacement signing policy without changing transaction history");
    let error = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &transaction)
        .await
        .expect_err("pending identity cannot bypass the current signing policy");
    let Error::AcceptTransaction(AcceptTransactionFail::SignatureVerification(error)) = error
    else {
        panic!("expected current signing-policy rejection");
    };
    assert_eq!(error.code(), SignatureRejectionCode::AlgorithmNotPermitted);
    assert_eq!(lifecycle_pending_wire(&app), original);
    assert_eq!(app.queue.active_len(), 1);
}
