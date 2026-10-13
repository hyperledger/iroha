//! SCCP admission is independent of the optional application API feature.
use super::*;
use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode},
    middleware::{Next, from_fn, from_fn_with_state},
    response::Response,
    routing::any,
};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
};
fn pending_body(polls: &Arc<AtomicUsize>) -> Body {
    let polls = Arc::clone(polls);
    Body::from_stream(futures::stream::poll_fn(move |_| {
        polls.fetch_add(1, Ordering::SeqCst);
        Poll::<Option<Result<Bytes, Infallible>>>::Pending
    }))
}
fn occupy_fanout_pool(app: &SharedAppState) -> tokio::sync::OwnedSemaphorePermit {
    app.query_fanout_inflight
        .try_acquire_parts([app.query_fanout_inflight.capacity_bytes()])
        .unwrap()
}
async fn insert_test_route_metadata(
    descriptor: iroha_torii_shared::route_catalog::RouteDescriptor,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    request
        .extensions_mut()
        .insert(MatchedRouteMetadata::from_descriptor(descriptor));
    next.run(request).await
}
fn admission_router(
    app: SharedAppState,
    descriptor: iroha_torii_shared::route_catalog::RouteDescriptor,
    _: bool,
) -> Router {
    Router::new()
        .route(descriptor.path(), any(|| async { StatusCode::NO_CONTENT }))
        .layer(from_fn_with_state(
            app,
            enforce_app_routed_read_http_admission,
        ))
        .layer(from_fn(move |request, next| {
            insert_test_route_metadata(descriptor, request, next)
        }))
}
#[test]
fn sccp_proof_selectors_use_exact_bounded_bodyless_query_decoders() {
    let expected = [
        (
            route_catalog::sccp::HISTORY,
            SccpHttpRead::History,
            "HistoryQuery",
        ),
        (
            route_catalog::sccp::MESSAGE_PROOF,
            SccpHttpRead::MessageProof,
            "ProofQuery",
        ),
        (
            route_catalog::sccp::CONTROL_PROOF,
            SccpHttpRead::ControlProof,
            "ProofQuery",
        ),
    ];
    assert_eq!(SCCP_HTTP_READ_ROUTES_V1.len(), expected.len());
    for (route, identity, name) in expected {
        let entry = app_routed_read_http_endpoint(route.stable_route_id()).unwrap();
        assert_eq!(entry.endpoint, AppReadHttpIdentity::Sccp(identity));
        assert_eq!(entry.decoder, AppRoutedReadHttpDecoder::StringQuery(name));
        assert_eq!(entry.decoder.body_type_name(), None);
        #[cfg(feature = "app_api")]
        assert!(
            APP_ROUTED_READ_HTTP_ENDPOINTS_V1
                .iter()
                .all(|item| item.route.stable_route_id() != route.stable_route_id())
        );
        #[cfg(feature = "app_api")]
        assert!(
            APP_LOCAL_COLLECTION_HTTP_ROUTES_V1
                .iter()
                .all(|item| item.route.stable_route_id() != route.stable_route_id())
        );
    }
}

#[tokio::test]
async fn sccp_selectors_wait_for_original_admission_without_polling_request_body() {
    let mut app = mk_app_state_for_tests();
    Arc::get_mut(&mut app).unwrap().query_queue_timeout = Duration::from_secs(1);
    for entry in SCCP_HTTP_READ_ROUTES_V1 {
        let before = app.query_fanout_inflight.available_permits();
        let waiters = app.app_routed_read_waiters.available_permits();
        let occupied = occupy_fanout_pool(&app);
        let polls = Arc::new(AtomicUsize::new(0));
        let request = Request::builder()
            .uri(entry.route.path())
            .body(pending_body(&polls))
            .unwrap();
        let mut response =
            Box::pin(admission_router(Arc::clone(&app), entry.route, false).oneshot(request));
        assert!(futures::poll!(response.as_mut()).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(app.app_routed_read_waiters.available_permits(), waiters - 1);
        drop(response);
        assert_eq!(app.app_routed_read_waiters.available_permits(), waiters);
        drop(occupied);
        assert_eq!(app.query_fanout_inflight.available_permits(), before);
    }
}

#[tokio::test]
async fn sccp_query_extractor_retains_text_and_rejects_unknown_fields_under_real_owner() {
    use axum::extract::FromRequestParts as _;
    let app = mk_app_state_for_tests();
    let reservation = try_acquire_new_query_fanout_memory(&app).unwrap();
    let envelope = reservation.admitted_envelope(&app).unwrap();
    let decode_plan =
        ToriiRoutedReadMemoryBudget::from_envelope(envelope, app.torii_proxy_max_response_bytes)
            .request_decode_plan_for_path(route_catalog::sccp::HISTORY.path())
            .unwrap();
    APP_ROUTED_READ_HTTP_ADMISSION
        .scope(
            AppRoutedReadHttpAdmission {
                reservation,
                decode_plan,
            },
            async {
                let (mut parts, _) = Request::builder()
                    .uri("/v1/sccp/history/1?size=33")
                    .body(Body::empty())
                    .unwrap()
                    .into_parts();
                let crate::NoritoStringQuery(query) = crate::NoritoStringQuery::<
                    crate::sccp::HistoryQuery,
                >::from_request_parts(
                    &mut parts, &()
                )
                .await
                .unwrap();
                assert_eq!(query.size.as_deref(), Some("33"));
                let (mut parts, _) = Request::builder()
                    .uri("/v1/sccp/history/1?size=33&attestation=own")
                    .body(Body::empty())
                    .unwrap()
                    .into_parts();
                assert!(
                    crate::NoritoStringQuery::<crate::sccp::HistoryQuery>::from_request_parts(
                        &mut parts,
                        &()
                    )
                    .await
                    .is_err()
                );
                let (mut parts, _) = Request::builder()
                    .uri("/v1/sccp/messages/id/proof?at=latest")
                    .body(Body::empty())
                    .unwrap()
                    .into_parts();
                let crate::NoritoStringQuery(query) = crate::NoritoStringQuery::<
                    crate::sccp::native::ProofQuery,
                >::from_request_parts(
                    &mut parts, &()
                )
                .await
                .unwrap();
                assert_eq!(query.at.as_deref(), Some("latest"));
                let (mut parts, _) = Request::builder()
                    .uri("/v1/sccp/messages/id/proof?at=latest&own=1")
                    .body(Body::empty())
                    .unwrap()
                    .into_parts();
                assert!(
                    crate::NoritoStringQuery::<crate::sccp::native::ProofQuery>::from_request_parts(
                        &mut parts,
                        &()
                    )
                    .await
                    .is_err()
                );
                assert!(crate::history_producer::HistoryProducerOwner::current().is_ok());
            },
        )
        .await;
    assert!(crate::history_producer::HistoryProducerOwner::current().is_err());
}

#[tokio::test]
async fn sccp_three_parameter_path_and_query_fit_the_original_request_owner() {
    use axum::extract::Path;
    let app = mk_app_state_for_tests();
    let descriptor = route_catalog::sccp::CONTROL_PROOF;
    let memory = ToriiRoutedReadMemoryBudget::new(
        app.query_fanout_working_set_bytes,
        app.torii_proxy_max_response_bytes,
    )
    .unwrap();
    let plan = memory
        .request_decode_plan_for_path(descriptor.path())
        .unwrap();
    let fixed = routed_read_url_parameter_fixed_bytes(
        3,
        "network".len() + "revision".len() + "control_nonce".len(),
    )
    .unwrap();
    let baseline = app_routed_read_url_parameter_fixed_bytes().unwrap();
    assert!(fixed > baseline, "third Arc key/value pair must be charged");
    let high_water = memory
        .app_request_high_water_bytes(plan.raw_input_limit_bytes)
        .unwrap()
        - baseline
        + fixed;
    assert!(high_water <= memory.envelope.working_set_bytes);
    assert!(plan.raw_input_limit_bytes <= memory.route_body_limit());
    if plan.raw_input_limit_bytes < memory.route_body_limit() {
        assert!(
            memory
                .app_request_high_water_bytes(plan.raw_input_limit_bytes + 1)
                .unwrap()
                - baseline
                + fixed
                > memory.envelope.working_set_bytes
        );
    }
    assert_eq!(
        plan.typed_limits.max_total_allocated_bytes(),
        memory.envelope.request_decode_allocated_bytes
    );
    assert!(plan.admit_raw_input(plan.raw_input_limit_bytes).is_ok());
    assert!(
        plan.admit_raw_input(plan.raw_input_limit_bytes + 1)
            .is_err()
    );
    assert!(
        memory
            .request_decode_plan_for_path("/{a}/{b}/{c}/{d}/{e}")
            .is_err()
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let entered = calls.clone();
    let owning_app = app.clone();
    let router = Router::new()
        .route(
            descriptor.path(),
            any(
                move |Path((network, revision, nonce)): Path<(String, u32, u64)>,
                      crate::NoritoStringQuery(query): crate::NoritoStringQuery<
                    crate::sccp::native::ProofQuery,
                >| {
                    let entered = entered.clone();
                    let owning_app = owning_app.clone();
                    async move {
                        assert_eq!((network.as_str(), revision, nonce), ("ethereum", 7, 9));
                        assert_eq!(query.at.as_deref(), Some("latest"));
                        APP_ROUTED_READ_HTTP_ADMISSION.with(|admission| {
                            assert!(admission.reservation.belongs_to(&owning_app))
                        });
                        assert!(crate::history_producer::HistoryProducerOwner::current().is_ok());
                        entered.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                },
            ),
        )
        .layer(from_fn_with_state(
            app.clone(),
            enforce_app_routed_read_http_admission,
        ))
        .layer(from_fn(move |request, next| {
            insert_test_route_metadata(descriptor, request, next)
        }));
    let before = app.query_fanout_inflight.available_permits();
    for (suffix, expected) in [
        ("at=latest", StatusCode::NO_CONTENT),
        ("at=latest&own=1", StatusCode::BAD_REQUEST),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/sccp/controls/ethereum/7/9/proof?{suffix}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert!(app.query_fanout_inflight.available_permits() < before);
        drop(response);
        assert_eq!(app.query_fanout_inflight.available_permits(), before);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(crate::history_producer::HistoryProducerOwner::current().is_err());
}
