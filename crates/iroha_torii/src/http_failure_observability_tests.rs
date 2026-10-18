//! Correlated HTTP failure events through the real Axum response boundary.

use super::*;
use axum::{Router, http::Request};
use iroha_core::telemetry::StatusSnapshotError;
use iroha_logger::prelude::tracing::{self, instrument::WithSubscriber};
use iroha_torii_shared::route_catalog::{
    AdmissionPolicy, ApiSurface, EnabledFeatures, HttpMethod, Listener, RouteDescriptor,
    RouteEffect,
};
use std::{io, sync::Mutex};

const ITEM: RouteDescriptor = RouteDescriptor::new(
    "test.failure.read",
    HttpMethod::Get,
    "/v1/tests/failures/{item_id}",
    ApiSurface::Public,
    Listener::Torii,
    RouteEffect::ReadOnly,
    AdmissionPolicy::Public,
);
const OK: RouteDescriptor = RouteDescriptor::new(
    "test.success.read",
    HttpMethod::Get,
    "/v1/tests/success",
    ApiSurface::Public,
    Listener::Torii,
    RouteEffect::ReadOnly,
    AdmissionPolicy::Public,
);
const PRIVATE_PATH: &str = "private-account-canary";
const PRIVATE_QUERY: &str = "private-cursor-canary";
const PRIVATE_HEADER: &str = "private-bearer-canary";
const PRIVATE_BODY: &str = "private-body-canary";
const PRIVATE_STORAGE: &str = "private-storage-path-canary";

#[derive(Clone, Copy)]
enum Failure {
    StateBusy,
    HistoryDeferred,
    HistoryRejected,
}

fn failure_response(failure: Failure) -> Response {
    let error = match failure {
        Failure::StateBusy => StatusSnapshotError::StateBusy,
        Failure::HistoryDeferred => {
            let budget = iroha_allocation::AllocationBudget::new(1);
            let _occupied = budget.try_reserve_bytes(1).expect("occupy original pool");
            let refusal = budget
                .try_reserve_bytes(1)
                .expect_err("actual capacity refusal");
            StatusSnapshotError::HistoryReadDeferred(
                iroha_core::execution_attempt::ExecutionDeferred::from(refusal).reason(),
            )
        }
        Failure::HistoryRejected => StatusSnapshotError::HistoryRead(PRIVATE_STORAGE.to_owned()),
    };
    routing::status_snapshot_failure_response(error)
}

fn router(app: SharedAppState, failure: Failure) -> Router {
    let mut builder = RouterBuilder::new(
        app.clone(),
        RouteCatalog::new(&[ITEM, OK]),
        EnabledFeatures::none(),
    )
    .expect("valid test catalog");
    builder.route(
        &ITEM,
        catalog_get(move || async move { failure_response(failure) }),
    );
    builder.route(&OK, catalog_get(|| async { StatusCode::NO_CONTENT }));
    let (router, manifest) = builder.finish().expect("complete test router");
    router
        .layer(axum::middleware::from_fn(capture_response_format))
        .layer(axum::middleware::from_fn(enforce_typed_error_contract))
        .layer(axum::middleware::from_fn(enforce_json_utf8_charset))
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            record_http_metrics,
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|_: &Request<Body>| iroha_logger::debug_span!("http_request")),
        )
        .layer(axum::middleware::from_fn_with_state(
            manifest.route_index(),
            attach_matched_route_metadata,
        ))
        .layer(axum::middleware::from_fn(attach_request_id))
        .with_state(app)
}

struct CaptureWriter(Arc<Mutex<Vec<u8>>>);
impl io::Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn observe(router: Router, request: Request<Body>) -> (Response, Vec<norito::json::Value>) {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let writer = bytes.clone();
    // Reuse the logger's existing tracing-subscriber formatter pattern, scoped to
    // this future. Never change the process-global test logger or filter.
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::ERROR)
        .with_ansi(false)
        .without_time()
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(move || CaptureWriter(writer.clone()))
        .finish();
    let response = async {
        assert!(!tracing::enabled!(tracing::Level::DEBUG));
        assert!(iroha_logger::debug_span!("http_request").is_disabled());
        router.oneshot(request).await.expect("HTTP response")
    }
    .with_subscriber(subscriber)
    .await;
    let text = String::from_utf8(bytes.lock().expect("capture lock").clone()).expect("UTF-8 logs");
    for private in [
        PRIVATE_PATH,
        PRIVATE_QUERY,
        PRIVATE_HEADER,
        PRIVATE_BODY,
        PRIVATE_STORAGE,
    ] {
        assert!(
            !text.contains(private),
            "private request/response material leaked into ERROR logs"
        );
    }
    let events = text
        .lines()
        .map(|line| {
            norito::json::from_str::<norito::json::Value>(line).expect("structured log event")
        })
        .filter(|event| event["fields"]["event"].as_str() == Some("torii.http.response_failure"))
        .collect();
    (response, events)
}

fn request(accept: &str) -> Request<Body> {
    Request::builder()
        .uri(format!(
            "/v1/tests/failures/{PRIVATE_PATH}?cursor={PRIVATE_QUERY}"
        ))
        .header(axum::http::header::ACCEPT, accept)
        .header(axum::http::header::AUTHORIZATION, PRIVATE_HEADER)
        .body(Body::from(PRIVATE_BODY))
        .expect("private canary request")
}

fn assert_event(response: &Response, events: &[norito::json::Value], code: &str, cause: &str) {
    assert_eq!(
        events.len(),
        1,
        "exactly one correlated event per 5xx response"
    );
    assert_eq!(events[0]["level"].as_str(), Some("ERROR"));
    let fields = &events[0]["fields"];
    assert_eq!(fields["method"].as_str(), Some("GET"));
    assert_eq!(fields["route_id"].as_str(), Some(ITEM.stable_route_id()));
    assert_eq!(fields["route_template"].as_str(), Some(ITEM.path()));
    assert_eq!(fields["error_code"].as_str(), Some(code));
    assert_eq!(fields["status_busy_cause"].as_str(), Some(cause));
    assert_eq!(fields["status"].as_u64(), Some(503));
    let id = response.headers()[REQUEST_ID_HEADER]
        .to_str()
        .expect("response request ID");
    assert!(valid_incoming_request_id(id));
    assert!(id.len() <= MAX_REQUEST_ID_LENGTH);
    assert_eq!(fields["request_id"].as_str(), Some(id));
}

#[tokio::test]
async fn http_failure_event_is_correlated_without_debug_span() {
    let app = tests_runtime_handlers::mk_app_state_for_tests();
    for (failure, cause) in [
        (Failure::StateBusy, "state_snapshot_contention"),
        (Failure::HistoryDeferred, "history_read_deferred"),
    ] {
        for accept in ["application/json", utils::NORITO_MIME_TYPE] {
            let mut request = request(accept);
            let incoming_id = "r".repeat(MAX_REQUEST_ID_LENGTH);
            request.headers_mut().insert(
                REQUEST_ID_HEADER,
                HeaderValue::from_str(&incoming_id).unwrap(),
            );
            let (response, events) = observe(router(app.clone(), failure), request).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()[REQUEST_ID_HEADER], incoming_id);
            assert_eq!(
                response.headers()["x-iroha-reject-code"],
                "status_state_busy"
            );
            assert_event(&response, &events, "status_state_busy", cause);
            assert_eq!(
                response
                    .extensions()
                    .get::<utils::HttpStatusBusyCause>()
                    .map(utils::HttpStatusBusyCause::as_str),
                Some(cause),
                "canonical error normalization must retain internal provenance"
            );
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let envelope: ErrorEnvelope = if accept == "application/json" {
                norito::json::from_slice(&body).unwrap()
            } else {
                norito::decode_from_bytes(&body).unwrap()
            };
            assert_eq!(envelope.code(), "status_state_busy");
        }
    }
}

#[tokio::test]
async fn invalid_request_ids_are_replaced_in_failure_event() {
    let app = tests_runtime_handlers::mk_app_state_for_tests();
    for supplied in [
        vec![HeaderValue::from_static("first,second")],
        vec![
            HeaderValue::from_static("first"),
            HeaderValue::from_static("second"),
        ],
        vec![HeaderValue::from_static("bad\tid")],
        vec![HeaderValue::from_str(&"x".repeat(MAX_REQUEST_ID_LENGTH + 1)).unwrap()],
    ] {
        let mut request = request("application/json");
        for value in &supplied {
            request
                .headers_mut()
                .append(REQUEST_ID_HEADER, value.clone());
        }
        let (response, events) = observe(router(app.clone(), Failure::StateBusy), request).await;
        assert_event(
            &response,
            &events,
            "status_state_busy",
            "state_snapshot_contention",
        );
        let generated = response.headers()[REQUEST_ID_HEADER].to_str().unwrap();
        assert_eq!(generated.len(), 64);
        assert!(
            generated
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        for original in supplied {
            assert_ne!(generated.as_bytes(), original.as_bytes());
        }
    }
}

#[tokio::test]
async fn storage_error_body_is_not_logged_and_success_emits_no_failure_event() {
    let app = tests_runtime_handlers::mk_app_state_for_tests();
    let (response, events) = observe(
        router(app.clone(), Failure::HistoryRejected),
        request("application/json"),
    )
    .await;
    assert_event(&response, &events, "status_state_unavailable", "none");
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let envelope: ErrorEnvelope = norito::json::from_slice(&body).unwrap();
    assert!(
        envelope.message().contains(PRIVATE_STORAGE),
        "exercise a real error body carrying the storage canary"
    );
    let (response, events) = observe(
        router(app, Failure::StateBusy),
        Request::builder()
            .uri(OK.path())
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(events.is_empty());
}
