#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![doc = "Telemetry gating integration tests exercising profile-based access."]
#![cfg(feature = "telemetry")]
use axum::{http::StatusCode, response::IntoResponse};
use iroha_config::parameters::actual::TelemetryProfile;
use iroha_telemetry::metrics::Metrics;
use iroha_torii::{
    MaybeTelemetry, handle_metrics, handle_status, handle_status_blocks, handle_status_peers,
};
fn telemetry_disabled() -> MaybeTelemetry {
    MaybeTelemetry::from_profile(None, TelemetryProfile::Disabled)
}
fn telemetry_for(profile: TelemetryProfile, configure: impl Fn(&Metrics)) -> MaybeTelemetry {
    let telemetry = MaybeTelemetry::for_tests().with_profile(profile);
    configure(telemetry.metrics());
    telemetry
}
#[tokio::test]
async fn disabled_profile_hides_status_and_metrics() {
    let telemetry = telemetry_disabled();
    let status_err = handle_status(
        &build_identity_test_fixture::build_identity().status(),
        &telemetry,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(
        status_err.into_response().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    for status_err in [
        handle_status_blocks(&telemetry, 1).unwrap_err(),
        handle_status_peers(&telemetry, 1).unwrap_err(),
    ] {
        assert_eq!(
            status_err.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    let metrics_err = handle_metrics(&telemetry).unwrap_err();
    assert_eq!(
        metrics_err.into_response().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
#[tokio::test]
async fn operator_profile_exposes_status_only() {
    let telemetry = telemetry_for(TelemetryProfile::Operator, |_| {});
    let status_resp = handle_status(
        &build_identity_test_fixture::build_identity().status(),
        &telemetry,
        None,
    )
    .await
    .unwrap();
    assert_eq!(status_resp.status(), StatusCode::OK);
    let metrics_err = handle_metrics(&telemetry).unwrap_err();
    assert_eq!(
        metrics_err.into_response().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
#[tokio::test]
async fn extended_profile_exposes_prometheus_metrics() {
    let telemetry = telemetry_for(TelemetryProfile::Extended, |metrics| {
        metrics
            .sumeragi_view_changes_total
            .with_label_values(&["global"])
            .inc();
    });
    let status_resp = handle_status(
        &build_identity_test_fixture::build_identity().status(),
        &telemetry,
        None,
    )
    .await
    .unwrap();
    assert_eq!(status_resp.status(), StatusCode::OK);
    let prometheus = handle_metrics(&telemetry).unwrap();
    assert!(
        !prometheus.trim().is_empty(),
        "expected non-empty Prometheus payload"
    );
}
#[tokio::test]
async fn developer_profile_hides_prometheus_metrics() {
    let developer = telemetry_for(TelemetryProfile::Developer, |_| {});
    let metrics_err = handle_metrics(&developer).unwrap_err();
    assert_eq!(
        metrics_err.into_response().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
#[tokio::test]
async fn full_profile_combines_all_capabilities() {
    let telemetry = telemetry_for(TelemetryProfile::Full, |metrics| {
        metrics
            .sumeragi_view_changes_total
            .with_label_values(&["global"])
            .inc();
    });
    let status = handle_status(
        &build_identity_test_fixture::build_identity().status(),
        &telemetry,
        None,
    )
    .await
    .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let prometheus = handle_metrics(&telemetry).unwrap();
    assert!(prometheus.contains("sumeragi_view_changes_total{lane=\"global\"} 1"));
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
