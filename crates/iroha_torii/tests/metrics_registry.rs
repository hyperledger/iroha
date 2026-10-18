//! Metrics registry hygiene tests (telemetry feature only).
#![cfg(feature = "telemetry")]
#[path = "fixtures.rs"]
mod fixtures;
#[test]
fn shared_metrics_reset_clears_counters() {
    // Start fresh registry.
    let metrics = fixtures::reset_shared_metrics();
    let counter = metrics
        .torii_address_invalid_total
        .with_label_values(&["/tests/metrics-reset", "reason"]);
    counter.inc();
    assert_eq!(counter.get(), 1);
    // Reset should give a new registry with zeroed counters.
    let reset = fixtures::reset_shared_metrics();
    let counter_after = reset
        .torii_address_invalid_total
        .with_label_values(&["/tests/metrics-reset", "reason"]);
    assert_eq!(
        counter_after.get(),
        0,
        "reset_shared_metrics should return a fresh registry"
    );
}
#[test]
fn duplicate_metric_panic_env_is_enabled() {
    fixtures::enable_duplicate_metric_panic();
    let flag =
        std::env::var("IROHA_METRICS_PANIC_ON_DUPLICATE").unwrap_or_else(|_| "0".to_string());
    assert!(
        matches!(flag.as_str(), "1" | "true" | "yes"),
        "duplicate-metric panic flag must be enabled in tests"
    );
}
