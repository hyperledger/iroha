//! PDP/PoTR simulation tests ensuring the shared harness remains deterministic.
use integration_tests::da::pdp_potr::{DEFAULT_SEED, SimulationConfig, run_simulation};
#[test]
fn harness_initialises_and_runs() {
    let stats = run_simulation(SimulationConfig::default(), DEFAULT_SEED);
    assert_eq!(stats.epochs.len(), stats.config.epochs);
    assert!(
        stats.pdp_detection_rate() > 0.85,
        "PDP detection rate should remain high"
    );
    assert!(
        stats.qos.repair_queue_peak > 0,
        "repair queue must register backlog under adversarial load"
    );
    assert!(
        stats.aggregate_potr.failures > 0,
        "PoTR challenges should produce failures when adversaries exist"
    );
}
#[test]
fn partition_heavy_scenario_triggers_repairs() {
    let stats = run_simulation(
        SimulationConfig {
            partition_probability: 0.8,
            max_partition_regions: 2,
            repair_capacity_per_epoch: 1,
            ..SimulationConfig::default()
        },
        DEFAULT_SEED,
    );
    assert!(
        stats.qos.repair_queue_peak >= 3,
        "high partition probability should inflate repair backlog"
    );
    assert!(
        stats.aggregate_pdp.undetected > 0,
        "partitions must yield undetected failures when collectors fall behind"
    );
}
#[test]
fn deterministic_summary_matches_expected() {
    let stats = run_simulation(SimulationConfig::default(), DEFAULT_SEED);
    assert_eq!(stats.aggregate_pdp.failures, 49);
    assert_eq!(stats.aggregate_pdp.detected, 48);
    assert_eq!(stats.aggregate_potr.failures, 77);
    assert_eq!(stats.aggregate_potr.detected, 28);
    assert_eq!(stats.qos.repair_queue_peak, 38);
    assert_eq!(stats.qos.total_repair_events, 122);
    assert!(
        (stats.qos.p95_response_ms() - 30_000.0).abs() <= 80.0,
        "p95 latency should remain near the configured 30 s interval"
    );
}
#[test]
fn partition_probability_influences_detection() {
    let baseline = run_simulation(
        SimulationConfig {
            partition_probability: 0.0,
            adversary_failure_probability: 0.4,
            ..SimulationConfig::default()
        },
        DEFAULT_SEED,
    );
    let partitioned = run_simulation(
        SimulationConfig {
            partition_probability: 0.8,
            adversary_failure_probability: 0.4,
            ..SimulationConfig::default()
        },
        DEFAULT_SEED,
    );
    let baseline_detected: usize = baseline
        .epochs
        .iter()
        .map(|epoch| epoch.detected_failures)
        .sum();
    let partition_detected: usize = partitioned
        .epochs
        .iter()
        .map(|epoch| epoch.detected_failures)
        .sum();
    assert!(
        partition_detected > baseline_detected,
        "high partition probability should increase detected failures"
    );
}
