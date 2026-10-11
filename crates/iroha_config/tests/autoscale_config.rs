//! Validate Nexus autoscale configuration parsing and guardrails.

use iroha_config::parameters::{
    actual::Root as ActualConfig,
    user::{Autoscale as UserAutoscale, Root as UserConfig},
};
use iroha_config_base::{read::ConfigReader, toml::TomlSource};
use iroha_model_base::topology::LaneId;
use std::path::PathBuf;
fn base_reader() -> ConfigReader {
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/base.toml");
    ConfigReader::new()
        .read_toml_with_extends(base_path)
        .expect("base config should load")
}
fn parse_actual_config(inline_toml: &str) -> Result<ActualConfig, String> {
    let table: toml::Table = inline_toml.parse().expect("inline TOML should parse");
    let user = base_reader()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .map_err(|error| format!("{error:?}"))?;
    user.parse().map_err(|error| format!("{error:?}"))
}
fn autoscale_config_error(inline_toml: &str) -> String {
    parse_actual_config(inline_toml).expect_err("autoscale config should be rejected")
}

#[test]
fn autoscale_rejects_retired_lane_bound_config_keys() {
    for retired in ["min_lanes", "max_lanes"] {
        let table = format!("[nexus.autoscale]\n{retired} = 3\n")
            .parse()
            .expect("retired autoscale TOML should parse");
        let error = base_reader()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<UserConfig>()
            .expect_err("retired autoscale lane-bound key must be rejected");
        let message = format!("{error:?}");
        assert!(
            message.contains("unknown parameter")
                && message.contains(&format!("nexus.autoscale.{retired}")),
            "unexpected retired autoscale key diagnostic: {message}"
        );
    }
}

#[test]
fn autoscale_json_rejects_retired_lane_bound_fields() {
    for retired in ["min_lanes", "max_lanes"] {
        let encoded = format!(
            r#"{{
                "enabled": true,
                "min_lane_id": 1,
                "max_lane_id_exclusive": 3,
                "target_block_ms": 1000,
                "scale_out_latency_ratio": 1.2,
                "scale_in_latency_ratio": 0.8,
                "scale_out_utilization_ratio": 0.85,
                "scale_in_utilization_ratio": 0.4,
                "scale_out_window_blocks": 8,
                "scale_in_window_blocks": 32,
                "cooldown_blocks": 4,
                "per_lane_target_tps": 50,
                "{retired}": 2
            }}"#
        );
        let error = norito::json::from_str::<UserAutoscale>(&encoded)
            .expect_err("retired autoscale JSON field must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("unknown field") && message.contains(retired),
            "unexpected retired autoscale JSON-field diagnostic: {message}"
        );
    }
}
fn assert_ratio_eq(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() <= f64::EPSILON,
        "expected {expected}, got {actual}"
    );
}
#[test]
fn autoscale_overrides_parse_from_toml() {
    let config = parse_actual_config(include_str!("fixtures/autoscale/overrides.toml"))
        .expect("valid autoscale config should parse");
    let autoscale = config.nexus.autoscale;
    assert!(autoscale.enabled);
    assert_eq!(autoscale.min_lane_id.get(), 3);
    assert_eq!(autoscale.max_lane_id_exclusive.get(), 5);
    assert_eq!(autoscale.target_block_ms.get(), 2_500);
    assert_ratio_eq(autoscale.scale_out_latency_ratio, 1.25);
    assert_ratio_eq(autoscale.scale_in_latency_ratio, 0.75);
    assert_ratio_eq(autoscale.scale_out_utilization_ratio, 0.90);
    assert_ratio_eq(autoscale.scale_in_utilization_ratio, 0.35);
    assert_eq!(autoscale.scale_out_window_blocks.get(), 12);
    assert_eq!(autoscale.scale_in_window_blocks.get(), 48);
    assert_eq!(autoscale.cooldown_blocks.get(), 9);
    assert_eq!(autoscale.per_lane_target_tps.get(), 75);
    assert_eq!(autoscale.last_transition_height, 0);
}
#[test]
fn autoscale_rejects_zero_sizing_fields() {
    let message = autoscale_config_error(include_str!("fixtures/autoscale/zero_fields.toml"));
    for field in [
        "min_lane_id",
        "max_lane_id_exclusive",
        "target_block_ms",
        "scale_out_window_blocks",
        "scale_in_window_blocks",
        "cooldown_blocks",
        "per_lane_target_tps",
    ] {
        assert!(
            message.contains(field),
            "error should identify invalid autoscale field {field}: {message}"
        );
    }
}
#[test]
fn autoscale_rejects_invalid_lane_bounds() {
    let message = autoscale_config_error(include_str!("fixtures/autoscale/invalid_bounds.toml"));
    assert!(
        message.contains("min_lane_id must be < max_lane_id_exclusive"),
        "error should identify inverted autoscale lane bounds: {message}"
    );
}
#[test]
fn autoscale_rejects_empty_elastic_lane_range() {
    let message = autoscale_config_error(include_str!("fixtures/autoscale/empty_range.toml"));
    assert!(
        message.contains("min_lane_id must be < max_lane_id_exclusive"),
        "error should reject an enabled autoscale profile with no elastic lane ids: {message}"
    );
}
#[test]
fn autoscale_rejects_max_lane_id_exclusive_above_safety_cap() {
    let message = autoscale_config_error(include_str!("fixtures/autoscale/above_cap.toml"));
    assert!(
        message.contains("max_lane_id_exclusive must be <= 8"),
        "error should identify autoscale max_lane_id_exclusive above the safety cap: {message}"
    );
}
#[test]
fn autoscale_rejects_reserved_lane_metadata_claim() {
    let message = autoscale_config_error(include_str!("fixtures/autoscale/reserved_metadata.toml"));
    assert!(
        message.contains("autoscale.managed") && message.contains("reserved"),
        "error should identify reserved autoscale-managed lane metadata: {message}"
    );
}
#[test]
fn autoscale_rejects_manual_lane_inside_elastic_id_range() {
    let message = autoscale_config_error(include_str!("fixtures/autoscale/manual_in_range.toml"));
    assert!(
        message.contains("reserved autoscale elastic lane id range [1, 2)")
            && message.contains("manual lanes outside"),
        "error should identify manual lanes inside the autoscale elastic range: {message}"
    );
}
#[test]
fn autoscale_accepts_sparse_manual_catalog_around_elastic_id_range() {
    let config = parse_actual_config(include_str!("fixtures/autoscale/sparse_catalog.toml"))
        .expect("sparse manual lanes outside the elastic id range should parse");
    let autoscale = config.nexus.autoscale;
    assert!(!autoscale.contains_elastic_lane_id(LaneId::new(2)));
    assert!(autoscale.contains_elastic_lane_id(LaneId::new(3)));
    assert!(autoscale.contains_elastic_lane_id(LaneId::new(5)));
    assert!(!autoscale.contains_elastic_lane_id(LaneId::new(6)));
    assert_eq!(
        config
            .nexus
            .lane_catalog
            .lanes()
            .iter()
            .map(|lane| lane.id)
            .collect::<Vec<_>>(),
        vec![LaneId::new(0), LaneId::new(2), LaneId::new(6)],
        "lane_count and autoscale bounds must not be reinterpreted as active-lane counts"
    );
}
#[test]
fn autoscale_accepts_elastic_id_range_above_initial_catalog_namespace() {
    let config = parse_actual_config(include_str!("fixtures/autoscale/range_above_catalog.toml"))
        .expect("the elastic range may reserve the next id for lifecycle expansion");
    assert_eq!(config.nexus.lane_catalog.lane_count().get(), 4);
    assert!(
        config
            .nexus
            .autoscale
            .contains_elastic_lane_id(LaneId::new(4))
    );
    assert!(
        config
            .nexus
            .lane_catalog
            .lanes()
            .iter()
            .all(|lane| lane.id != LaneId::new(4)),
        "an elastic id is reserved for deterministic creation, not required to be active at startup"
    );
}
#[test]
fn autoscale_rejects_manual_lane_in_sparse_elastic_id_gap() {
    let message =
        autoscale_config_error(include_str!("fixtures/autoscale/manual_in_sparse_gap.toml"));
    assert!(
        message.contains("lane 5 is inside reserved autoscale elastic lane id range [3, 6)"),
        "a sparse catalog must not hide a manual occupant of the reserved id range: {message}"
    );
}
#[test]
fn autoscale_rejects_default_lane_inside_elastic_id_range() {
    let message = autoscale_config_error(include_str!("fixtures/autoscale/default_in_range.toml"));
    assert!(
        message.contains("nexus.routing_policy.default_lane")
            && message.contains("must be below nexus.autoscale.min_lane_id 1"),
        "error should identify non-base default lanes: {message}"
    );
}
#[test]
fn autoscale_rejects_default_lane_above_elastic_id_range() {
    let message =
        autoscale_config_error(include_str!("fixtures/autoscale/default_above_range.toml"));
    assert!(
        message.contains("nexus.routing_policy.default_lane")
            && message.contains("must be below nexus.autoscale.min_lane_id 1"),
        "error should reject high-side default lanes: {message}"
    );
}
#[test]
fn autoscale_rejects_hysteresis_without_gap() {
    let message = autoscale_config_error(include_str!("fixtures/autoscale/no_hysteresis_gap.toml"));
    assert!(
        message.contains("scale_in_latency_ratio must be < scale_out_latency_ratio"),
        "error should identify latency hysteresis violation: {message}"
    );
    assert!(
        message.contains("scale_in_utilization_ratio must be < scale_out_utilization_ratio"),
        "error should identify utilization hysteresis violation: {message}"
    );
}
#[test]
fn autoscale_rejects_hysteresis_that_collapses_after_permille_rounding() {
    let message =
        autoscale_config_error(include_str!("fixtures/autoscale/rounded_hysteresis.toml"));
    assert!(
        message.contains("scale_in_latency_ratio must round below scale_out_latency_ratio"),
        "error should identify collapsed latency hysteresis: {message}"
    );
    assert!(
        message.contains("scale_in_utilization_ratio must round below scale_out_utilization_ratio"),
        "error should identify collapsed utilization hysteresis: {message}"
    );
}
#[test]
fn autoscale_rejects_non_finite_ratios() {
    let message = autoscale_config_error(include_str!("fixtures/autoscale/non_finite_ratios.toml"));
    for field in [
        "scale_out_latency_ratio",
        "scale_in_latency_ratio",
        "scale_out_utilization_ratio",
        "scale_in_utilization_ratio",
    ] {
        assert!(
            message.contains(field),
            "error should identify non-finite autoscale field {field}: {message}"
        );
    }
    assert!(
        message.contains("invalid float value") && message.contains("NaN or infinite"),
        "config reader should reject non-finite autoscale ratios before runtime parse: {message}"
    );
}
#[test]
fn autoscale_rejects_sub_permille_ratios() {
    let message =
        autoscale_config_error(include_str!("fixtures/autoscale/sub_permille_ratios.toml"));
    for field in [
        "scale_out_latency_ratio",
        "scale_in_latency_ratio",
        "scale_out_utilization_ratio",
        "scale_in_utilization_ratio",
    ] {
        assert!(
            message.contains(field),
            "error should identify sub-permille autoscale field {field}: {message}"
        );
    }
    assert!(
        message.contains("1 permille"),
        "error should explain representable permille precision: {message}"
    );
}
#[test]
fn lane_consensus_validator_cap_accepts_boundary() {
    let config = parse_actual_config(include_str!("fixtures/autoscale/validator_cap.toml"))
        .expect("the protocol maximum must remain configurable");
    assert_eq!(config.nexus.staking.max_validators.get(), 128);
}
#[test]
fn lane_consensus_validator_cap_rejects_oversized_staking_roster() {
    let message =
        autoscale_config_error(include_str!("fixtures/autoscale/validator_over_cap.toml"));
    assert!(
        message.contains("nexus.staking.max_validators must be <= 128") && message.contains("129"),
        "error should identify the bounded consensus proof envelope: {message}"
    );
}
#[test]
fn dataspace_fault_tolerance_accepts_largest_bounded_committee() {
    let config = parse_actual_config(include_str!("fixtures/autoscale/bounded_committee.toml"))
        .expect("3f+1=127 must fit the 128-validator protocol envelope");
    assert_eq!(
        config.nexus.dataspace_catalog.entries()[0].fault_tolerance,
        42
    );
}
#[test]
fn dataspace_fault_tolerance_rejects_oversized_committee() {
    let message =
        autoscale_config_error(include_str!("fixtures/autoscale/oversized_committee.toml"));
    assert!(
        message.contains("fault_tolerance 43 requires 130 validators")
            && message.contains("lane consensus cap 128"),
        "error should identify the first oversized 3f+1 committee: {message}"
    );
}
