//! Validate Torii transaction-ingress resource-corridor configuration.

use iroha_config::parameters::{actual::Root as ActualConfig, defaults, user::Root as UserConfig};
use iroha_config_base::{read::ConfigReader, toml::TomlSource};
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
#[test]
fn transaction_ingress_limits_have_nonzero_production_defaults() {
    let config = parse_actual_config("").expect("default transaction-ingress config should parse");
    assert_eq!(
        config.torii.transaction_ingress.max_concurrent_compute_jobs,
        defaults::torii::TRANSACTION_INGRESS_MAX_CONCURRENT_COMPUTE_JOBS
    );
    assert_eq!(
        config.torii.transaction_ingress.max_batch_transactions,
        defaults::torii::TRANSACTION_INGRESS_MAX_BATCH_TRANSACTIONS
    );
}
#[test]
fn transaction_ingress_limit_overrides_reach_actual_config() {
    let config = parse_actual_config(
        r"
[torii.transaction_ingress]
max_concurrent_compute_jobs = 3
max_batch_transactions = 17
",
    )
    .expect("nonzero transaction-ingress limits should parse");
    assert_eq!(
        config
            .torii
            .transaction_ingress
            .max_concurrent_compute_jobs
            .get(),
        3
    );
    assert_eq!(
        config
            .torii
            .transaction_ingress
            .max_batch_transactions
            .get(),
        17
    );
}
#[test]
fn transaction_ingress_compute_limit_rejects_zero() {
    let error = parse_actual_config(
        r"
[torii.transaction_ingress]
max_concurrent_compute_jobs = 0
",
    )
    .expect_err("zero transaction-ingress compute limit must be rejected");
    assert!(
        error.contains("max_concurrent_compute_jobs"),
        "unexpected zero-limit diagnostic: {error}"
    );
}
#[test]
fn transaction_ingress_batch_limit_rejects_zero() {
    let error = parse_actual_config(
        r"
[torii.transaction_ingress]
max_batch_transactions = 0
",
    )
    .expect_err("zero transaction batch limit must be rejected");
    assert!(
        error.contains("max_batch_transactions"),
        "unexpected zero-limit diagnostic: {error}"
    );
}
