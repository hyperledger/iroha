//! Validate DA ingest compute-concurrency configuration.

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
fn da_ingest_compute_limit_has_a_nonzero_production_default() {
    let config = parse_actual_config("").expect("default DA ingest config should parse");
    assert_eq!(
        config.torii.da_ingest.max_concurrent_compute_jobs,
        defaults::torii::DA_MAX_CONCURRENT_COMPUTE_JOBS
    );
    assert!(config.torii.da_ingest.max_concurrent_compute_jobs.get() > 0);
}
#[test]
fn da_ingest_compute_limit_override_reaches_actual_config() {
    let config = parse_actual_config(
        r"
[torii.da_ingest]
max_concurrent_compute_jobs = 3
",
    )
    .expect("nonzero DA compute limit should parse");
    assert_eq!(config.torii.da_ingest.max_concurrent_compute_jobs.get(), 3);
}
#[test]
fn da_ingest_compute_limit_rejects_zero() {
    let error = parse_actual_config(
        r"
[torii.da_ingest]
max_concurrent_compute_jobs = 0
",
    )
    .expect_err("zero DA compute limit must be rejected");
    assert!(
        error.contains("max_concurrent_compute_jobs"),
        "unexpected zero-limit diagnostic: {error}"
    );
}
