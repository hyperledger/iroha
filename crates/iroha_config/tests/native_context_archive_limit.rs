//! Validate mandatory native context archive size configuration.
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
fn native_context_archive_limit_has_a_nonzero_production_default() {
    let config =
        parse_actual_config("").expect("default native context archive config should parse");
    assert_eq!(
        config.kura.native_context_archive_max_bytes,
        defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES
    );
    assert!(config.kura.native_context_archive_max_bytes.get() > 0);
}
#[test]
fn native_context_archive_limit_override_reaches_actual_config() {
    let config = parse_actual_config(
        r"
[kura]
native_context_archive_max_bytes = 3
",
    )
    .expect("nonzero native context archive limit should parse");
    assert_eq!(config.kura.native_context_archive_max_bytes.get(), 3);
}
#[test]
fn native_context_archive_limit_rejects_zero() {
    let error = parse_actual_config(
        r"
[kura]
native_context_archive_max_bytes = 0
",
    )
    .expect_err("zero native context archive limit must be rejected");
    assert!(
        error.contains("native_context_archive_max_bytes"),
        "unexpected zero-limit diagnostic: {error}"
    );
}

#[test]
fn history_checkpoint_cache_count_defaults_and_bounds_reach_actual_config() {
    let default = parse_actual_config("").unwrap();
    assert_eq!(default.kura.history_checkpoint_cache_capacity.get(), 8192);
    for count in [
        1,
        8192,
        defaults::kura::MAX_HISTORY_CHECKPOINT_CACHE_CAPACITY,
    ] {
        let config = parse_actual_config(&format!(
            "[kura]\nhistory_checkpoint_cache_capacity = {count}\n"
        ))
        .unwrap();
        assert_eq!(config.kura.history_checkpoint_cache_capacity.get(), count);
    }
    for count in [0, defaults::kura::MAX_HISTORY_CHECKPOINT_CACHE_CAPACITY + 1] {
        let error = parse_actual_config(&format!(
            "[kura]\nhistory_checkpoint_cache_capacity = {count}\n"
        ))
        .expect_err("unbounded or zero checkpoint slot counts must be rejected");
        assert!(
            error.contains("history_checkpoint_cache_capacity"),
            "{error}"
        );
    }
}
