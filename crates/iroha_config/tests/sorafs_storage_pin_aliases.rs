//! Validate the V1 hard cut for the retired local storage-pin admission policy.

use iroha_config::parameters::{actual::Root as ActualConfig, user::Root as UserConfig};
use iroha_config_base::{env::MockEnv, read::ConfigReader, toml::TomlSource};
use std::path::PathBuf;
fn base_reader() -> ConfigReader {
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/base.toml");
    ConfigReader::new()
        .read_toml_with_extends(base_path)
        .expect("base config should load")
}
fn strip_ansi_codes(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && matches!(chars.peek(), Some('[')) {
            chars.next();
            for next in chars.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
        } else {
            result.push(ch);
        }
    }
    result
}
#[test]
fn retired_storage_pin_config_is_rejected_as_unknown() {
    for (field, value) in [
        ("require_token", "true"),
        ("tokens", "[\"retired-secret\"]"),
        ("allow_cidrs", "[\"127.0.0.1/32\"]"),
    ] {
        let table = format!("[sorafs.storage.pin]\n{field} = {value}\n")
            .parse()
            .expect("retired inline TOML should parse");
        let error = base_reader()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<UserConfig>()
            .expect_err("retired local pin-admission fields must be rejected");
        let message = strip_ansi_codes(&format!("{error:?}"));
        assert!(
            message.contains("unknown parameter: `sorafs.storage.pin"),
            "unexpected retired-field diagnostic for {field}: {message}"
        );
        assert!(
            !message.contains("retired-secret"),
            "unknown-field diagnostics must not disclose retired bearer values"
        );
    }
}
#[test]
fn retired_storage_pin_rate_limit_config_is_rejected_as_unknown() {
    for (field, value) in [
        ("max_requests", "30"),
        ("window_secs", "60"),
        ("ban_secs", "300"),
    ] {
        let table = format!("[sorafs.storage.pin.rate_limit]\n{field} = {value}\n")
            .parse()
            .expect("retired inline TOML should parse");
        let error = base_reader()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<UserConfig>()
            .expect_err("retired local pin rate limits must be rejected");
        let message = strip_ansi_codes(&format!("{error:?}"));
        assert!(
            message.contains("unknown parameter: `sorafs.storage.pin"),
            "unexpected retired-field diagnostic for {field}: {message}"
        );
    }
}
#[test]
fn retired_storage_pin_environment_aliases_are_unvisited() {
    const RETIRED_ALIASES: [&str; 4] = [
        "SORAFS_STORAGE_PIN_REQUIRE_TOKEN",
        "SORAFS_STORAGE_PIN_RATE_LIMIT_MAX_REQUESTS",
        "SORAFS_STORAGE_PIN_RATE_LIMIT_WINDOW_SECS",
        "SORAFS_STORAGE_PIN_RATE_LIMIT_BAN_SECS",
    ];
    let env = MockEnv::new()
        .set(RETIRED_ALIASES[0], "true")
        .set(RETIRED_ALIASES[1], "1")
        .set(RETIRED_ALIASES[2], "1")
        .set(RETIRED_ALIASES[3], "300");
    let _: ActualConfig = base_reader()
        .with_env(env.clone())
        .read_and_complete::<UserConfig>()
        .expect("retired environment aliases are not schema inputs")
        .parse()
        .expect("retired environment aliases cannot alter V1 configuration");
    let unvisited = env.unvisited();
    for alias in RETIRED_ALIASES {
        assert!(
            unvisited.contains(alias),
            "retired environment alias must remain unvisited: {alias}"
        );
    }
}
