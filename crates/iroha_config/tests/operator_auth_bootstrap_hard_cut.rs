//! Enforce the single first-credential operator-token bootstrap configuration surface.

use std::path::PathBuf;

use iroha_config::parameters::{actual::Root as ActualConfig, user::Root as UserConfig};
use iroha_config_base::{read::ConfigReader, toml::TomlSource};

const VALID_BOOTSTRAP_TOKEN: &str = "first-credential-bootstrap-token-01";

fn base_reader() -> ConfigReader {
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/base.toml");
    ConfigReader::new()
        .read_toml_with_extends(base_path)
        .expect("base config should load")
}

#[test]
fn retired_operator_bearer_mode_fields_are_rejected() {
    for (field, value) in [
        ("token_fallback", "\"always\""),
        ("token_source", "\"api\""),
    ] {
        let table = format!("[torii.operator_auth]\n{field} = {value}\n")
            .parse()
            .expect("retired inline TOML should parse");
        let error = base_reader()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<UserConfig>()
            .expect_err("retired operator bearer mode must be unknown");
        let report = format!("{error:?}");
        assert!(
            report.contains("unknown parameter")
                && report.contains(&format!("`torii.operator_auth.{field}`")),
            "unexpected retired-field diagnostic: {report}"
        );
    }
}

#[test]
fn dedicated_operator_bootstrap_tokens_remain_configurable() {
    let table = concat!(
        "[torii.operator_auth]\n",
        "tokens = [\"first-credential-bootstrap-token-01\"]\n",
        "ephemeral_state_capacity = 64\n",
        "credential_capacity = 8\n",
    )
    .parse()
    .expect("operator bootstrap TOML should parse");
    let actual: ActualConfig = base_reader()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .expect("operator bootstrap token should remain configurable")
        .parse()
        .expect("operator bootstrap config should be valid");
    assert_eq!(actual.torii.operator_auth.tokens, [VALID_BOOTSTRAP_TOKEN]);
    assert_eq!(
        actual.torii.operator_auth.ephemeral_state_capacity.get(),
        64
    );
    assert_eq!(actual.torii.operator_auth.credential_capacity.get(), 8);
}

#[test]
fn operator_bootstrap_tokens_are_exact_bounded_visible_values() {
    let too_many = (0
        ..=iroha_config::parameters::defaults::torii::operator_auth::MAX_BOOTSTRAP_TOKENS)
        .map(|index| format!("\"first-credential-bootstrap-token-{index:02}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let cases = [
        "[\"short\"]".to_owned(),
        "[\" first-credential-bootstrap-token-01\"]".to_owned(),
        "[\"first-credential-bootstrap-token-01\", \"first-credential-bootstrap-token-01\"]"
            .to_owned(),
        format!(
            "[\"{}\"]",
            "a".repeat(
                iroha_config::parameters::defaults::torii::operator_auth::BOOTSTRAP_TOKEN_MAX_BYTES
                    + 1
            )
        ),
        format!("[{too_many}]"),
    ];
    for tokens in cases {
        let table = format!("[torii.operator_auth]\ntokens = {tokens}\n")
            .parse()
            .expect("operator auth TOML should parse");
        let user = base_reader()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<UserConfig>()
            .expect("bootstrap token syntax should reach semantic validation");
        let error = user
            .parse()
            .expect_err("malformed bootstrap tokens must be rejected");
        assert!(
            format!("{error:?}").contains("torii.operator_auth.tokens"),
            "unexpected bootstrap-token diagnostic: {error:?}"
        );
    }
}

#[test]
fn operator_auth_ephemeral_state_capacity_must_be_nonzero() {
    let table = "[torii.operator_auth]\nephemeral_state_capacity = 0\n"
        .parse()
        .expect("operator auth TOML should parse");
    let _error = base_reader()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .expect_err("zero ephemeral state capacity must be rejected");
}

#[test]
fn operator_auth_credential_capacity_must_be_nonzero() {
    let table = "[torii.operator_auth]\ncredential_capacity = 0\n"
        .parse()
        .expect("operator auth TOML should parse");
    let _error = base_reader()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .expect_err("zero credential capacity must be rejected");
}

#[test]
fn operator_auth_capacities_have_sane_upper_bounds() {
    for (field, value) in [
        (
            "ephemeral_state_capacity",
            iroha_config::parameters::defaults::torii::operator_auth::MAX_EPHEMERAL_STATE_CAPACITY
                + 1,
        ),
        (
            "credential_capacity",
            iroha_config::parameters::defaults::torii::operator_auth::MAX_CREDENTIAL_CAPACITY + 1,
        ),
    ] {
        let table = format!("[torii.operator_auth]\n{field} = {value}\n")
            .parse()
            .expect("operator auth TOML should parse");
        let user = base_reader()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<UserConfig>()
            .expect("operator-auth capacity syntax should reach semantic validation");
        let _error = user
            .parse()
            .expect_err("oversized operator-auth capacity must be rejected");
    }
}

#[test]
fn operator_auth_lockout_durations_must_be_nonzero() {
    for field in ["lockout_window_secs", "lockout_duration_secs"] {
        let table = format!("[torii.operator_auth]\n{field} = 0\n")
            .parse()
            .expect("operator auth TOML should parse");
        let user = base_reader()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<UserConfig>()
            .expect("lockout duration syntax should reach semantic validation");
        let error = user
            .parse()
            .expect_err("zero lockout duration must be rejected");
        assert!(format!("{error:?}").contains(field));
    }
}
