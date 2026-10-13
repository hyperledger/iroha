use super::*;
use crate::json_macros::JsonSerialize;
use clap::Parser;
use eyre::eyre;
use iroha::crypto::{Algorithm, KeyPair};
use iroha::data_model::{
    Level,
    account::AccountId,
    events::{EventFilterBox, data::DataEventFilter, execute_trigger::ExecuteTriggerEventFilter},
    isi::Log,
    transaction::Executable,
};
use iroha_i18n::{Bundle, Language, Localizer};
use iroha_model_base::chain::ChainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::topology::DataSpaceId;
use std::{
    fs,
    num::NonZeroU64,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;
use url::Url;
fn fixture_key_pair(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("fixture seed must derive a valid keypair")
}
fn sample_canonical_i105_literal(seed: u8) -> String {
    AccountId::new(fixture_key_pair(seed).public_key().clone())
        .canonical_i105()
        .expect("canonical I105")
}
fn sample_noncanonical_i105_literal(seed: u8) -> String {
    sample_canonical_i105_literal(seed).replacen("sora", "ｓｏｒａ", 1)
}
#[test]
fn local_sorafs_pack_accepts_no_config_and_rejects_transaction_globals() {
    let args = Args::try_parse_from([
        "iroha",
        "--machine",
        "app",
        "sorafs",
        "toolkit",
        "pack",
        "public-assets",
    ])
    .expect("parse local CAR pack");
    assert!(matches!(
        &args.command,
        Command::App(app::Command::Sorafs(commands::sorafs::Command::Toolkit(
            commands::sorafs::toolkit::Command::Pack(_)
        )))
    ));
    reject_irrelevant_local_tool_globals(&args, "app sorafs toolkit pack")
        .expect("local pack needs no client context");
    let mut with_config = args;
    with_config.config = Some(PathBuf::from("must-not-read.toml"));
    assert!(reject_irrelevant_local_tool_globals(&with_config, "app sorafs toolkit pack").is_err());
    with_config.config = None;
    with_config.emit_instructions = true;
    assert!(reject_irrelevant_local_tool_globals(&with_config, "app sorafs toolkit pack").is_err());
}
#[test]
fn bounded_cli_input_accepts_exact_limit() {
    let input = [0xA5; 32];
    let mut reader = input.as_slice();
    let bytes = read_cli_input_bounded(&mut reader, input.len(), "test stdin")
        .expect("an exact-boundary stdin document is accepted");
    assert_eq!(bytes, input);
}
#[test]
fn bounded_cli_input_rejects_limit_plus_one() {
    let input = [0xA5; 33];
    let mut reader = input.as_slice();
    let error = read_cli_input_bounded(&mut reader, input.len() - 1, "test stdin")
        .expect_err("stdin growth beyond the boundary must be rejected");
    assert!(
        error
            .to_string()
            .contains("first-release limit of 32 bytes")
    );
}
#[test]
fn bounded_cli_file_rejects_sparse_limit_plus_one_before_reading() {
    let file = NamedTempFile::new().expect("create sparse CLI input");
    file.as_file()
        .set_len((MAX_CLI_STDIN_BYTES_V1 + 1) as u64)
        .expect("set sparse CLI input length");
    let error = read_cli_file_bounded(file.path(), "test file")
        .expect_err("limit plus one must be rejected from metadata");
    assert!(error.to_string().contains("first-release limit"));
}
#[test]
fn cli_json_preflight_rejects_sequence_limit_plus_one() {
    let mut input = String::with_capacity(2 * MAX_CLI_JSON_SEQUENCE_ELEMENTS_V1 + 3);
    input.push('[');
    for index in 0..=MAX_CLI_JSON_SEQUENCE_ELEMENTS_V1 {
        if index != 0 {
            input.push(',');
        }
        input.push('0');
    }
    input.push(']');
    let error = parse_json::<Vec<u8>>(&input)
        .expect_err("the typed decoder must not receive an oversized sequence");
    assert!(error.to_string().contains("admit JSON input"));
}
#[test]
fn parse_register_account_id_accepts_canonical_i105_literal() {
    let literal = sample_canonical_i105_literal(23);
    let parsed = parse_register_account_id(&literal).expect("register account id");
    assert_eq!(parsed.to_string(), literal);
}
#[test]
fn data_verifying_key_filter_parser_rejects_unsafe_backend_and_name() {
    let id = trigger::parse_data_verifying_key_id("halo2/ipa: vk_main ")
        .expect("valid verifying-key event filter id");
    assert_eq!(id.backend.as_str(), "halo2/ipa");
    assert_eq!(id.name, "vk_main");
    for spec in [
        "mock/dev:vk_main",
        "halo2/ipa/orchard:vk_main",
        " halo2/ipa:vk_main",
        "halo2/ipa :vk_main",
        ":vk_main",
        "halo2/ipa:",
        "halo2/ipa:   ",
        "halo2/ipa:vk:main",
        "halo2/ipa",
    ] {
        let err = trigger::parse_data_verifying_key_id(spec)
            .expect_err("unsafe verifying-key event filter id must reject");
        let message = err.to_string();
        assert!(
            message.contains("--data-verifying-key"),
            "unexpected error for {spec:?}: {message}"
        );
    }
}
#[test]
fn data_proof_filter_parser_rejects_unsafe_backend_and_hash() {
    let id = trigger::parse_data_proof_id(&format!("halo2/ipa:0x{}", "A5".repeat(32)))
        .expect("valid proof event filter id");
    assert_eq!(id.backend.as_str(), "halo2/ipa");
    assert_eq!(id.proof_hash, [0xA5; 32]);
    for spec in [
        format!("mock/dev:{}", "a".repeat(64)),
        format!("groth16/bls12-377:{}", "a".repeat(64)),
        format!(" halo2/ipa:{}", "a".repeat(64)),
        format!("halo2/ipa:{}", "a".repeat(63)),
        format!("halo2/ipa:{}", "z".repeat(64)),
        "halo2/ipa:".to_string(),
        ":aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        "halo2/ipa".to_string(),
    ] {
        let err = trigger::parse_data_proof_id(&spec)
            .expect_err("unsafe proof event filter id must reject");
        let message = err.to_string();
        assert!(
            message.contains("--data-proof")
                || message.contains("unsupported verifier-registry label")
                || message.contains("invalid hex"),
            "unexpected error for {spec:?}: {message}"
        );
    }
}
#[derive(Clone, Copy, JsonSerialize)]
struct DummyEvent;
#[derive(clap::Parser, Debug)]
struct QuantityParserHarness {
    #[arg(long)]
    quantity: iroha_primitives::numeric::Quantity,
}
#[derive(clap::Parser, Debug)]
struct FxCorridorDomainParserHarness {
    #[arg(
            long = "allowed-destination-alias-domain",
            required = true,
            value_parser = parse_domain_id_literal
        )]
    domains: Vec<DomainId>,
}
#[test]
fn fx_corridor_domain_arguments_use_the_canonical_domain_parser() {
    let domain = DomainId::try_new("hbl", "sbp").expect("canonical domain");
    let literal = domain.to_string();
    let parsed = FxCorridorDomainParserHarness::try_parse_from([
        "fx-corridor-domain-parser",
        "--allowed-destination-alias-domain",
        literal.as_str(),
    ])
    .expect("canonical fully-qualified domain must parse");
    assert_eq!(parsed.domains, vec![domain]);
    let error = FxCorridorDomainParserHarness::try_parse_from([
        "fx-corridor-domain-parser",
        "--allowed-destination-alias-domain",
        "hbl",
    ])
    .expect_err("a domain without its dataspace must fail during argument parsing");
    assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
}
#[test]
fn cli_quantities_accept_canonical_boundaries_and_reject_signed_or_oversized_values() {
    for value in [
        "0",
        "1.25",
        "0.1234567890123456789012345678",
        "340282366920938463463374607431768211455",
    ] {
        let parsed = QuantityParserHarness::try_parse_from([
            "quantity-parser",
            &format!("--quantity={value}"),
        ])
        .unwrap_or_else(|error| panic!("canonical quantity `{value}` was rejected: {error}"));
        assert_eq!(parsed.quantity.to_string(), value);
    }
    let oversized_mantissa = format!("1{}", "0".repeat(200));
    for value in ["-0.01", "0.12345678901234567890123456789"]
        .into_iter()
        .chain(std::iter::once(oversized_mantissa.as_str()))
    {
        let error = QuantityParserHarness::try_parse_from([
            "quantity-parser",
            &format!("--quantity={value}"),
        ])
        .expect_err("invalid ledger quantity must fail during argument parsing");
        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
    }
}
pub(crate) fn test_context(output_format: CliOutputFormat) -> PrintJsonContext<Vec<u8>, Vec<u8>> {
    PrintJsonContext {
        write: Vec::new(),
        err_write: Vec::new(),
        config: fallback_config(),
        filesystem_config: client_config::FilesystemConfig::default(),
        offline_fallback: false,
        operator_key_pair: None,
        transaction_metadata: None,
        fee_payment: FeePaymentArgs::default(),
        input_instructions: false,
        output_instructions: false,
        output_format,
        json_lines: false,
        i18n: Localizer::new(Bundle::Cli, Language::English),
    }
}
#[test]
fn operator_private_key_file_is_an_explicit_global_runtime_option() {
    let args = Args::try_parse_from([
        "iroha",
        "--operator-private-key-file",
        "/run/secrets/iroha/operator.key",
        "ops",
        "sumeragi",
        "status",
    ])
    .expect("parse explicit operator credential path");
    assert_eq!(
        args.operator_private_key_file.as_deref(),
        Some(Path::new("/run/secrets/iroha/operator.key"))
    );
    let args = Args::try_parse_from(["iroha", "ops", "sumeragi", "status"])
        .expect("operator credential remains optional for non-operator commands");
    assert!(args.operator_private_key_file.is_none());
    assert!(args.operator_private_key_fd.is_none());
    assert!(
        load_runtime_operator_key(&args)
            .expect("no inferred signer")
            .is_none()
    );
}
#[test]
fn operator_private_key_fd_is_explicit_bounded_and_exclusive() {
    for fd in ["3", "65535"] {
        let args = Args::try_parse_from([
            "iroha",
            "--operator-private-key-fd",
            fd,
            "ops",
            "sumeragi",
            "status",
        ])
        .expect("bounded operator descriptor");
        assert_eq!(args.operator_private_key_fd, Some(fd.parse().unwrap()));
        assert!(args.operator_private_key_file.is_none());
    }
    for fd in ["0", "1", "2", "65536", "-1", "3.0", "not-a-descriptor"] {
        assert!(
            Args::try_parse_from([
                "iroha",
                "--operator-private-key-fd",
                fd,
                "ops",
                "sumeragi",
                "status",
            ])
            .is_err()
        );
    }
    assert!(
        Args::try_parse_from([
            "iroha",
            "--operator-private-key-fd",
            "3",
            "--operator-private-key-file",
            "/run/secrets/iroha/operator.key",
            "ops",
            "sumeragi",
            "status",
        ])
        .is_err()
    );
}
#[test]
fn credential_free_commands_reject_operator_fd_without_reading_it() {
    let args = Args::try_parse_from([
        "iroha",
        "--operator-private-key-fd",
        "65535",
        "ops",
        "sumeragi",
        "status",
    ])
    .expect("parse only; descriptor is never opened");
    assert!(reject_irrelevant_local_tool_globals(&args, "app sorafs toolkit pack").is_err());
    for error in [
        reject_irrelevant_taira_doctor_globals(&args).unwrap_err(),
        reject_irrelevant_taira_public_reset_globals(&args).unwrap_err(),
    ] {
        assert!(format!("{error:?}").contains("--operator-private-key-fd"));
    }
}
#[cfg(unix)]
#[test]
fn inherited_operator_key_load_installs_the_explicit_run_context_signer() {
    use iroha::crypto::ExposedPrivateKey;
    use std::{
        io::{Seek as _, SeekFrom},
        os::{fd::AsRawFd as _, unix::fs::PermissionsExt as _},
    };
    let directory = tempfile::tempdir().expect("private operator fixture");
    let path = directory.path().join("operator.key");
    let key_pair = fixture_key_pair(0x73);
    let encoded =
        zeroize::Zeroizing::new(ExposedPrivateKey(key_pair.private_key().clone()).to_string());
    fs::write(&path, encoded.as_bytes()).expect("write explicit signer");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("owner-only signer");
    let mut file = fs::File::open(&path).expect("read-only inherited file");
    file.seek(SeekFrom::Start(5)).expect("caller offset");
    let fd = file.as_raw_fd().to_string();
    let args = Args::try_parse_from([
        "iroha",
        "--operator-private-key-fd",
        &fd,
        "ops",
        "sumeragi",
        "status",
    ])
    .expect("parse inherited signer");
    let mut context = test_context(CliOutputFormat::Json);
    context.operator_key_pair = load_runtime_operator_key(&args).expect("load real descriptor");
    let client = context.client_from_config().expect("valid command context");
    assert_eq!(
        client.operator_key_pair().map(KeyPair::public_key),
        Some(key_pair.public_key())
    );
    assert_ne!(client.key_pair().public_key(), key_pair.public_key());
    assert_eq!(client.network_id(), &context.config.network_id);
    assert_eq!(
        file.stream_position().expect("retained caller descriptor"),
        5
    );
}
#[test]
fn run_context_installs_only_the_explicit_operator_key() {
    let mut context = test_context(CliOutputFormat::Json);
    assert!(
        context
            .client_from_config()
            .expect("valid command context")
            .operator_key_pair()
            .is_none()
    );
    let operator_key_pair = fixture_key_pair(0x71);
    context.operator_key_pair = Some(operator_key_pair.clone());
    let client = context.client_from_config().expect("valid command context");
    assert_eq!(
        client.operator_key_pair().map(KeyPair::public_key),
        Some(operator_key_pair.public_key())
    );
    assert_eq!(client.network_id(), &context.config.network_id);
    assert_ne!(
        client.key_pair().public_key(),
        operator_key_pair.public_key()
    );
}
#[test]
fn run_context_returns_invalid_client_configuration() {
    let mut context = test_context(CliOutputFormat::Json);
    context.config.torii_api_url = Url::parse("ftp://invalid.example/").expect("URL fixture");
    let error = context
        .client_from_config()
        .expect_err("invalid endpoint must be returned before command dispatch");
    assert!(matches!(
        error.downcast_ref::<iroha::Error>(),
        Some(iroha::Error::Context(
            iroha::client::AuthorityContextError::UnsupportedEndpointScheme { .. }
        ))
    ));
}
fn account_with_seed(domain_literal: &str, seed: u8) -> AccountId {
    let _domain =
        iroha_model_base::domain::DomainId::try_new(domain_literal, "universal").expect("domain");
    let key_pair = fixture_key_pair(seed);
    AccountId::new(key_pair.public_key().clone())
}
#[test]
fn fixture_key_pair_uses_checked_seed_derivation() {
    assert_eq!(fixture_key_pair(7).algorithm(), Algorithm::Ed25519);
    assert!(
        KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
        "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
    );
}
#[test]
fn output_format_override_from_args_parses_flags() {
    assert_eq!(
        output_format_override_from_args(["--output-format", "text"]),
        (Some(OutputFormatArg::Text), false)
    );
    assert_eq!(
        output_format_override_from_args(["--output-format=json"]),
        (Some(OutputFormatArg::Json), false)
    );
    assert_eq!(
        output_format_override_from_args(["account", "list", "-o", "jsonl"]),
        (Some(OutputFormatArg::Jsonl), false)
    );
    assert_eq!(
        output_format_override_from_args(["-otext", "--machine"]),
        (Some(OutputFormatArg::Text), true)
    );
    assert_eq!(
        output_format_override_from_args(["--machine", "--", "-o", "text"]),
        (None, true),
        "arguments after `--` are values, not options"
    );
}
#[test]
fn output_selection_defaults_to_text_only_on_an_interactive_terminal() {
    let text = OutputSelection {
        format: CliOutputFormat::Text,
        json_lines: false,
    };
    let json = OutputSelection {
        format: CliOutputFormat::Json,
        json_lines: false,
    };
    assert_eq!(OutputSelection::resolve(None, false, true), text);
    assert_eq!(OutputSelection::resolve(None, false, false), json);
    assert_eq!(
        OutputSelection::resolve(None, true, true),
        json,
        "--machine never depends on terminal detection"
    );
    assert_eq!(
        OutputSelection::resolve(Some(OutputFormatArg::Json), false, true),
        json
    );
    assert_eq!(
        OutputSelection::resolve(Some(OutputFormatArg::Jsonl), false, true),
        OutputSelection {
            format: CliOutputFormat::Json,
            json_lines: true,
        }
    );
}
#[test]
fn output_format_is_a_global_short_option() {
    for argv in [
        vec!["iroha", "-o", "json", "tools", "version"],
        vec!["iroha", "tools", "version", "-o", "json"],
        vec!["iroha", "tools", "version", "--output-format", "json"],
    ] {
        let args = Args::try_parse_from(&argv).expect("parse args");
        assert_eq!(args.output_format, Some(OutputFormatArg::Json), "{argv:?}");
        assert_eq!(effective_output_format(&args), CliOutputFormat::Json);
    }
    let args = Args::try_parse_from(["iroha", "--machine", "tools", "version"]).unwrap();
    assert_eq!(effective_output_format(&args), CliOutputFormat::Json);
}
#[test]
fn instruction_pipeline_flags_are_unambiguous_long_options() {
    let args = Args::try_parse_from([
        "iroha",
        "--stdin-instructions",
        "--emit-instructions",
        "tx",
        "ping",
        "--msg",
        "hi",
    ])
    .expect("parse instruction pipeline flags");
    assert!(args.stdin_instructions);
    assert!(args.emit_instructions);
    for retired in [
        ["iroha", "-i", "tx"],
        ["iroha", "--input", "tx"],
        ["iroha", "--output", "tx"],
    ] {
        assert!(Args::try_parse_from(retired).is_err(), "{retired:?}");
    }
}
#[test]
fn positive_counts_reject_zero() {
    assert_eq!(positive_u64("1"), Ok(1));
    assert_eq!(positive_u64("500"), Ok(500));
    assert!(positive_u64("0").is_err());
    assert!(positive_u64("-1").is_err());
    assert!(positive_u64("many").is_err());
    for flag in ["--limit", "--fetch-size"] {
        assert!(
            Args::try_parse_from(["iroha", "ledger", "peer", "list", "all", flag, "0"]).is_err(),
            "{flag} 0 must be rejected while parsing"
        );
    }
}
#[test]
fn json_lines_rendering_prints_array_elements_one_per_line() {
    let rendered =
        render_json_output(&norito::json!([{"id": 1}, {"id": 2}]), true).expect("render");
    assert_eq!(rendered, "{\"id\":1}\n{\"id\":2}\n");
    let rendered = render_json_output(&norito::json!({"id": 1}), true).expect("render");
    assert_eq!(rendered, "{\"id\":1}\n");
    let pretty = render_json_output(&norito::json!({"id": 1}), false).expect("render");
    assert!(
        pretty.ends_with('\n') && pretty.contains("\"id\": 1"),
        "{pretty}"
    );
}
#[test]
fn command_errors_render_each_cause_once_with_a_causes_array() {
    let inner = eyre!("tcp connect error: Connection refused");
    let embedded = inner.wrap_err("Failed to send request: tcp connect error: Connection refused");
    let outer = embedded.wrap_err("Torii node capability probe failed");
    let report = command_error_report(&outer);
    let description = describe_cli_error(&report);
    assert_eq!(description.message, "Torii node capability probe failed");
    assert_eq!(
        description.causes,
        vec!["Failed to send request: tcp connect error: Connection refused".to_owned()],
        "a cause already contained in a shown message is not repeated"
    );
    let text = render_cli_error(
        &report,
        OutputSelection {
            format: CliOutputFormat::Text,
            json_lines: false,
        },
    );
    assert_eq!(text.kind, CliErrorKind::Command);
    assert_eq!(
        text.output.matches("Connection refused").count(),
        1,
        "{}",
        text.output
    );
    assert!(
        text.output
            .starts_with("error: Torii node capability probe failed\n")
    );
    let json = render_cli_error(
        &report,
        OutputSelection {
            format: CliOutputFormat::Json,
            json_lines: true,
        },
    );
    assert_eq!(json.output.lines().count(), 1, "jsonl errors are one line");
    let value: norito::json::Value = norito::json::from_str(json.output.trim()).unwrap();
    assert_eq!(
        value
            .pointer("/error/message")
            .and_then(norito::json::Value::as_str),
        Some("Torii node capability probe failed")
    );
    assert_eq!(
        value
            .pointer("/error/causes")
            .and_then(norito::json::Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        value
            .pointer("/error/exit_code")
            .and_then(norito::json::Value::as_u64),
        Some(1)
    );
}
#[test]
fn config_errors_keep_their_causes_and_hint() {
    let report = Report::new(MainError::Config)
        .attach("missing exact network identity; configure exactly one of network_id or network_id_file")
        .change_context(MainError::Config)
        .attach_opaque(CliHint("pass `--config <PATH>`".to_owned()));
    let description = describe_cli_error(&report);
    assert_eq!(description.message, "Failed to load config");
    assert_eq!(
        description.causes,
        vec![
            "missing exact network identity; configure exactly one of network_id or network_id_file"
                .to_owned()
        ]
    );
    assert_eq!(description.hints, vec!["pass `--config <PATH>`".to_owned()]);
    let text = render_cli_error(
        &report,
        OutputSelection {
            format: CliOutputFormat::Text,
            json_lines: false,
        },
    );
    assert!(
        text.output
            .contains("Caused by:\n    missing exact network identity")
    );
    assert!(text.output.contains("hint: pass `--config <PATH>`"));
    assert_eq!(text.kind.exit_code(), 3);
}
#[test]
fn argument_errors_keep_clap_tips_readable() {
    let error = Args::try_parse_from(["iroha", "acount"]).expect_err("typo must fail");
    let report = Report::new(MainError::CliArgs(error.render().to_string()));
    let text = render_cli_error(
        &report,
        OutputSelection {
            format: CliOutputFormat::Text,
            json_lines: false,
        },
    );
    assert!(
        text.output
            .starts_with("error: unrecognized subcommand 'acount'")
    );
    assert!(text.output.contains("tip:"), "{}", text.output);
    assert!(!text.output.contains("\\n"));
    let description = describe_cli_error(&report);
    assert_eq!(description.message, "unrecognized subcommand 'acount'");
    assert!(
        description
            .hints
            .iter()
            .any(|hint| hint.contains("'account'")),
        "{description:?}"
    );
    assert_eq!(
        render_cli_error(&report, OutputSelection::resolve(None, true, false))
            .kind
            .exit_code(),
        4
    );
}
#[test]
fn missing_subcommand_is_reported_as_help() {
    let error = Args::try_parse_from(["iroha", "account"]).expect_err("group needs a subcommand");
    assert_eq!(
        error.kind(),
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    );
    assert!(error.render().to_string().contains("Usage: iroha account"));
}
#[test]
fn raw_domain_registration_command_is_not_parseable() {
    assert!(
        Args::try_parse_from([
            "iroha",
            "ledger",
            "domain",
            "register",
            "--id",
            "planned.universal",
        ])
        .is_err(),
        "ordinary domain creation must use `app alias setup`"
    );
}
#[test]
fn retired_sumeragi_debug_commands_are_not_parseable() {
    for command in [
        ["iroha", "ops", "sumeragi", "collectors"].as_slice(),
        ["iroha", "ops", "sumeragi", "rbc"].as_slice(),
        ["iroha", "ops", "sumeragi", "rbc", "sessions"].as_slice(),
    ] {
        assert!(
            Args::try_parse_from(command).is_err(),
            "retired Sumeragi debug command leaked: {command:?}"
        );
    }
}
#[test]
fn fallback_config_derives_checked_signing_key() {
    let config = fallback_config();
    assert_eq!(
        config.http_transport_policy,
        iroha::config::HttpTransportPolicy::Ordinary
    );
    let payload = b"offline fallback config signing smoke";
    let signature = iroha_crypto::Signature::try_new(config.key_pair.private_key(), payload)
        .expect("fallback signing key should sign");
    signature
        .verify(config.key_pair.public_key(), payload)
        .expect("fallback signature should verify");
}
#[test]
fn configuration_json_reports_selected_http_transport_policy() {
    let mut config = fallback_config();
    let filesystem = client_config::FilesystemConfig::default();
    for policy in [
        iroha::config::HttpTransportPolicy::Ordinary,
        iroha::config::HttpTransportPolicy::DirectLoopback,
    ] {
        config.http_transport_policy = policy;
        let json = config_to_json(&config, &filesystem).unwrap();
        assert_eq!(
            json.get("http_transport_policy")
                .and_then(norito::json::Value::as_str),
            Some(policy.as_str())
        );
    }
}
#[test]
fn fallback_config_is_limited_to_local_commands() {
    let args = Args::try_parse_from([
        "iroha",
        "app",
        "da",
        "rent-quote",
        "--gib",
        "1",
        "--months",
        "1",
    ])
    .expect("parse offline rent quote");
    assert!(args.command.allows_fallback_config());
    for command in [
        vec![
            "iroha",
            "app",
            "sorafs",
            "reserve",
            "quote",
            "--storage-class",
            "hot",
            "--tier",
            "tier-a",
            "--gib",
            "1",
        ],
        vec![
            "iroha",
            "app",
            "sorafs",
            "reserve",
            "ledger",
            "--quote",
            "reserve-quote.json",
            "--provider-account",
            "provider",
            "--treasury-account",
            "treasury",
            "--reserve-account",
            "reserve",
            "--asset-definition",
            "xor",
        ],
        vec![
            "iroha",
            "app",
            "sorafs",
            "reserve",
            "lifecycle",
            "--quote",
            "reserve-quote.json",
        ],
    ] {
        let args = Args::try_parse_from(command).expect("parse offline SoraFS reserve command");
        assert!(args.command.allows_fallback_config());
    }
    let args = Args::try_parse_from([
        "iroha",
        "app",
        "taikai",
        "cek-rotate",
        "--event-id",
        "demo-event",
        "--stream-id",
        "stream-1",
        "--kms-profile",
        "kms-demo",
        "--new-wrap-key-label",
        "wrap-v2",
        "--effective-segment",
        "42",
        "--out",
        "receipt.to",
    ])
    .expect("parse offline taikai cek rotation");
    assert!(args.command.allows_fallback_config());
    let args = Args::try_parse_from([
        "iroha",
        "app",
        "taikai",
        "ingest",
        "watch",
        "--source-dir",
        ".",
        "--event-id",
        "demo-event",
        "--stream-id",
        "stream-1",
        "--rendition-id",
        "1080p-main",
    ])
    .expect("parse offline taikai watcher");
    assert!(args.command.allows_fallback_config());
    let args = Args::try_parse_from([
        "iroha",
        "app",
        "taikai",
        "ingest",
        "watch",
        "--source-dir",
        ".",
        "--event-id",
        "demo-event",
        "--stream-id",
        "stream-1",
        "--rendition-id",
        "1080p-main",
        "--publish-da",
    ])
    .expect("parse publishing taikai watcher");
    assert!(!args.command.allows_fallback_config());
    let args = Args::try_parse_from(["iroha", "tools", "address", "convert", "sora1"])
        .expect("parse address conversion");
    assert!(args.command.allows_fallback_config());
    let args = Args::try_parse_from(["iroha", "app", "zk", "roots", "--asset-id", "asset#domain"])
        .expect("parse runtime ZK roots command");
    assert!(!args.command.allows_fallback_config());
    let args = Args::try_parse_from([
        "iroha",
        "tx",
        "status",
        "--hash",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ])
    .expect("parse runtime tx status");
    assert!(!args.command.allows_fallback_config());
    let args = Args::try_parse_from([
        "iroha",
        "--machine",
        "contract",
        "manifest",
        "build",
        "--code-file",
        "contract.to",
        "--out",
        "contract.manifest.json",
    ])
    .expect("parse local contract manifest build");
    assert!(args.command.allows_fallback_config());
    assert!(args.command.allows_fallback_config_in_machine_mode());
    let network_id = iroha::data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"local-contract-test",
        )),
    )
    .to_string();
    for command in [
        vec![
            "iroha",
            "--machine",
            "contract",
            "derive-address",
            "--authority",
            "fixture-authority",
            "--deploy-nonce",
            "1",
            "--network-id",
            &network_id,
            "--chain-discriminant",
            "753",
        ],
        vec![
            "iroha",
            "--machine",
            "contract",
            "debug-view",
            "--code-file",
            "contract.to",
            "--entrypoint",
            "show",
        ],
        vec![
            "iroha",
            "--machine",
            "contract",
            "debug-call",
            "--code-file",
            "contract.to",
            "--entrypoint",
            "run",
        ],
        vec![
            "iroha",
            "--machine",
            "contract",
            "simulate",
            "--authority",
            "fixture-authority",
            "--private-key",
            "fixture-private-key",
            "--code-file",
            "contract.to",
            "--gas-limit",
            "1",
        ],
    ] {
        let args = Args::try_parse_from(command).expect("parse local contract command");
        assert!(args.command.allows_fallback_config());
        assert!(args.command.allows_fallback_config_in_machine_mode());
    }
    let code_hash =
        hex::encode(iroha_crypto::Hash::new(b"fallback-manifest-query-fixture").as_ref());
    let args = Args::try_parse_from([
        "iroha",
        "contract",
        "manifest",
        "get",
        "--dataspace-id",
        "0",
        "--code-hash",
        &code_hash,
    ])
    .expect("parse on-chain contract manifest query");
    assert!(!args.command.allows_fallback_config());
    assert!(!args.command.allows_fallback_config_in_machine_mode());
}
#[test]
fn vk_register_and_update_help_documents_namespace() {
    for action in ["register", "update"] {
        let err = Args::try_parse_from(["iroha", "app", "zk", "vk", action, "--help"])
            .expect_err("--help must return rendered command help");
        assert_eq!(err.kind(), ErrorKind::DisplayHelp);
        let help = err.to_string();
        assert!(
            help.contains("namespace") && help.contains("core") && help.contains("non-empty"),
            "{action} help must document namespace default and validation:\n{help}"
        );
    }
}
#[test]
fn tx_status_wait_is_explicit() {
    let args = Args::try_parse_from([
        "iroha",
        "tx",
        "status",
        "--hash",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ])
    .expect("parse tx status");
    let Command::Tx(transaction::Command::Status(status)) = args.command else {
        panic!("expected tx status command");
    };
    assert!(!status.wait.wait);
    assert!(status.wait.is_enabled());
    assert_eq!(status.scope, None);
}
#[test]
fn tx_status_scope_is_explicit_and_cannot_override_wait_routing() {
    let args = Args::try_parse_from([
        "iroha",
        "tx",
        "status",
        "--hash",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--scope",
        "local",
    ])
    .expect("parse explicitly local tx status");
    let Command::Tx(transaction::Command::Status(status)) = args.command else {
        panic!("expected tx status command");
    };
    assert_eq!(status.scope, Some(transaction::StatusScope::Local));
    let error = Args::try_parse_from([
        "iroha",
        "tx",
        "status",
        "--hash",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--scope",
        "global",
        "--wait",
    ])
    .expect_err("explicit scope must not override transaction wait routing");
    assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
}
#[test]
fn trigger_enable_disable_parse_positional_id() {
    let args = Args::try_parse_from(["iroha", "trigger", "enable", "soraswap_tick"])
        .expect("parse trigger enable");
    let Command::Trigger(trigger::Command::Enable(enable)) = args.command else {
        panic!("expected trigger enable command");
    };
    assert_eq!(enable.id.to_string(), "soraswap_tick");
    let args = Args::try_parse_from(["iroha", "trigger", "disable", "soraswap_tick"])
        .expect("parse trigger disable");
    let Command::Trigger(trigger::Command::Disable(disable)) = args.command else {
        panic!("expected trigger disable command");
    };
    assert_eq!(disable.id.to_string(), "soraswap_tick");
}
#[test]
fn trigger_list_all_active_parse() {
    let args =
        Args::try_parse_from(["iroha", "trigger", "list", "all"]).expect("parse trigger list");
    let Command::Trigger(trigger::Command::List(trigger::List::All { active, .. })) = args.command
    else {
        panic!("expected trigger list all command");
    };
    assert!(!active);
    let args = Args::try_parse_from(["iroha", "trigger", "list", "all", "--active"])
        .expect("parse active trigger list");
    let Command::Trigger(trigger::Command::List(trigger::List::All { active, .. })) = args.command
    else {
        panic!("expected trigger list all --active command");
    };
    assert!(active);
}

#[test]
fn trigger_completed_list_rejects_retired_timeout_flag() {
    let error =
        Args::try_parse_from(["iroha", "trigger", "completed", "list", "--timeout-ms", "1"])
            .expect_err("completed list must reject the retired timeout flag");
    assert!(error.to_string().contains("--timeout-ms"));
}

fn json_output() -> OutputSelection {
    OutputSelection::resolve(Some(OutputFormatArg::Json), true, false)
}
#[test]
fn render_cli_error_includes_kind_and_exit_code() {
    let report = Report::new(MainError::Config);
    let rendered = render_cli_error(&report, json_output());
    assert_eq!(rendered.kind, CliErrorKind::Config);
    let value: norito::json::Value =
        norito::json::from_str(&rendered.output).expect("parse error json");
    let obj = value.as_object().expect("error object");
    let err = obj.get("error").expect("error field");
    assert_eq!(
        err.get("kind").and_then(norito::json::Value::as_str),
        Some("config")
    );
    assert_eq!(
        err.get("exit_code").and_then(norito::json::Value::as_i64),
        Some(3)
    );
}
#[test]
fn render_cli_error_includes_command_message() {
    let report = Report::new(MainError::Command("missing budget".to_string()));
    let rendered = render_cli_error(&report, json_output());
    let value: norito::json::Value =
        norito::json::from_str(&rendered.output).expect("parse error json");
    let err = value
        .as_object()
        .and_then(|obj| obj.get("error"))
        .and_then(|err| err.get("message"))
        .and_then(norito::json::Value::as_str)
        .expect("error message");
    assert!(
        err.contains("missing budget"),
        "message should include context: {err}"
    );
}
#[test]
fn render_cli_error_marks_cli_argument_failures_as_input() {
    let report = Report::new(MainError::CliArgs("unknown flag".to_string()));
    let rendered = render_cli_error(&report, json_output());
    assert_eq!(rendered.kind, CliErrorKind::Input);
    let value: norito::json::Value =
        norito::json::from_str(&rendered.output).expect("parse error json");
    let err = value
        .as_object()
        .and_then(|obj| obj.get("error"))
        .and_then(|err| err.get("message"))
        .and_then(norito::json::Value::as_str)
        .expect("error message");
    assert!(
        err.contains("unknown flag"),
        "message should include parse context: {err}"
    );
}
#[test]
fn account_transaction_and_trigger_trees_have_one_top_level_mount() {
    let tx = Args::try_parse_from(["iroha", "tx", "signed-size"])
        .expect("canonical signed-size command should parse");
    assert!(matches!(
        tx.command,
        Command::Tx(transaction::Command::SignedSize(_))
    ));
    for retired in [
        &["iroha", "transaction", "signed-size"][..],
        &["iroha", "ledger", "transaction", "signed-size"][..],
        &["iroha", "ledger", "account", "--help"][..],
        &["iroha", "ledger", "trigger", "--help"][..],
    ] {
        let error = Args::try_parse_from(retired)
            .expect_err("retired duplicate command mounts must not parse");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::InvalidSubcommand,
            "unexpected parse result for {retired:?}: {error}"
        );
    }
}
#[test]
fn printjsoncontext_routes_text_to_stderr_in_json_mode() {
    let mut ctx = test_context(CliOutputFormat::Json);
    ctx.println("hello").expect("println");
    assert!(ctx.write.is_empty(), "stdout should be empty");
    let stderr = String::from_utf8(ctx.err_write).expect("stderr utf8");
    assert_eq!(stderr, "hello\n");
}
#[test]
fn printjsoncontext_writes_text_to_stdout_in_text_mode() {
    let mut ctx = test_context(CliOutputFormat::Text);
    ctx.println("hello").expect("println");
    assert!(ctx.err_write.is_empty(), "stderr should be empty");
    let stdout = String::from_utf8(ctx.write).expect("stdout utf8");
    assert_eq!(stdout, "hello\n");
}
#[test]
fn printjsoncontext_writes_data_lines_to_stdout_in_json_mode() {
    let mut ctx = test_context(CliOutputFormat::Json);
    ctx.println_data("input,status").expect("println data");
    assert!(ctx.err_write.is_empty(), "stderr should be empty");
    let stdout = String::from_utf8(ctx.write).expect("stdout utf8");
    assert_eq!(stdout, "input,status\n");
}
#[test]
fn taira_doctor_cli_parses_public_root_and_json() {
    let args = Args::try_parse_from([
        "iroha",
        "taira",
        "doctor",
        "--public-root",
        "https://taira.sora.org",
        "--json",
    ])
    .expect("parse args");
    let Command::Taira(crate::taira::Command::Doctor(cmd)) = args.command else {
        panic!("expected taira doctor command");
    };
    assert_eq!(cmd.public_root, "https://taira.sora.org");
    assert!(cmd.json);
}
#[test]
fn taira_public_reset_exports_source_without_runtime_signing_arguments() {
    let args = Args::try_parse_from([
        "iroha",
        "taira",
        "public-reset",
        "source-manifest",
        "--source-root",
        "/private/source/iroha",
    ])
    .expect("parse read-only typed source export");
    assert!(matches!(
        args.command,
        Command::Taira(crate::taira::Command::PublicReset(_))
    ));
    assert!(
        Args::try_parse_from([
            "iroha",
            "taira",
            "public-reset",
            "source-manifest",
            "--source-root",
            "/private/source/iroha",
            "--ssh-identity",
            "/private/id_ed25519",
        ])
        .is_err(),
        "local source export must reject unrelated signing inputs"
    );
}

#[test]
fn taira_public_reset_exposes_strict_preflight_and_apply() {
    let args = Args::try_parse_from([
        "iroha",
        "taira",
        "public-reset",
        "preflight",
        "--inventory",
        "/private/runtime/inventory.json",
        "--authorization",
        "/private/runtime/authorization.json",
        "--trusted-public-key",
        "/private/runtime/trusted-key.json",
        "--ssh-identity",
        "/private/runtime/id_ed25519",
        "--known-hosts",
        "/private/runtime/known_hosts",
    ])
    .expect("parse strict public-reset preflight");
    assert!(matches!(
        args.command,
        Command::Taira(crate::taira::Command::PublicReset(_))
    ));

    let apply = Args::try_parse_from([
        "iroha",
        "taira",
        "public-reset",
        "apply",
        "--inventory",
        "/private/runtime/inventory.json",
        "--authorization",
        "/private/runtime/authorization.json",
        "--trusted-public-key",
        "/private/runtime/trusted-key.json",
        "--ssh-identity",
        "/private/runtime/id_ed25519",
        "--known-hosts",
        "/private/runtime/known_hosts",
        "--runtime-client-config",
        "/private/runtime/client.toml",
        "--validator-operator-key",
        "/private/runtime/operator.key",
        "--validator-client-config",
        "/private/runtime/validator-1.toml",
        "/private/runtime/validator-2.toml",
        "/private/runtime/validator-3.toml",
        "/private/runtime/validator-4.toml",
        "--onboarding-token",
        "/private/runtime/onboarding-token",
        "--inrou-stage-dir",
        "/private/runtime/inrou-stage",
    ])
    .expect("parse strict public-reset apply");
    assert!(matches!(
        apply.command,
        Command::Taira(crate::taira::Command::PublicReset(_))
    ));

    for retired in [
        "--journal-dir",
        "--canary-fee-payer",
        "--maintenance-admin-config",
        "--epoch-seed-sources",
    ] {
        let error = Args::try_parse_from([
            "iroha",
            "taira",
            "public-reset",
            "apply",
            "--inventory",
            "/private/runtime/inventory.json",
            "--authorization",
            "/private/runtime/authorization.json",
            "--trusted-public-key",
            "/private/runtime/trusted-key.json",
            "--ssh-identity",
            "/private/runtime/id_ed25519",
            "--known-hosts",
            "/private/runtime/known_hosts",
            retired,
            "retired-value",
        ])
        .expect_err("retired public-reset apply flag must be rejected");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}
#[test]
fn taira_public_reset_local_inputs_require_a_dedicated_operator_key() {
    let local = [
        "--runtime-client-config",
        "/private/runtime/client.toml",
        "--validator-client-config",
        "/private/runtime/client-1.toml",
        "/private/runtime/client-2.toml",
        "/private/runtime/client-3.toml",
        "/private/runtime/client-4.toml",
        "--onboarding-token",
        "/private/runtime/token",
        "--inrou-stage-dir",
        "/private/runtime/stage",
        "--validator-unit",
        "/private/runtime/validator-1.service",
        "/private/runtime/validator-2.service",
        "/private/runtime/validator-3.service",
        "/private/runtime/validator-4.service",
        "--beacon-inputs",
        "/private/runtime/beacon-inputs.json",
        "--beacon-validator-unit",
        "/private/runtime/validator-1.beacon.service",
        "/private/runtime/validator-2.beacon.service",
        "/private/runtime/validator-3.beacon.service",
        "/private/runtime/validator-4.beacon.service",
        "--native-edge-capability",
        "/private/runtime/native-edge-capability.json",
        "--known-hosts",
        "/private/runtime/known_hosts",
        "--output",
        "/private/runtime/new.json",
    ];
    for subcommand in ["assemble", "authorize"] {
        let mut argv = vec!["iroha", "taira", "public-reset", subcommand];
        if subcommand == "assemble" {
            argv.extend(["--intent", "/private/runtime/intent.json"]);
        } else {
            argv.extend([
                "--inventory",
                "/private/runtime/inventory.json",
                "--trusted-public-key",
                "/private/runtime/trusted.json",
                "--signing-key-fd",
                "3",
            ]);
        }
        argv.extend(["--public-inputs", "/private/runtime/public-inputs"]);
        argv.extend(local);
        let error = Args::try_parse_from(&argv).expect_err("explicit operator credential required");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(error.to_string().contains("--validator-operator-key"));
        argv.extend(["--validator-operator-key", "/private/runtime/operator.key"]);
        Args::try_parse_from(&argv)
            .expect("parse complete local custody arguments without opening files");
        argv.extend(["--edge-unit", "/private/runtime/edge.service"]);
        let retired = Args::try_parse_from(argv)
            .expect_err("the independent native edge requires a capability, not a Linux unit");
        assert_eq!(retired.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}
#[test]
fn taira_public_reset_operator_keygen_has_explicit_private_output() {
    let args = Args::try_parse_from([
        "iroha",
        "taira",
        "public-reset",
        "operator-keygen",
        "--private-key-file",
        "/private/runtime/new-operator.key",
    ])
    .expect("parse key generation without generating a credential");
    reject_irrelevant_taira_public_reset_globals(&args).expect("no unrelated global signer");
    let error = Args::try_parse_from(["iroha", "taira", "public-reset", "operator-keygen"])
        .expect_err("explicit output is required");
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
}
#[test]
fn taira_write_canary_cli_parses_defaults_and_overrides() {
    let args = Args::try_parse_from([
        "iroha",
        "taira",
        "write-canary",
        "--faucet-asset-id",
        "asset",
        "--faucet-authority",
        "authority",
        "--faucet-amount",
        "25000",
        "--onboarding-token-file",
        "/tmp/taira-onboarding.token",
        "--operation",
        "faucet",
        "--authorization-sha256",
        "abababababababababababababababababababababababababababababababab",
        "--authorization-nonce",
        "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn",
        "--mutation-phase",
        "pre_edge",
        "--idempotency-key",
        "abababababababababababababababababababababababababababababababab",
        "--execution-expires-at-unix-ms",
        "18446744073709551615",
        "--recover-prepared-envelope-fd",
        "3",
        "--json",
    ])
    .expect("parse args");
    let Command::Taira(crate::taira::Command::WriteCanary(cmd)) = args.command else {
        panic!("expected taira write-canary command");
    };
    assert_eq!(cmd.public_root, "https://taira.sora.org");
    assert_eq!(cmd.faucet_authority.as_deref(), Some("authority"));
    assert_eq!(cmd.faucet_asset_id.as_deref(), Some("asset"));
    assert_eq!(cmd.faucet_amount.as_deref(), Some("25000"));
    assert_eq!(
        cmd.onboarding_token_file.as_deref(),
        Some(std::path::Path::new("/tmp/taira-onboarding.token"))
    );
    assert_eq!(cmd.recover_prepared_envelope_fd, Some(3));
    assert!(cmd.json);
    assert_eq!(
        cmd.idempotency_key,
        "abababababababababababababababababababababababababababababababab"
    );

    for retired in [
        "--write-config",
        "--recover-only",
        "--alias-prefix",
        "--use-config-signer",
    ] {
        let error = Args::try_parse_from(["iroha", "taira", "write-canary", retired])
            .expect_err("retired write-canary flag must fail closed");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}
#[test]
fn taira_inrou_workspace_cli_requires_explicit_assets_and_output() {
    let args = Args::try_parse_from([
        "iroha",
        "taira",
        "inrou-workspace",
        "--kernel",
        "/private/assets/vmlinux",
        "--rootfs",
        "/private/assets/rootfs.ext4",
        "--initrd",
        "/private/assets/initrd.img",
        "--output-dir",
        "/private/runtime/taira-inrou-canary",
        "--json",
    ])
    .expect("parse Taira Inrou workspace args");
    let Command::Taira(crate::taira::Command::InrouWorkspace(cmd)) = args.command else {
        panic!("expected taira inrou-workspace command");
    };
    assert_eq!(
        cmd.kernel,
        std::path::PathBuf::from("/private/assets/vmlinux")
    );
    assert_eq!(
        cmd.rootfs,
        std::path::PathBuf::from("/private/assets/rootfs.ext4")
    );
    assert_eq!(
        cmd.initrd,
        std::path::PathBuf::from("/private/assets/initrd.img")
    );
    assert_eq!(
        cmd.output_dir,
        std::path::PathBuf::from("/private/runtime/taira-inrou-canary")
    );
    assert!(cmd.json);

    let error = Args::try_parse_from([
        "iroha",
        "taira",
        "inrou-workspace",
        "--kernel",
        "/private/assets/vmlinux",
        "--rootfs",
        "/private/assets/rootfs.ext4",
        "--output-dir",
        "/private/runtime/taira-inrou-canary",
    ])
    .expect_err("Taira Inrou workspace must require an explicit initrd");
    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
}
#[test]
fn taira_inrou_stage_cli_requires_mode_and_parses_explicit_upgrade() {
    let args = Args::try_parse_from([
        "iroha",
        "taira",
        "inrou-stage",
        "--mode",
        "upgrade",
        "--container",
        "/tmp/inrou/container.json",
        "--service",
        "/tmp/inrou/service.json",
        "--bundle-file",
        "/tmp/inrou/bundle.bin",
        "--sorafs-retention-epoch",
        "2000000000",
        "--stage-dir",
        "/tmp/taira-inrou-stage-upgrade",
        "--bind-validator-config-dir",
        "/private/runtime/taira-validator-configs",
    ])
    .expect("parse Taira Inrou stage args");
    let Command::Taira(crate::taira::Command::InrouStage(cmd)) = args.command else {
        panic!("expected taira inrou-stage command");
    };
    assert_eq!(cmd.mode, crate::taira::InrouCanaryMode::Upgrade);
    assert_eq!(cmd.sorafs_retention_epoch.get(), 2_000_000_000);
    assert_eq!(
        cmd.bind_validator_config_dir,
        std::path::PathBuf::from("/private/runtime/taira-validator-configs")
    );

    let error = Args::try_parse_from([
        "iroha",
        "taira",
        "inrou-stage",
        "--container",
        "/tmp/inrou/container.json",
        "--service",
        "/tmp/inrou/service.json",
        "--bundle-file",
        "/tmp/inrou/bundle.bin",
        "--sorafs-retention-epoch",
        "2000000000",
        "--stage-dir",
        "/tmp/taira-inrou-stage",
        "--bind-validator-config-dir",
        "/private/runtime/taira-validator-configs",
    ])
    .expect_err("Inrou stage must require an explicit mutation mode");
    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);

    let error = Args::try_parse_from([
        "iroha",
        "taira",
        "inrou-stage",
        "--mode",
        "deploy",
        "--container",
        "/tmp/inrou/container.json",
        "--service",
        "/tmp/inrou/service.json",
        "--bundle-file",
        "/tmp/inrou/bundle.bin",
        "--stage-dir",
        "/tmp/taira-inrou-stage",
        "--bind-validator-config-dir",
        "/private/runtime/taira-validator-configs",
    ])
    .expect_err("Inrou stage must require an explicit SoraFS retention epoch");
    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);

    let error = Args::try_parse_from([
        "iroha",
        "taira",
        "inrou-stage",
        "--mode",
        "deploy",
        "--container",
        "/tmp/inrou/container.json",
        "--service",
        "/tmp/inrou/service.json",
        "--bundle-file",
        "/tmp/inrou/bundle.bin",
        "--sorafs-retention-epoch",
        "2000000000",
        "--stage-dir",
        "/tmp/taira-inrou-stage",
    ])
    .expect_err("Inrou stage must require the validator config binding directory");
    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
}
#[test]
fn taira_inrou_canary_cli_requires_mode_and_parses_explicit_upgrade() {
    let command = [
        "iroha",
        "taira",
        "inrou-canary",
        "--stage-dir",
        "/tmp/taira-inrou-stage",
        "--mode",
        "upgrade",
        "--operation",
        "bundle-pin",
        "--authorization-sha256",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--authorization-nonce",
        "cccccccccccccccccccccccccccccccc",
        "--mutation-phase",
        "pre_edge",
        "--execution-expires-at-unix-ms",
        "2000000000000",
        "--idempotency-key",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--timeout-secs",
        "90",
        "--json",
    ];
    let args = Args::try_parse_from(command.into_iter().chain([
        "--prepare-envelope",
        "--prepared-output-fd",
        "3",
    ]))
    .expect("parse Taira Inrou canary args");
    let Command::Taira(crate::taira::Command::InrouCanary(cmd)) = args.command else {
        panic!("expected taira inrou-canary command");
    };
    assert_eq!(
        cmd.stage_dir,
        std::path::PathBuf::from("/tmp/taira-inrou-stage")
    );
    assert_eq!(cmd.mode, crate::taira::InrouCanaryMode::Upgrade);
    assert_eq!(cmd.operation, crate::taira::InrouCanaryOperation::BundlePin);
    assert!(cmd.prepare_envelope);
    assert_eq!(cmd.prepared_output_fd, Some(3));
    assert_eq!(
        cmd.idempotency_key,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(cmd.timeout_secs, 90);
    assert!(cmd.json);

    let error = Args::try_parse_from(command)
        .expect_err("Inrou canary must require an exact prepared action");
    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    let error = Args::try_parse_from(command.into_iter().chain(["--prepare-envelope"]))
        .expect_err("preparation must require its output descriptor");
    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    for action in [
        "--submit-prepared-envelope-fd",
        "--recover-prepared-envelope-fd",
    ] {
        let args = Args::try_parse_from(command.into_iter().chain([action, "3"]))
            .expect("exact submission or recovery descriptor must parse");
        let Command::Taira(crate::taira::Command::InrouCanary(cmd)) = args.command else {
            panic!("expected taira inrou-canary command");
        };
        assert!(!cmd.prepare_envelope);
        assert_eq!(
            cmd.submit_prepared_envelope_fd,
            (action == "--submit-prepared-envelope-fd").then_some(3)
        );
        assert_eq!(
            cmd.recover_prepared_envelope_fd,
            (action == "--recover-prepared-envelope-fd").then_some(3)
        );
    }
    let error = Args::try_parse_from(command.into_iter().chain([
        "--submit-prepared-envelope-fd",
        "3",
        "--recover-prepared-envelope-fd",
        "4",
    ]))
    .expect_err("prepared actions must be mutually exclusive");
    assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    let error = Args::try_parse_from(
        command
            .into_iter()
            .filter(|argument| !matches!(*argument, "--mode" | "upgrade"))
            .chain(["--submit-prepared-envelope-fd", "3"]),
    )
    .expect_err("Inrou canary must require an explicit mutation mode");
    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
}
#[test]
fn taira_inrou_check_is_distinct_and_requires_an_explicit_stage_mode() {
    let args = Args::try_parse_from([
        "iroha",
        "taira",
        "inrou-check",
        "--stage-dir",
        "/tmp/taira-inrou-stage",
        "--mode",
        "deploy",
        "--timeout-secs",
        "45",
        "--json",
    ])
    .expect("parse read-only Taira Inrou check args");
    let Command::Taira(crate::taira::Command::InrouCheck(cmd)) = args.command else {
        panic!("expected taira inrou-check command");
    };
    assert_eq!(
        cmd.stage_dir,
        std::path::PathBuf::from("/tmp/taira-inrou-stage")
    );
    assert_eq!(cmd.mode, crate::taira::InrouCanaryMode::Deploy);
    assert_eq!(cmd.timeout_secs, 45);
    assert!(cmd.json);

    let error = Args::try_parse_from([
        "iroha",
        "taira",
        "inrou-check",
        "--stage-dir",
        "/tmp/taira-inrou-stage",
    ])
    .expect_err("Inrou check must never infer the retained stage mode");
    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
}
#[test]
fn soracloud_top_level_app_parser_replaces_nested_app_path() {
    Args::try_parse_from([
        "iroha",
        "soracloud",
        "app",
        "doctor",
        "--manifest",
        "app_manifest.json",
    ])
    .expect("top-level soracloud app doctor should parse");
    let err = Args::try_parse_from([
        "iroha",
        "app",
        "soracloud",
        "app",
        "doctor",
        "--manifest",
        "app_manifest.json",
    ])
    .expect_err("old nested Soracloud path must be removed");
    assert_eq!(err.kind(), ErrorKind::InvalidSubcommand);
}
#[test]
fn soracloud_offline_app_commands_allow_fallback_config() {
    let init =
        Args::try_parse_from(["iroha", "soracloud", "app", "init"]).expect("app init should parse");
    assert!(init.command.allows_fallback_config());
    let simulate = Args::try_parse_from([
        "iroha",
        "soracloud",
        "app",
        "simulate",
        "--manifest",
        "app_manifest.json",
        "--sorafs-retention-epoch",
        "2000000000",
    ])
    .expect("app simulate should parse");
    assert!(simulate.command.allows_fallback_config());
    let release = Args::try_parse_from([
        "iroha",
        "soracloud",
        "app",
        "release",
        "--sorafs-retention-epoch",
        "2000000000",
    ])
    .expect("app release should parse");
    assert!(!release.command.allows_fallback_config());
}
#[test]
fn soracloud_service_model_hf_and_agent_parsers_are_namespaced() {
    Args::try_parse_from([
        "iroha",
        "soracloud",
        "service",
        "plan",
        "--container",
        "container_manifest.json",
        "--service",
        "service_manifest.json",
    ])
    .expect("top-level soracloud service plan should parse");
    Args::try_parse_from([
        "iroha",
        "soracloud",
        "model",
        "training-job-status",
        "--service-name",
        "trainer",
        "--job-id",
        "job1",
    ])
    .expect("top-level soracloud model training status should parse");
    Args::try_parse_from([
        "iroha",
        "soracloud",
        "hf",
        "status",
        "--repo-id",
        "openai/gpt-oss",
        "--revision",
        "0123456789abcdef0123456789abcdef01234567",
        "--storage-class",
        "warm",
        "--lease-term-ms",
        "60000",
    ])
    .expect("top-level soracloud hf status should parse");
    Args::try_parse_from([
        "iroha",
        "soracloud",
        "agent",
        "status",
        "--apartment-name",
        "agent_a",
    ])
    .expect("top-level soracloud agent status should parse");
}
#[test]
fn soracloud_workspace_mutation_requires_explicit_retention_identity() {
    Args::try_parse_from([
        "iroha",
        "soracloud",
        "service",
        "deploy-workspace",
        "--sorafs-retention-epoch",
        "2000000000",
        "--torii-url",
        "http://127.0.0.1:8080",
    ])
    .expect("workspace deploy should parse one explicit retention identity");
    let error = Args::try_parse_from([
        "iroha",
        "soracloud",
        "service",
        "upgrade-workspace",
        "--torii-url",
        "http://127.0.0.1:8080",
    ])
    .expect_err("workspace upgrade must not derive a retention identity from wall time");
    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
}
#[test]
fn resolve_account_id_with_rejects_public_key_domain() {
    let domain: DomainId = DomainId::try_new("wonderland", "universal").expect("domain");
    let key_pair = fixture_key_pair(7);
    let literal = format!("{}@{}", key_pair.public_key(), domain);
    let err = resolve_account_id_with(&literal).expect_err("public_key@domain should be rejected");
    assert!(
        err.to_string().contains("must not include '@domain'"),
        "unexpected error: {err}"
    );
}
#[test]
fn resolve_account_id_with_rejects_non_canonical_i105_literal() {
    let literal = sample_noncanonical_i105_literal(25);
    let err =
        resolve_account_id_with(&literal).expect_err("non-canonical I105 literal should fail");
    assert!(
        err.to_string().contains("must be canonical I105"),
        "unexpected error: {err}"
    );
}
#[test]
fn parse_register_account_id_rejects_alias_like_literal() {
    let err = parse_register_account_id("inori@invalid-domain").expect_err("alias should fail");
    assert!(
        err.to_string()
            .contains("accounts are global and aliases carry domains"),
        "unexpected error: {err}"
    );
}
#[test]
fn parse_register_account_id_rejects_non_canonical_i105_literal() {
    let literal = sample_noncanonical_i105_literal(26);
    let err =
        parse_register_account_id(&literal).expect_err("non-canonical I105 literal should fail");
    assert!(
        err.to_string()
            .contains("must be a canonical I105 account id"),
        "unexpected error: {err}"
    );
}
#[test]
fn parse_register_account_id_rejects_canonical_hex() {
    let key_pair = fixture_key_pair(14);
    let literal = AccountId::new(key_pair.public_key().clone())
        .to_canonical_hex()
        .expect("canonical hex");
    let err = parse_register_account_id(&literal).expect_err("canonical hex should fail");
    assert!(
        err.to_string().contains("canonical hex is not accepted"),
        "unexpected error: {err}"
    );
}
#[test]
fn parse_asset_balance_scope_literal_accepts_global() {
    let parsed = parse_asset_balance_scope_literal("global").expect("global scope should parse");
    assert_eq!(parsed, iroha::data_model::asset::AssetBalanceScope::Global);
}
#[test]
fn parse_asset_balance_scope_literal_accepts_dataspace() {
    let parsed =
        parse_asset_balance_scope_literal("dataspace:7").expect("dataspace scope should parse");
    assert_eq!(
        parsed,
        iroha::data_model::asset::AssetBalanceScope::Dataspace(
            iroha_model_base::topology::DataSpaceId::new(7)
        )
    );
}
#[test]
fn parse_asset_balance_scope_literal_rejects_invalid_literal() {
    let err = parse_asset_balance_scope_literal("scope:not-supported")
        .expect_err("invalid asset balance scope must fail");
    assert!(
        err.to_string()
            .contains("asset balance scope must be `global` or `dataspace:<id>`"),
        "unexpected error: {err}"
    );
}
#[test]
fn ledger_asset_mint_parser_rejects_missing_account_for_definition() {
    let err = Args::try_parse_from([
        "iroha",
        "ledger",
        "asset",
        "mint",
        "--definition",
        "66owaQmAQMuHxPzxUN3bqZ6FJfDa",
        "--quantity",
        "1",
    ])
    .expect_err("definition selector without account must be rejected");
    assert!(
        err.to_string().contains("--account"),
        "unexpected clap error: {err}"
    );
}
#[test]
fn parse_asset_definition_literal_accepts_base58() {
    let expected = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("domain"),
        "rose".parse().expect("name"),
    );
    let parsed =
        parse_asset_definition_literal(&expected.to_string()).expect("base58 literal should parse");
    assert_eq!(parsed, expected);
}
#[test]
fn parse_asset_definition_literal_rejects_prefixed_literal() {
    let err = parse_asset_definition_literal("prefix:2f17c72466f84a4bb8a8e24884fdcd2f")
        .expect_err("prefixed literal should be rejected");
    assert!(
        err.to_string().contains("Base58"),
        "unexpected error: {err}"
    );
}
#[test]
fn resolve_account_id_with_resolves_encoded_literal() {
    let key_pair = fixture_key_pair(9);
    let account = AccountId::new(key_pair.public_key().clone());
    let canonical = account.canonical_i105().expect("canonical I105");
    let resolved = resolve_account_id_with(&canonical).expect("local resolve");
    assert_eq!(resolved.to_string(), account.to_string());
}
#[test]
fn stream_timeout_driver_propagates_errors() {
    let mut processed = 0usize;
    let result = drive_stream_until_deadline(
        |_timeout| {
            Err::<Option<DummyEvent>, _>(iroha::Error::Transport {
                operation: "events.subscribe",
                kind: iroha::TransportErrorKind::Other,
                details: "connection failed".to_owned(),
            })
        },
        |_event| -> Result<()> {
            processed += 1;
            Ok(())
        },
        Duration::from_millis(1),
        "timeout",
    );
    let err = result.expect_err("stream error should propagate");
    assert!(err.to_string().contains("connection failed"));
    assert_eq!(processed, 0);
}

#[test]
fn stream_timeout_driver_waits_only_for_the_remaining_deadline() {
    let mut calls = 0;
    let mut received = Vec::new();
    drive_stream_until_deadline(
        |timeout| {
            assert!(
                timeout <= Duration::from_secs(7) && timeout > Duration::from_secs(6),
                "each receive waits only for the time left before the deadline: {timeout:?}"
            );
            calls += 1;
            match calls {
                1 | 2 => Ok(Some(calls)),
                3 => Err(iroha::Error::Timeout {
                    operation: "stream.receive",
                }),
                _ => panic!("receive called after idle timeout"),
            }
        },
        |item| {
            received.push(item);
            Ok(())
        },
        Duration::from_secs(7),
        "timeout",
    )
    .expect("idle timeout completes the listener");
    assert_eq!(calls, 3);
    assert_eq!(received, vec![1, 2]);
}

#[test]
fn stream_timeout_driver_stops_a_busy_stream_at_the_deadline() {
    let started = std::time::Instant::now();
    let mut received = 0_u32;
    drive_stream_until_deadline(
        |timeout| {
            assert!(timeout <= Duration::from_millis(40));
            std::thread::sleep(Duration::from_millis(2));
            Ok::<Option<u32>, _>(Some(1))
        },
        |item| {
            received += item;
            Ok(())
        },
        Duration::from_millis(40),
        "timeout",
    )
    .expect("the deadline completes a stream that never idles");
    assert!(received > 0);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "a busy stream must not extend the deadline"
    );
}

#[test]
fn stream_timeout_driver_preserves_transport_timeout_errors() {
    let result = drive_stream_until_deadline(
        |_| {
            Err::<Option<DummyEvent>, _>(iroha::Error::Timeout {
                operation: "events.subscribe",
            })
        },
        |_| panic!("transport timeout must not deliver an item"),
        Duration::from_secs(1),
        "timeout",
    );
    assert!(result.unwrap_err().to_string().contains("events.subscribe"));
}

#[test]
fn stream_timeout_driver_stops_at_clean_eof() {
    let mut calls = 0;
    drive_stream_until_deadline(
        |_| {
            calls += 1;
            Ok::<Option<DummyEvent>, _>(None)
        },
        |_| panic!("EOF must not deliver an item"),
        Duration::from_secs(1),
        "timeout",
    )
    .expect("clean EOF");
    assert_eq!(calls, 1);
}

#[test]
fn stream_close_retains_receive_and_close_failures() {
    let close_error = || iroha::Error::Timeout {
        operation: "stream.close",
    };
    assert_eq!(finish_stream(Ok(7), Ok(())).unwrap(), 7);
    assert_eq!(
        finish_stream::<()>(Err(eyre!("original receive failure")), Ok(()))
            .unwrap_err()
            .to_string(),
        "original receive failure",
    );
    assert!(matches!(
        finish_stream(Ok(()), Err(close_error()))
            .unwrap_err()
            .downcast_ref::<iroha::Error>(),
        Some(iroha::Error::Timeout {
            operation: "stream.close"
        }),
    ));
    let error = finish_stream::<()>(Err(eyre!("original receive failure")), Err(close_error()))
        .unwrap_err();
    assert!(format!("{error:#}").contains("original receive failure"));
    assert!(error.to_string().contains("stream.close"));
}

fn authority_fee_payment_with_gas(limit: u64) -> FeePaymentIntent {
    FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(limit))
}
#[test]
fn validate_executable_fee_payment_accepts_positive_ivm_gas_limit() {
    let executable = Executable::Ivm(IvmBytecode::from_compiled(vec![0x00]));
    let fee_payment = authority_fee_payment_with_gas(42);
    validate_executable_fee_payment(&executable, &fee_payment).expect("gas limit should validate");
}
#[test]
fn validate_executable_fee_payment_rejects_missing_ivm_gas_limit() {
    let executable = Executable::Ivm(IvmBytecode::from_compiled(vec![0x00]));
    let err = validate_executable_fee_payment(
        &executable,
        &FeePaymentIntent::authority(Vec::new(), None),
    )
    .expect_err("missing gas limit must fail");
    assert!(err.to_string().contains("IVM transactions require"));
    assert!(err.to_string().contains("--gas-limit <u64>"));
}
#[test]
fn apply_cli_gas_limit_override_rejects_zero() {
    let err = apply_cli_gas_limit_override(FeePaymentIntent::authority(Vec::new(), None), Some(0))
        .expect_err("zero gas limit must fail");
    assert!(err.to_string().contains("greater than zero"));
}
#[test]
fn validate_executable_fee_payment_skips_instruction_transactions() {
    let executable = Executable::Instructions(Vec::<InstructionBox>::new().into());
    validate_executable_fee_payment(&executable, &FeePaymentIntent::authority(Vec::new(), None))
        .expect("plain instructions should not require gas_limit");
}
#[test]
fn validate_executable_fee_payment_accepts_positive_ivm_proved_gas_limit() {
    let executable = Executable::IvmProved(iroha::data_model::transaction::IvmProved {
        bytecode: IvmBytecode::from_compiled(vec![0x00]),
        overlay: Vec::<InstructionBox>::new().into(),
        events_commitment: Hash::new(b"events"),
        gas_policy_commitment: Hash::new(b"gas"),
    });
    let fee_payment = authority_fee_payment_with_gas(42);
    validate_executable_fee_payment(&executable, &fee_payment).expect("gas limit should validate");
}
#[test]
fn validate_executable_fee_payment_rejects_missing_contract_call_gas_limit() {
    let executable = Executable::ContractCall(
        iroha::data_model::transaction::executable::ContractInvocation {
            contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                .parse()
                .expect("contract address"),
            expected_code_hash: Hash::new(b"cli-contract-code"),
            entrypoint: "call".to_owned(),
            arguments: None,
        },
    );
    let err = validate_executable_fee_payment(
        &executable,
        &FeePaymentIntent::authority(Vec::new(), None),
    )
    .expect_err("missing gas limit must fail");
    assert!(
        err.to_string()
            .contains("contract-call transactions require")
    );
    assert!(!err.to_string().contains("--gas-limit <u64>"));
}
#[test]
fn apply_cli_gas_limit_override_sets_and_replaces_signed_value() {
    let fee_payment = authority_fee_payment_with_gas(10);
    let fee_payment = apply_cli_gas_limit_override(fee_payment, Some(42)).unwrap();
    let gas_limit = iroha::data_model::transaction::require_transaction_gas_limit(&fee_payment)
        .expect("gas limit should be present");
    assert_eq!(gas_limit, 42);
}
#[test]
fn fee_payment_args_require_explicit_payer_and_exact_sponsor_revision() {
    assert!(FeePaymentArgs::default().selection().is_err());
    let authority = FeePaymentArgs {
        fee_payer: Some(FeePayerArg::Authority),
        ..FeePaymentArgs::default()
    }
    .selection()
    .expect("authority selection");
    assert!(matches!(authority, FeePaymentIntent::Authority(_)));
    let missing = FeePaymentArgs {
        fee_payer: Some(FeePayerArg::Sponsor),
        ..FeePaymentArgs::default()
    };
    assert!(missing.selection().is_err());
}
#[test]
fn fee_quote_may_replace_limits_but_not_payer_or_gas_bound() {
    use iroha::data_model::{
        asset::AssetDefinitionId,
        nexus::FeeSponsorProgramId,
        transaction::{FeeChargeKind, FeeChargeLimit},
    };
    use iroha_primitives::numeric::Quantity;
    let requested = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(42));
    let quoted = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").expect("domain"),
                "rose".parse().expect("name"),
            ),
            Quantity::try_from(1_u64).expect("quantity"),
        )],
        NonZeroU64::new(42),
    );
    assert!(requested.has_same_payer_and_gas_bound(&quoted));
    let sponsor = FeeSponsorProgramId::new(
        AccountId::new(fixture_key_pair(7).public_key().clone()),
        "default".parse().expect("program name"),
    );
    let wrong_payer = FeePaymentIntent::sponsor(sponsor, 1, Vec::new(), NonZeroU64::new(42));
    assert!(!requested.has_same_payer_and_gas_bound(&wrong_payer));
    let wrong_gas = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(41));
    assert!(!requested.has_same_payer_and_gas_bound(&wrong_gas));
}
#[test]
fn authorized_transaction_lifetime_uses_exact_creation_and_preserves_shorter_ttl() {
    let config = fallback_config();
    let mut builder = TransactionBuilder::new(
        config.network_id,
        config.account,
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "bounded transaction".to_owned())]);
    builder.set_ttl(Duration::from_millis(120_000));
    let original = builder.into_payload().unwrap();
    for (creation, configured, expiry, expected) in [
        (1_000, 120_000, 74_000, 73_000),
        (1_000, 50, 74_000, 50),
        (1_000, 120_000, 1_001, 1),
        (u64::MAX - 1, 120_000, u64::MAX, 1),
    ] {
        let mut payload = original.clone();
        payload.creation_time_ms = creation;
        payload.time_to_live_ms = NonZeroU64::new(configured);
        let mut expected_payload = payload.clone();
        expected_payload.time_to_live_ms = NonZeroU64::new(expected);
        bound_transaction_payload_lifetime(&mut payload, expiry).unwrap();
        assert_eq!(payload, expected_payload);
        assert!(payload.creation_time_ms.checked_add(expected).unwrap() <= expiry);
    }
}

#[test]
fn authorized_transaction_lifetime_rejects_empty_window_and_missing_ttl() {
    let config = fallback_config();
    let mut builder = TransactionBuilder::new(
        config.network_id,
        config.account,
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "bounded transaction".to_owned())]);
    builder.set_creation_time(Duration::from_millis(1_000));
    builder.set_ttl(Duration::from_millis(120_000));
    let original = builder.into_payload().unwrap();
    for expiry in [0, 999, 1_000] {
        let mut payload = original.clone();
        assert!(bound_transaction_payload_lifetime(&mut payload, expiry).is_err());
        assert_eq!(payload, original);
    }
    let mut missing = original;
    missing.time_to_live_ms = None;
    assert!(bound_transaction_payload_lifetime(&mut missing, 2_000).is_err());
    assert_eq!(missing.time_to_live_ms, None);
}

#[test]
fn fee_quote_signing_preserves_exact_payload_and_expiry() {
    use iroha::data_model::{nexus::FeeDebitSource, transaction::TransactionPayload};
    use iroha_torii_shared::{FeeQuoteDecision, FeeQuoteObservation};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    // Each signing entry point binds the exact quoted payload.
    for mode in 0..2 {
        let mut config = fallback_config();
        let discriminant = config.account_chain_discriminant;
        let _profile = ChainDiscriminantGuard::enter(discriminant);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let _profile = ChainDiscriminantGuard::enter(discriminant);
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut buffer).unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buffer[..read]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = std::str::from_utf8(&request[..header_end]).unwrap();
            assert!(headers.starts_with("POST /v1/fees/quote "));
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            while request.len() < header_end + length {
                let read = stream.read(&mut buffer).unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buffer[..read]);
            }
            let request: json::Value =
                json::from_slice(&request[header_end..header_end + length]).unwrap();
            let payload: TransactionPayload =
                json::from_value(request.get("payload").unwrap().clone()).unwrap();
            let quote = FeeQuoteResponse {
                intent: payload.fee_payment_intent().clone(),
                observation: FeeQuoteObservation {
                    ledger_time_ms: 1,
                    next_block_height: 7,
                    route_dataspace_id: DataSpaceId::UNIVERSAL,
                },
                components: Vec::new(),
                capacities: Vec::new(),
                decision: FeeQuoteDecision::Accepted {
                    debit_source: FeeDebitSource::Account(payload.authority().clone()),
                    program_revision: None,
                },
            };
            quote.validate_for_draft(&payload).unwrap();
            let body = json::to_vec(&quote).unwrap();
            thread::sleep(Duration::from_millis(25));
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(&body).unwrap();
            payload
        });
        config.torii_api_url = Url::parse(&format!("http://{address}/")).unwrap();
        let client = BlockingClient::from_client(Client::builder(config).build().unwrap()).unwrap();
        let executable = Executable::from(vec![InstructionBox::from(Log::new(
            Level::INFO,
            "exact quoted payload".to_owned(),
        ))]);
        let fees = FeePaymentIntent::authority(Vec::new(), None);
        let expiry = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
            + 10_000;
        let (transaction, quote) = match mode {
            0 => quote_and_sign_transaction_with_expiry(
                &client,
                executable,
                fees,
                Metadata::default(),
                expiry,
            ),
            _ => quote_and_sign_transaction(&client, executable, fees, Metadata::default()),
        }
        .unwrap();
        let quoted = server.join().unwrap();
        assert_eq!(
            transaction.payload(),
            &quoted,
            "quote and signature must bind the same payload"
        );
        transaction.verify_signature().unwrap();
        quote
            .validate_for_signed_payload(transaction.payload())
            .unwrap();
        if mode == 0 {
            assert!(quoted.creation_time_ms + quoted.time_to_live_ms.unwrap().get() <= expiry);
        }
    }
}

#[test]
fn fee_quote_signing_rejects_invalid_semantics_and_response_media_type() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use iroha::data_model::nexus::FeeDebitSource;
    use iroha_model_base::topology::DataSpaceId;
    use iroha_torii_shared::{FeeQuoteDecision, FeeQuoteObservation};

    let invoke = |next_block_height, response_content_type: &'static str| {
        let mut config = fallback_config();
        let intent = FeePaymentIntent::authority(Vec::new(), None);
        let quote = FeeQuoteResponse {
            intent: intent.clone(),
            observation: FeeQuoteObservation {
                ledger_time_ms: 1,
                next_block_height,
                route_dataspace_id: DataSpaceId::UNIVERSAL,
            },
            components: Vec::new(),
            capacities: Vec::new(),
            decision: FeeQuoteDecision::Accepted {
                debit_source: FeeDebitSource::Account(config.account.clone()),
                program_revision: None,
            },
        };
        let body = norito::json::to_vec(&quote).expect("encode fee quote");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fee-quote server");
        let address = listener.local_addr().expect("fee-quote server address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept fee-quote request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = stream.read(&mut buffer).expect("read fee-quote request");
                assert_ne!(read, 0, "fee-quote request ended before its headers");
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("complete fee-quote request headers")
                + 4;
            let headers = std::str::from_utf8(&request[..header_end])
                .expect("UTF-8 fee-quote request headers");
            assert!(headers.starts_with("POST /v1/fees/quote "));
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("content length"))
                })
                .expect("fee-quote request content length");
            while request.len() < header_end + content_length {
                let read = stream
                    .read(&mut buffer)
                    .expect("read fee-quote request body");
                assert_ne!(read, 0, "fee-quote request body ended early");
                request.extend_from_slice(&buffer[..read]);
            }
            let response_headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {response_content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(response_headers.as_bytes())
                .expect("write fee-quote response headers");
            stream.write_all(&body).expect("write fee-quote response");
        });
        config.torii_api_url = Url::parse(&format!("http://{address}/")).expect("fee-quote URL");
        let client = BlockingClient::from_client(
            Client::builder(config)
                .build()
                .expect("valid fee-quote context"),
        )
        .expect("blocking fee-quote fixture client");
        let result = quote_and_sign_transaction(
            &client,
            Executable::Instructions(Vec::<InstructionBox>::new().into()),
            intent,
            Metadata::default(),
        );
        server.join().expect("fee-quote server thread");
        result
    };

    let error = invoke(0, "application/json")
        .expect_err("signing must reject an invalid response observation");
    assert!(format!("{error:#}").contains("next_block_height must be non-zero"));

    let error =
        invoke(1, "text/plain").expect_err("signing must reject a non-JSON successful response");
    let error = format!("{error:#}");
    assert!(
        error.contains("fee quote response has invalid content-type (expected application/json)"),
        "unexpected fee-quote media-type error: {error}"
    );
}
#[test]
fn account_admission_rejected_message_includes_hint() {
    let i18n = Localizer::new(Bundle::Cli, Language::English);
    let message = account_admission_rejected_message("hint text", &i18n);
    assert!(message.contains("Account admission rejected"));
    assert!(message.contains("hint text"));
}
struct VersionContext {
    config: Config,
    i18n: Localizer,
    output_format: CliOutputFormat,
    lines: Vec<String>,
    server_version: String,
}
impl VersionContext {
    fn new(output_format: CliOutputFormat, server_version: &str) -> Self {
        Self {
            config: fallback_config(),
            i18n: Localizer::new(Bundle::Cli, Language::English),
            output_format,
            lines: Vec::new(),
            server_version: server_version.to_string(),
        }
    }
}
impl RunContext for VersionContext {
    fn config(&self) -> &Config {
        &self.config
    }
    fn transaction_metadata(&self) -> Option<&Metadata> {
        None
    }
    fn input_instructions(&self) -> bool {
        false
    }
    fn output_instructions(&self) -> bool {
        false
    }
    fn i18n(&self) -> &Localizer {
        &self.i18n
    }
    fn output_format(&self) -> CliOutputFormat {
        self.output_format
    }
    fn print_data<T>(&mut self, _data: &T) -> Result<()>
    where
        T: JsonSerialize + ?Sized,
    {
        Ok(())
    }
    fn println(&mut self, data: impl std::fmt::Display) -> Result<()> {
        self.lines.push(data.to_string());
        Ok(())
    }
    fn server_version(&self) -> Result<String> {
        Ok(self.server_version.clone())
    }
}
#[test]
fn version_run_prints_localized_lines_in_text_mode() {
    let mut ctx = VersionContext::new(CliOutputFormat::Text, "1.2.3");
    Version.run(&mut ctx).expect("version run");
    let i18n = Localizer::new(Bundle::Cli, Language::English);
    let expected = vec![
        i18n.t_with(
            "info.client_git_sha",
            &[("sha", build_metadata().source_commit_label())],
        ),
        i18n.t_with(
            "info.client_version",
            &[("version", build_metadata().version())],
        ),
        i18n.t_with("info.server_version", &[("version", "1.2.3")]),
    ];
    assert_eq!(ctx.lines, expected);
}
#[test]
fn listen_events_message_formats_context() {
    let i18n = Localizer::new(Bundle::Cli, Language::English);
    let filter = EventFilterBox::Data(DataEventFilter::Any);
    let timeout = Duration::from_secs(1);
    let message = listen_events_message(&filter, Some(timeout), &i18n);
    let expected = format!("Listening to events with filter: {filter:?} and timeout: {timeout:?}");
    assert_eq!(message, expected);
    let message = listen_events_message(&filter, None, &i18n);
    let expected = format!("Listening to events with filter: {filter:?}");
    assert_eq!(message, expected);
}
#[test]
fn listen_blocks_message_formats_context() {
    let i18n = Localizer::new(Bundle::Cli, Language::English);
    let height = NonZeroU64::new(7).expect("height");
    let timeout = Duration::from_secs(2);
    let message = listen_blocks_message(height, Some(timeout), &i18n);
    let expected = format!("Listening to blocks from height: {height} and timeout: {timeout:?}");
    assert_eq!(message, expected);
    let message = listen_blocks_message(height, None, &i18n);
    let expected = format!("Listening to blocks from height: {height}");
    assert_eq!(message, expected);
}
#[test]
fn help_text_localization_preserves_headings_when_translation_matches() {
    let i18n = Localizer::new(Bundle::Cli, Language::English);
    let raw = "Usage:\nOptions:\n";
    let localized = localize_help_text(raw, &i18n);
    assert_eq!(localized, raw);
    assert!(!localized.contains("help.heading.usage"));
}
#[test]
fn language_override_from_args_parses_flags() {
    let args = vec!["--language".to_string(), "ja".to_string()];
    assert_eq!(language_override_from_args(args), Some("ja".to_string()));
    let args = vec!["--language=fr".to_string()];
    assert_eq!(language_override_from_args(args), Some("fr".to_string()));
}
#[test]
fn apply_transaction_overrides_uses_transaction_block_only() {
    let mut config = fallback_config();
    let raw: toml::Value = toml::from_str(
        r#"
transaction_ttl = "99s"
transaction_status_timeout = "77s"
[transaction]
time_to_live_ms = 1200
status_timeout_ms = 3400
"#,
    )
    .expect("valid toml");
    apply_transaction_overrides(&mut config, &raw);
    assert_eq!(config.transaction_ttl, Duration::from_millis(1200));
    assert_eq!(
        config.transaction_status_timeout,
        Duration::from_millis(3400)
    );
}

#[test]
fn inherited_config_cli_requires_explicit_provenance_and_rejects_mixed_sources() {
    let valid = [
        "iroha",
        "--config-fd",
        "19",
        "--config-source-path",
        "/private/runtime/client.toml",
        "ops",
        "sumeragi",
        "status",
    ];
    let args = Args::try_parse_from(valid).expect("explicit descriptor CLI");
    assert_eq!(args.config_fd, Some(19));
    assert_eq!(
        args.config_source_path,
        Some(PathBuf::from("/private/runtime/client.toml"))
    );
    for invalid in [
        vec!["iroha", "--config-fd", "19", "ops", "sumeragi", "status"],
        vec![
            "iroha",
            "--config-source-path",
            "/private/runtime/client.toml",
            "ops",
            "sumeragi",
            "status",
        ],
        vec![
            "iroha",
            "--config-fd",
            "2",
            "--config-source-path",
            "/private/runtime/client.toml",
            "ops",
            "sumeragi",
            "status",
        ],
        vec![
            "iroha",
            "--config-fd",
            "19",
            "--config-source-path",
            "/private/runtime/client.toml",
            "--config",
            "/private/runtime/other.toml",
            "ops",
            "sumeragi",
            "status",
        ],
    ] {
        assert!(Args::try_parse_from(invalid).is_err());
    }
}

#[test]
fn cli_loader_owns_filesystem_sections_before_sdk_validation() {
    let file = NamedTempFile::new().expect("client configuration file");
    let source = format!(
        "{}\n[connect]\nqueue_root = \"queue-state\"\n\n[soracloud]\nhttp_witness_file = \"witness.json\"\n",
        include_str!("../../../defaults/client.toml")
    );
    fs::write(file.path(), source).expect("write composite CLI configuration");
    let (config, filesystem) = load_cli_client_config(LoadPath::Explicit(file.path().into()))
        .expect("CLI-owned sections are removed before SDK validation");
    assert_eq!(config.torii_api_url.as_str(), "http://127.0.0.1:8080/");
    let source_dir = file.path().parent().expect("configuration directory");
    assert_eq!(
        filesystem.connect_queue_root,
        source_dir.join("queue-state")
    );
    assert_eq!(
        filesystem.soracloud_http_witness_file,
        Some(source_dir.join("witness.json"))
    );
}
#[test]
fn apply_transaction_overrides_ignores_legacy_top_level_keys() {
    let mut config = fallback_config();
    let original_ttl = config.transaction_ttl;
    let original_status = config.transaction_status_timeout;
    let raw: toml::Value = toml::from_str(
        r#"
transaction_ttl = "99s"
transaction_status_timeout = "77s"
"#,
    )
    .expect("valid toml");
    apply_transaction_overrides(&mut config, &raw);
    assert_eq!(config.transaction_ttl, original_ttl);
    assert_eq!(config.transaction_status_timeout, original_status);
}
struct CaptureContext {
    cfg: iroha::config::Config,
    captured: Option<Executable>,
    i18n: Localizer,
}
impl CaptureContext {
    fn new(account: AccountId) -> Self {
        let key_pair = fixture_key_pair(0xA5);
        let cfg = iroha::config::Config {
            chain: ChainId::from("00000000-0000-0000-0000-000000000000"),
            network_id:
                "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
                    .parse()
                    .expect("network id"),
            account,
            account_chain_discriminant:
                iroha_config::parameters::defaults::common::chain_discriminant(),
            key_pair,
            basic_auth: None,
            api_token: None,
            http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
            torii_api_url: Url::parse("http://127.0.0.1/").unwrap(),
            torii_request_timeout: iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT,
            transaction_ttl: iroha::config::DEFAULT_TRANSACTION_TIME_TO_LIVE,
            transaction_status_timeout: iroha::config::DEFAULT_TRANSACTION_STATUS_TIMEOUT,
            transaction_add_nonce: iroha::config::DEFAULT_TRANSACTION_NONCE,
            sorafs_alias_cache: crate::config_utils::default_alias_cache_policy(),
            sorafs_anonymity_policy: crate::config_utils::default_anonymity_policy(),
            sorafs_rollout_phase: crate::config_utils::default_rollout_phase(),
        };
        Self {
            cfg,
            captured: None,
            i18n: Localizer::new(Bundle::Cli, Language::English),
        }
    }
}
impl RunContext for CaptureContext {
    fn config(&self) -> &iroha::config::Config {
        &self.cfg
    }
    fn transaction_metadata(&self) -> Option<&Metadata> {
        None
    }
    fn input_instructions(&self) -> bool {
        false
    }
    fn output_instructions(&self) -> bool {
        false
    }
    fn i18n(&self) -> &Localizer {
        &self.i18n
    }
    fn print_data<T>(&mut self, _data: &T) -> Result<()>
    where
        T: JsonSerialize + ?Sized,
    {
        Ok(())
    }
    fn println(&mut self, _data: impl std::fmt::Display) -> Result<()> {
        Ok(())
    }
    fn submit_with_metadata(
        &mut self,
        instructions: impl Into<Executable>,
        _metadata: Metadata,
        _wait_for_confirmation: bool,
    ) -> Result<()> {
        self.captured = Some(instructions.into());
        Ok(())
    }
    fn submit(&mut self, instructions: impl Into<Executable>) -> Result<()> {
        self.captured = Some(instructions.into());
        Ok(())
    }
}
#[test]
fn ping_rejects_zero_count() {
    let account = account_with_seed("wonderland", 0x42);
    let mut ctx = CaptureContext::new(account);
    let cmd = transaction::Ping {
        log_level: Level::INFO,
        msg: "ping".to_string(),
        count: 0,
        parallel: 1,
        parallel_cap: transaction::DEFAULT_PING_PARALLEL_CAP,
        no_wait: false,
        no_index: false,
    };
    let err = cmd.run(&mut ctx).expect_err("count must be rejected");
    assert!(
        err.to_string()
            .contains("`--count` must be greater than zero")
    );
}
#[test]
fn ping_submits_single_log_instruction() {
    let account = account_with_seed("wonderland", 0x42);
    let mut ctx = CaptureContext::new(account);
    let cmd = transaction::Ping {
        log_level: Level::WARN,
        msg: "hello".to_string(),
        count: 1,
        parallel: 1,
        parallel_cap: transaction::DEFAULT_PING_PARALLEL_CAP,
        no_wait: false,
        no_index: false,
    };
    cmd.run(&mut ctx).expect("ping run");
    let exec = ctx.captured.expect("captured instructions");
    let instructions = match exec {
        Executable::Instructions(instructions) => instructions.into_vec(),
        Executable::ContractCall(_) => panic!("expected instructions"),
        Executable::Ivm(_) => panic!("expected instructions"),
        Executable::IvmProved(_) => panic!("expected instructions"),
        Executable::Batch(_) => panic!("expected instructions"),
    };
    assert_eq!(instructions.len(), 1);
    let log = instructions[0]
        .as_any()
        .downcast_ref::<Log>()
        .expect("log instruction");
    assert_eq!(log.level, Level::WARN);
    assert_eq!(log.msg, "hello");
}
#[test]
fn multisig_register_run_defaults_to_domainless_home_domain() {
    let account = AccountId::new(fixture_key_pair(0xD6).public_key().clone());
    let mut ctx = CaptureContext::new(account.clone());
    let register = multisig::Register {
        signatories: vec![account.to_string()],
        weights: vec![1],
        quorum: 1,
        account: Some(account.to_string()),
        transaction_ttl: std::time::Duration::from_millis(
            iroha::executor_data_model::isi::multisig::DEFAULT_MULTISIG_TTL_MS,
        )
        .into(),
    };
    register.run(&mut ctx).expect("register should build");
    let exec = ctx.captured.expect("captured executable");
    let Executable::Instructions(instructions) = exec else {
        panic!("expected instructions executable");
    };
    assert_eq!(instructions.len(), 1);
    let payload = instructions[0]
        .as_any()
        .downcast_ref::<iroha::data_model::isi::CustomInstruction>()
        .expect("custom multisig instruction")
        .payload()
        .as_ref()
        .to_owned();
    let instruction: iroha::executor_data_model::isi::multisig::MultisigInstructionBox =
        norito::json::from_str(&payload).expect("multisig instruction payload should parse");
    let iroha::executor_data_model::isi::multisig::MultisigInstructionBox::Register(register) =
        instruction
    else {
        panic!("expected multisig register instruction");
    };
    assert_eq!(
        register.home_domain, None,
        "CLI default multisig registration should not invent a home domain"
    );
}
#[test]
fn admission_hint_reports_disabled_domain() {
    use iroha::data_model::isi::error::AccountAdmissionError;
    let err = eyre::Report::from(AccountAdmissionError::ImplicitAccountCreationDisabled);
    let hint = account_admission_hint(err.as_ref()).expect("hint should be present");
    assert!(
        hint.contains("Implicit account creation is disabled"),
        "unexpected hint: {hint}"
    );
    assert!(
        hint.contains("register the destination"),
        "hint should instruct explicit registration: {hint}"
    );
}
#[test]
fn admission_hint_reports_quota_scope() {
    use iroha::data_model::isi::error::{
        AccountAdmissionError, AccountAdmissionQuotaExceeded, AccountAdmissionQuotaScope,
    };
    let err = eyre::Report::from(AccountAdmissionError::QuotaExceeded(
        AccountAdmissionQuotaExceeded {
            scope: AccountAdmissionQuotaScope::Transaction,
            created: 3,
            cap: 2,
        },
    ));
    let hint = account_admission_hint(err.as_ref()).expect("hint should be present");
    assert!(hint.contains("quota"), "unexpected hint: {hint}");
    assert!(
        hint.contains("transaction"),
        "quota scope should be surfaced: {hint}"
    );
}
#[test]
fn admission_rejected_message_includes_hint() {
    let i18n = Localizer::new(Bundle::Cli, Language::English);
    let message = account_admission_rejected_message("hint text", &i18n);
    assert!(
        message.contains("Account admission rejected"),
        "unexpected message: {message}"
    );
    assert!(
        message.contains("hint text"),
        "unexpected message: {message}"
    );
}
#[test]
fn listen_messages_include_timeout_context() {
    let i18n = Localizer::new(Bundle::Cli, Language::English);
    let filter = EventFilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new());
    let message = listen_events_message(&filter, Some(Duration::from_secs(1)), &i18n);
    assert!(
        message.contains("Listening to events"),
        "unexpected message: {message}"
    );
    assert!(message.contains("timeout"), "unexpected message: {message}");
    let height = NonZeroU64::new(7).expect("height");
    let message = listen_blocks_message(height, Some(Duration::from_secs(2)), &i18n);
    assert!(
        message.contains("Listening to blocks"),
        "unexpected message: {message}"
    );
    assert!(message.contains("timeout"), "unexpected message: {message}");
}
#[test]
fn trigger_register_builds_expected_instruction() {
    // Prepare a tiny bytecode blob file
    let dir = std::env::temp_dir();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = dir.join(format!("iroha_cli_trigger_test_{ts}.to"));
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(&[1, 2, 3, 4]).unwrap();
    // Use a deterministic account for authority
    let account = account_with_seed("wonderland", 0x42);
    let mut ctx = CaptureContext::new(account.clone());
    let args = trigger::Register {
        id: "my_trigger".parse().unwrap(),
        path: Some(path),
        instructions_stdin: false,
        instructions: None,
        repeats: Some(2),
        authority: None,
        filter: trigger::FilterType::Execute,
        time_start_ms: None,
        time_period_ms: None,
        data_filter: None,
        data_domain: None,
        data_account: None,
        data_asset: None,
        data_asset_account: None,
        data_asset_scope: None,
        data_asset_definition: None,
        data_role: None,
        data_trigger: None,
        data_verifying_key: None,
        data_proof: None,
        data_proof_only: None,
        data_vk_only: None,
        time_start: None,
        time_start_rfc3339: None,
    };
    args.run(&mut ctx).expect("run ok");
    let exec = ctx.captured.expect("captured");
    let Executable::Instructions(instructions) = exec else {
        panic!("expected instructions executable");
    };
    assert_eq!(instructions.len(), 1);
    let ib = &instructions[0];
    let any: &dyn iroha::data_model::isi::Instruction = &**ib;
    let reg = any
        .as_any()
        .downcast_ref::<iroha::data_model::isi::RegisterBox>()
        .expect("register instruction");
    let iroha::data_model::isi::RegisterBox::Trigger(reg_tr) = reg else {
        panic!("expected trigger register")
    };
    let trig = reg_tr.object();
    assert_eq!(trig.id(), &"my_trigger".parse().unwrap());
    assert_eq!(
        trig.action().repeats(),
        iroha::data_model::trigger::action::Repeats::Exactly(2)
    );
    assert_eq!(trig.action().authority(), &account);
    match trig.action().filter() {
        iroha::data_model::events::EventFilterBox::ExecuteTrigger(f) => {
            let expected = ExecuteTriggerEventFilter::new()
                .for_trigger("my_trigger".parse().unwrap())
                .under_authority(account.into());
            assert_eq!(f, &expected);
        }
        _ => panic!("expected ExecuteTrigger filter"),
    }
}
#[test]
fn trigger_register_time_filter_defaults_to_exactly_one() {
    // Prepare tiny bytecode file
    let dir = std::env::temp_dir();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = dir.join(format!("iroha_cli_trigger_test_time_{ts}.to"));
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(&[0xAA, 0xBB]).unwrap();
    // Deterministic account
    let account = account_with_seed("wonderland", 0x42);
    let mut ctx = CaptureContext::new(account.clone());
    let start_ms = 1_700_000_000_000u64;
    // No repeats provided; non-periodic schedule should imply Exactly(1)
    let args = trigger::Register {
        id: "once".parse().unwrap(),
        path: Some(path),
        instructions_stdin: false,
        instructions: None,
        repeats: None,
        authority: None,
        filter: trigger::FilterType::Time,
        time_start_ms: Some(start_ms),
        time_period_ms: None,
        data_filter: None,
        data_domain: None,
        data_account: None,
        data_asset: None,
        data_asset_account: None,
        data_asset_scope: None,
        data_asset_definition: None,
        data_role: None,
        data_trigger: None,
        data_verifying_key: None,
        data_proof: None,
        data_proof_only: None,
        data_vk_only: None,
        time_start: None,
        time_start_rfc3339: None,
    };
    args.run(&mut ctx).expect("run ok");
    let exec = ctx.captured.expect("captured");
    let Executable::Instructions(instructions) = exec else {
        panic!("expected instructions executable");
    };
    assert_eq!(instructions.len(), 1);
    let ib = &instructions[0];
    let reg = (**ib)
        .as_any()
        .downcast_ref::<iroha::data_model::isi::RegisterBox>()
        .expect("register");
    let iroha::data_model::isi::RegisterBox::Trigger(reg_tr) = reg else {
        panic!("expected trigger register")
    };
    let trig = reg_tr.object();
    assert_eq!(
        trig.action().repeats(),
        iroha::data_model::trigger::action::Repeats::Exactly(1)
    );
    match trig.action().filter() {
        iroha::data_model::events::EventFilterBox::Time(_) => {}
        _ => panic!("expected time filter"),
    }
}
#[test]
fn trigger_register_data_domain_filter_builds() {
    // Prepare tiny bytecode file
    let dir = std::env::temp_dir();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = dir.join(format!("iroha_cli_trigger_test_data_{ts}.to"));
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(&[0x01]).unwrap();
    let account = account_with_seed("wonderland", 0x42);
    let mut ctx = CaptureContext::new(account);
    let args = trigger::Register {
        id: "data_trig".parse().unwrap(),
        path: Some(path),
        instructions_stdin: false,
        instructions: None,
        repeats: Some(1),
        authority: None,
        filter: trigger::FilterType::Data,
        time_start_ms: None,
        time_period_ms: None,
        data_filter: None,
        data_domain: Some(DomainId::try_new("wonderland", "universal").unwrap()),
        data_account: None,
        data_asset: None,
        data_asset_account: None,
        data_asset_scope: None,
        data_asset_definition: None,
        data_role: None,
        data_trigger: None,
        data_verifying_key: None,
        data_proof: None,
        data_proof_only: None,
        data_vk_only: None,
        time_start: None,
        time_start_rfc3339: None,
    };
    args.run(&mut ctx).expect("run ok");
    let exec = ctx.captured.expect("captured");
    let Executable::Instructions(instructions) = exec else {
        panic!("expected instructions executable");
    };
    assert_eq!(instructions.len(), 1);
    let ib = &instructions[0];
    let reg = (**ib)
        .as_any()
        .downcast_ref::<iroha::data_model::isi::RegisterBox>()
        .expect("register");
    let iroha::data_model::isi::RegisterBox::Trigger(reg_tr) = reg else {
        panic!("expected trigger register")
    };
    let trig = reg_tr.object();
    match trig.action().filter() {
        iroha::data_model::events::EventFilterBox::Data(_) => {}
        _ => panic!("expected data filter"),
    }
}

#[path = "main_shared_tests/canonical_reads.rs"]
mod canonical_reads;

#[path = "main_shared_tests/point_reads.rs"]
mod point_reads;

#[path = "main_shared_tests/collection_lists.rs"]
mod collection_lists;

#[test]
fn library_test_build_metadata_is_an_explicit_development_identity() {
    let build = build_metadata();
    assert_eq!(build.source_commit_label(), "local-fast-build");
    assert_eq!(build.sealed_source_commit(), None);
    assert_eq!(
        compiled_build_identity().unwrap().release_source_commit(),
        Err(iroha_core::release_identity::BuildIdentityError::DevelopmentSource)
    );
}

#[test]
fn metadata_installation_preserves_the_first_identity() {
    let slot = std::sync::OnceLock::new();
    let initial = CompiledBuildMetadata::from_compiled_parts(
        "executable-version",
        Some("local-fast-build"),
        None,
        None,
        None,
        None,
    );
    assert!(install_build_metadata(&slot, initial));
    assert!(install_build_metadata(&slot, initial));
    let different = CompiledBuildMetadata::from_compiled_parts(
        "another-executable-version",
        Some("local-fast-build"),
        None,
        None,
        None,
        None,
    );
    assert!(!install_build_metadata(&slot, different));
    assert_eq!(slot.get(), Some(&initial));
    assert!(install_build_metadata(&slot, initial));
}

#[test]
fn version_is_supplied_by_the_executable() {
    let build = CompiledBuildMetadata::from_compiled_parts(
        "executable-version",
        Some("local-fast-build"),
        None,
        None,
        None,
        None,
    );
    let error = args_command(build)
        .try_get_matches_from(["iroha", "--version"])
        .expect_err("version display exits through clap");
    assert_eq!(error.kind(), ErrorKind::DisplayVersion);
    assert_eq!(error.render().to_string(), "iroha executable-version\n");
}
