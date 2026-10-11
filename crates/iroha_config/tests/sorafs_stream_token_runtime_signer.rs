//! Validate the sole signer stream-token configuration and independent public trust.

use iroha_config::parameters::{actual::Root as ActualConfig, defaults, user::Root as UserConfig};
use iroha_config_base::{env::MockEnv, read::ConfigReader, toml::TomlSource};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::account::AccountId;
use std::{fmt::Write as _, path::PathBuf};
fn base_reader() -> ConfigReader {
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/base.toml");
    ConfigReader::new()
        .read_toml_with_extends(base_path)
        .expect("base config should load")
}
fn parse_overlay(source: &str) -> Result<ActualConfig, String> {
    let table = source
        .parse()
        .map_err(|error| format!("inline TOML must parse: {error}"))?;
    base_reader()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .map_err(|error| format!("{error:?}"))?
        .parse()
        .map_err(|error| format!("{error:?}"))
}
fn public_key_hex(seed: u8) -> String {
    let key_pair =
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("test Ed25519 keypair");
    hex::encode(key_pair.public_key().to_bytes().1)
}
fn native_signer_bindings() -> String {
    [
        ("proof_outcome", "proof-outcome", 0x52),
        ("repair", "repair", 0x53),
        ("reserve", "reserve", 0x54),
        ("orderbook", "orderbook", 0x55),
    ]
    .into_iter()
    .fold(String::new(), |mut bindings, (role, handle_role, seed)| {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("test Ed25519 keypair");
        let public_key_hex = hex::encode(key_pair.public_key().to_bytes().1);
        let authority = AccountId::new(key_pair.public_key().clone())
            .to_i105_for_discriminant(defaults::common::CHAIN_DISCRIMINANT)
            .expect("test authority must encode as I105");
        let policy_digest_hex = hex::encode([seed; 32]);
        write!(
            bindings,
            r#"
[sorafs.storage.native_transaction_signers.{role}]
handle = "software://sorafs/{handle_role}/stream-token-primary"
authority = "{authority}"
algorithm = "ed25519"
public_key_hex = "{public_key_hex}"
revision = 1
policy_digest_hex = "{policy_digest_hex}""#
        )
        .expect("writing to a String cannot fail");
        bindings.push('\n');
        bindings
    })
}
const SIGNER_PREFIX: &str = "sorafs.storage.stream_tokens.signer";
const PROVIDER_HEX: &str = "abababababababababababababababababababababababababababababababab";
fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}
fn signer_fields() -> Vec<(&'static str, String)> {
    [
        (
            "runtime_handle",
            quoted("hsm://sorafs/stream-token/primary"),
        ),
        ("key_handle", quoted("pkcs11:production/stream-token/key-7")),
        ("service_id", quoted("stream-primary")),
        ("administrator_id", quoted("stream-security-primary")),
        ("public_key_hex", quoted(&public_key_hex(0x42))),
        ("key_revision", "7".to_owned()),
        ("policy_revision", "9".to_owned()),
        ("policy_digest_hex", quoted(&"b4".repeat(32))),
        ("attester.service_id", quoted("custody-authority-primary")),
        (
            "attester.administrator_id",
            quoted("custody-security-primary"),
        ),
        ("attester.public_key_hex", quoted(&public_key_hex(0x43))),
        ("attester.key_revision", "3".to_owned()),
        ("attester.policy_revision", "5".to_owned()),
        ("attester.policy_digest_hex", quoted(&"c6".repeat(32))),
        ("attester.active_from_unix_ms", "800000".to_owned()),
        ("attester.active_until_unix_ms", "2000000".to_owned()),
        ("attester.max_validity_ms", "1000000".to_owned()),
        ("attester.max_anchor_age_ms", "10000".to_owned()),
        (
            "observer.runtime_handle",
            quoted("finalized-source:prod/stream-token/primary"),
        ),
        ("observer.service_id", quoted("state-observer-primary")),
        (
            "observer.administrator_id",
            quoted("state-observer-security-primary"),
        ),
        ("observer.public_key_hex", quoted(&public_key_hex(0x44))),
        ("observer.key_revision", "11".to_owned()),
        ("observer.policy_revision", "13".to_owned()),
        ("observer.policy_digest_hex", quoted(&"d7".repeat(32))),
        ("observer.active_from_unix_ms", "900000".to_owned()),
        ("observer.active_until_unix_ms", "1900000".to_owned()),
        ("observer.max_state_age_ms", "300000".to_owned()),
    ]
    .into()
}
fn signer_tables(fields: &[(&str, String)]) -> String {
    let mut source = String::new();
    for prefix in ["", "attester.", "observer."] {
        let suffix = prefix.strip_suffix('.').unwrap_or(prefix);
        write!(
            source,
            "\n[{SIGNER_PREFIX}{}]\n",
            if suffix.is_empty() {
                String::new()
            } else {
                format!(".{suffix}")
            }
        )
        .expect("String write");
        for (field, value) in fields {
            if let Some(leaf) = field
                .strip_prefix(prefix)
                .filter(|leaf| !leaf.contains('.'))
            {
                writeln!(source, "{leaf} = {value}").expect("String write");
            }
        }
    }
    source
}
fn native_gateway_credential(name: &str) -> String {
    let root = if cfg!(windows) {
        "C:/runtime/gateway"
    } else {
        "/runtime/gateway"
    };
    format!("{root}/{name}")
}
fn native_gateway_bindings() -> String {
    let account = |seed| {
        AccountId::new(
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .expect("test key")
                .public_key()
                .clone(),
        )
        .to_i105_for_discriminant(defaults::common::CHAIN_DISCRIMINANT)
        .expect("test account")
    };
    let fee = norito::json::to_json(&iroha_data_model::transaction::FeePaymentIntent::authority(
        Vec::new(),
        None,
    ))
    .expect("fee JSON");
    format!(
        r#"
[sorafs.storage.stream_tokens.admission_native]
operator = "{}"
operator_credential = "{operator_credential}"
observer = "{}"
observer_credential = "{observer_credential}"
reputation_recorder = "{}"
reputation_recorder_credential = "{reputation_recorder_credential}"
fee_payment_json = '{}'
clock_uncertainty_ms = 100
"#,
        account(0x71),
        account(0x72),
        account(0x73),
        fee,
        operator_credential = native_gateway_credential("operator.key"),
        observer_credential = native_gateway_credential("observer.key"),
        reputation_recorder_credential = native_gateway_credential("recorder.key"),
    )
}
fn enabled_with_fields(fields: &[(&str, String)]) -> String {
    format!(
        r#"
[sorafs.storage]
enabled = true
provider_id_hex = "{PROVIDER_HEX}"
[sorafs.storage.stream_tokens]
enabled = true
admission_provider_handle = "sealed-cas:prod/stream-token/gateway-admission/v1"
admission_provider_revision = 7
admission_provider_policy_digest_hex = "{}"
{}{}{}
"#,
        "a5".repeat(32),
        signer_tables(fields),
        native_signer_bindings(),
        native_gateway_bindings()
    )
}
fn enabled_overlay() -> String {
    enabled_with_fields(&signer_fields())
}
fn replaced_field(field: &str, value: String) -> String {
    let mut fields = signer_fields();
    fields
        .iter_mut()
        .find(|(name, _)| *name == field)
        .expect("known field")
        .1 = value;
    enabled_with_fields(&fields)
}
fn rejects(source: &str, expected: &str) {
    let error = parse_overlay(source).expect_err("configuration must fail closed");
    assert!(error.contains(expected), "expected {expected}; got {error}");
}
#[test]
fn enabled_stream_tokens_parse_one_exact_non_secret_runtime_binding() {
    let actual = parse_overlay(&enabled_overlay()).expect("complete independent signer binding");
    let storage = &actual.torii.sorafs_storage;
    assert_eq!(
        storage.provider_id.as_ref().expect("provider").as_bytes(),
        &[0xab; 32]
    );
    let tokens = &storage.stream_tokens;
    assert!(tokens.enabled);
    let signer_backend = tokens.signer.as_ref().expect("complete signer config");
    assert_eq!(
        signer_backend.runtime_handle,
        "hsm://sorafs/stream-token/primary"
    );
    assert_eq!(
        signer_backend.key_handle,
        "pkcs11:production/stream-token/key-7"
    );
    assert_eq!(signer_backend.service_id, "stream-primary");
    assert_eq!(signer_backend.administrator_id, "stream-security-primary");
    assert_eq!(hex::encode(signer_backend.public_key), public_key_hex(0x42));
    assert_eq!(
        (signer_backend.key_revision, signer_backend.policy_revision),
        (7, 9)
    );
    assert_eq!(signer_backend.policy_digest, [0xb4; 32]);
    let attester = &signer_backend.attester;
    assert_eq!(attester.authority.service_id, "custody-authority-primary");
    assert_eq!(
        attester.authority.administrator_id,
        "custody-security-primary"
    );
    assert_eq!(
        hex::encode(attester.authority.public_key),
        public_key_hex(0x43)
    );
    assert_eq!(
        (
            attester.authority.key_revision,
            attester.authority.policy_revision
        ),
        (3, 5)
    );
    assert_eq!(attester.authority.policy_digest, [0xc6; 32]);
    assert_eq!(
        (
            attester.authority.active_from_unix_ms,
            attester.authority.active_until_unix_ms
        ),
        (800_000, 2_000_000)
    );
    assert_eq!(
        (attester.max_validity_ms, attester.max_anchor_age_ms),
        (1_000_000, 10000)
    );
    let observer = &signer_backend.observer;
    assert_eq!(
        observer.runtime_handle,
        "finalized-source:prod/stream-token/primary"
    );
    assert_eq!(observer.authority.service_id, "state-observer-primary");
    assert_eq!(
        observer.authority.administrator_id,
        "state-observer-security-primary"
    );
    assert_eq!(
        hex::encode(observer.authority.public_key),
        public_key_hex(0x44)
    );
    assert_eq!(
        (
            observer.authority.key_revision,
            observer.authority.policy_revision
        ),
        (11, 13)
    );
    assert_eq!(observer.authority.policy_digest, [0xd7; 32]);
    assert_eq!(
        (
            observer.authority.active_from_unix_ms,
            observer.authority.active_until_unix_ms
        ),
        (900_000, 1_900_000)
    );
    assert_eq!(observer.max_state_age_ms, 300_000);
    assert_eq!(
        tokens.admission_provider_handle.as_deref(),
        Some("sealed-cas:prod/stream-token/gateway-admission/v1")
    );
    assert_eq!(tokens.admission_provider_revision, Some(7));
    assert_eq!(tokens.admission_provider_policy_digest, Some([0xa5; 32]));
    assert_eq!(tokens.admission_max_pending, 65_536);
    assert_eq!(tokens.admission_max_tracked_tokens, 65_536);
    assert_eq!(tokens.admission_reconcile_max_items, 256);
    assert_eq!(tokens.admission_lease_ttl_ms, 120_000);
}
#[path = "sorafs_stream_token_runtime_signer/signer_config_tests.rs"]
mod signer_config_tests;
#[test]
fn legacy_stream_token_signing_key_path_is_rejected_without_disclosing_it() {
    let retired_path = "/run/secrets/retired-stream-token-seed";
    let table = format!(
        r#"
[sorafs.storage.stream_tokens]
signing_key_path = "{retired_path}"
"#
    )
    .parse()
    .expect("legacy inline TOML should parse");
    let error = base_reader()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .expect_err("legacy stream-token seed path must be rejected");
    let diagnostic = format!("{error:?}");
    assert!(
        diagnostic.contains("unknown parameter")
            && diagnostic.contains("sorafs.storage.stream_tokens.signing_key_path"),
        "unexpected legacy field diagnostic: {diagnostic}"
    );
    assert!(
        !diagnostic.contains(retired_path),
        "unknown-field diagnostics must not disclose the retired path"
    );
}
#[test]
fn retired_sorafs_environment_aliases_remain_unvisited() {
    const RETIRED_ALIASES: [(&str, &str); 25] = [
        ("SORAFS_TELEMETRY_REQUIRE_SUBMITTER", "true"),
        ("SORAFS_TELEMETRY_REQUIRE_NONCE", "true"),
        ("SORAFS_TELEMETRY_MAX_WINDOW_GAP_SECS", "1"),
        ("SORAFS_TELEMETRY_REJECT_ZERO_CAPACITY", "true"),
        ("SORAFS_TELEMETRY_SUBMITTERS", "retired"),
        ("SORAFS_TELEMETRY_PER_PROVIDER_SUBMITTERS", "retired"),
        ("SORAFS_STORAGE_ENABLED", "true"),
        ("SORAFS_STORAGE_DATA_DIR", "/run/retired"),
        ("SORAFS_STREAM_TOKENS_ENABLED", "true"),
        ("GOV_SORAFS_PIN_POLICY_MIN_REPLICAS_FLOOR", "2"),
        ("GOV_SORAFS_PIN_POLICY_MAX_REPLICAS_CEILING", "4"),
        ("GOV_SORAFS_PIN_POLICY_MAX_RETENTION_EPOCH", "100"),
        ("GOV_SORAFS_PIN_POLICY_ALLOWED_STORAGE_CLASSES", "hot"),
        ("GOV_SORAFS_PIN_POLICY_REQUIRE_COUNCIL_SIGNATURES", "true"),
        ("GOV_SORAFS_PENALTY_UTILISATION_FLOOR_BPS", "5000"),
        ("GOV_SORAFS_PENALTY_UPTIME_FLOOR_BPS", "9000"),
        ("GOV_SORAFS_PENALTY_POR_FLOOR_BPS", "9000"),
        ("GOV_SORAFS_PENALTY_STRIKE_THRESHOLD", "3"),
        ("GOV_SORAFS_PENALTY_BOND_BPS", "100"),
        ("GOV_SORAFS_PENALTY_COOLDOWN_WINDOWS", "2"),
        ("GOV_SORAFS_PENALTY_MAX_PDP_FAILURES", "3"),
        ("GOV_SORAFS_PENALTY_MAX_POTR_BREACHES", "3"),
        ("TORII_SORAFS_DISCOVERY_ENABLED", "true"),
        (
            "TORII_SORAFS_PUBLISH_GATEWAY_BASE_URL",
            "https://retired.example",
        ),
        ("TORII_SORAFS_ADMISSION_DIR", "/run/retired-admission"),
    ];
    let env = RETIRED_ALIASES
        .iter()
        .fold(MockEnv::new(), |env, (alias, value)| {
            env.set(*alias, *value)
        });
    let actual: ActualConfig = base_reader()
        .with_env(env.clone())
        .read_and_complete::<UserConfig>()
        .expect("retired environment aliases are not schema inputs")
        .parse()
        .expect("retired environment aliases cannot alter V1 configuration");
    assert!(!actual.torii.sorafs_storage.stream_tokens.enabled);
    let unvisited = env.unvisited();
    for (alias, _) in RETIRED_ALIASES {
        assert!(
            unvisited.contains(alias),
            "retired environment alias must remain unvisited: {alias}"
        );
    }
}
#[test]
fn sorafs_configuration_has_no_production_environment_bindings() {
    let source = [
        include_str!("../src/parameters/user.rs"),
        include_str!("../src/parameters/user/stream_token_signer.rs"),
        include_str!("../src/parameters/user/stream_token_admission.rs"),
    ]
    .join("\n");
    let bindings = source
        .lines()
        .filter(|line| line.contains("env =") && line.contains("SORAFS_"))
        .collect::<Vec<_>>();
    assert!(
        bindings.is_empty(),
        "SoraFS V1 behavior must be configured through canonical TOML only; found environment bindings: {bindings:?}"
    );
}

#[path = "sorafs_stream_token_runtime_signer/production_identity_tests.rs"]
mod production_identity_tests;

#[test]
fn gateway_native_configuration_preserves_exact_public_pins_and_default_deadline() {
    let actual = parse_overlay(&enabled_overlay()).expect("complete native gateway");
    let tokens = &actual.torii.sorafs_storage.stream_tokens;
    assert_eq!(tokens.admission_operation_timeout_ms, 30_000);
    assert_eq!(tokens.admission_reconcile_interval_ms, 1_000);
    let native = tokens.admission_native.as_ref().expect("native required");
    assert_ne!(native.operator, native.observer);
    assert_ne!(native.operator, native.reputation_recorder);
    assert_ne!(native.observer, native.reputation_recorder);
    assert_eq!(
        native.reputation_recorder_credential,
        PathBuf::from(native_gateway_credential("recorder.key"))
    );
    assert_eq!(native.clock_uncertainty_ms, 100);
    assert_eq!(
        native.operator_credential,
        PathBuf::from(native_gateway_credential("operator.key"))
    );
    assert_eq!(
        native.observer_credential,
        PathBuf::from(native_gateway_credential("observer.key"))
    );
    assert_eq!(
        native.fee_payment,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None)
    );
}
#[test]
fn gateway_native_configuration_rejects_missing_partial_or_disabled_custody() {
    let base = enabled_overlay();
    rejects(
        &base.replace(&native_gateway_bindings(), ""),
        "admission_native is required",
    );
    for line in [
        format!(
            "operator_credential = \"{}\"\n",
            native_gateway_credential("operator.key")
        ),
        "clock_uncertainty_ms = 100\n".to_owned(),
    ] {
        rejects(&base.replace(&line, ""), "admission_native is required");
    }
    rejects(&native_gateway_bindings(), "admission_native is forbidden");
}
#[test]
fn gateway_native_configuration_rejects_shared_or_relative_credentials_and_bad_clock() {
    let base = enabled_overlay();
    let bindings = native_gateway_bindings();
    let operator = bindings
        .lines()
        .find_map(|line| line.strip_prefix("operator = "))
        .unwrap();
    let observer_line = bindings
        .lines()
        .find(|line| line.starts_with("observer = "))
        .unwrap();
    rejects(
        &base.replace(observer_line, &format!("observer = {operator}")),
        "admission_native is required",
    );
    for source in [
        base.replace(
            &native_gateway_credential("observer.key"),
            &native_gateway_credential("operator.key"),
        ),
        base.replace(&native_gateway_credential("observer.key"), "observer.key"),
        base.replace(
            &native_gateway_credential("observer.key"),
            &native_gateway_credential("../observer.key"),
        ),
        base.replace("clock_uncertainty_ms = 100", "clock_uncertainty_ms = 5001"),
        base.replace("fee_payment_json = '", "fee_payment_json = 'malformed"),
    ] {
        rejects(&source, "admission_native is required");
    }
}
#[test]
fn gateway_operation_deadline_is_bounded_independently_of_lease_lifetime() {
    for value in [0, 60_001] {
        rejects(
            &enabled_overlay().replace(
                "admission_provider_revision = 7",
                &format!(
                    "admission_provider_revision = 7\nadmission_operation_timeout_ms = {value}"
                ),
            ),
            "admission_operation_timeout_ms must be within",
        );
    }
    for value in [1, 60_000] {
        let actual = parse_overlay(&enabled_overlay().replace(
            "admission_provider_revision = 7",
            &format!("admission_provider_revision = 7\nadmission_operation_timeout_ms = {value}"),
        ))
        .expect("bounded deadline");
        assert_eq!(
            actual
                .torii
                .sorafs_storage
                .stream_tokens
                .admission_operation_timeout_ms,
            value
        );
    }
}

#[test]
fn native_reputation_recorder_custody_is_required_independent_and_absolute() {
    let base = enabled_overlay();
    let bindings = native_gateway_bindings();
    let recorder_line = bindings
        .lines()
        .find(|line| line.starts_with("reputation_recorder = "))
        .unwrap();
    let credential_line = bindings
        .lines()
        .find(|line| line.starts_with("reputation_recorder_credential = "))
        .unwrap();
    for line in [recorder_line, credential_line] {
        rejects(&base.replace(line, ""), "admission_native is required");
    }
    for role in ["operator", "observer"] {
        let value = bindings
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{role} = ")))
            .unwrap();
        rejects(
            &base.replace(recorder_line, &format!("reputation_recorder = {value}")),
            "admission_native is required",
        );
        rejects(
            &base.replace(
                &native_gateway_credential("recorder.key"),
                &native_gateway_credential(&format!("{role}.key")),
            ),
            "admission_native is required",
        );
    }
    for replacement in [
        "recorder.key".to_owned(),
        native_gateway_credential("../recorder.key"),
    ] {
        rejects(
            &base.replace(&native_gateway_credential("recorder.key"), &replacement),
            "admission_native is required",
        );
    }
    rejects(
        &format!("[sorafs.storage.stream_tokens.admission_native]\n{credential_line}\n"),
        "admission_native is forbidden",
    );
}

#[test]
fn native_delivery_reconcile_interval_has_a_finite_independent_bound() {
    for value in [0, 60_001] {
        rejects(
            &enabled_overlay().replace(
                "admission_provider_revision = 7",
                &format!(
                    "admission_provider_revision = 7\nadmission_reconcile_interval_ms = {value}"
                ),
            ),
            "admission_reconcile_interval_ms must be within",
        );
    }
    for value in [1, 60_000] {
        let source = enabled_overlay().replace(
            "admission_provider_revision = 7",
            &format!("admission_provider_revision = 7\nadmission_reconcile_interval_ms = {value}"),
        );
        let config = parse_overlay(&source).expect("bounded native delivery interval");
        assert_eq!(
            config
                .torii
                .sorafs_storage
                .stream_tokens
                .admission_reconcile_interval_ms,
            value
        );
    }
}
