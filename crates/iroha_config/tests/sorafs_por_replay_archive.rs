//! Validate the public finalized-PoR replay-archive binding and worker bounds.

use iroha_config::parameters::{actual::Root as ActualConfig, defaults, user::Root as UserConfig};
use iroha_config_base::{env::MockEnv, read::ConfigReader, toml::TomlSource};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::account::AccountId;
use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};
fn base_reader() -> ConfigReader {
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/base.toml");
    ConfigReader::new()
        .with_env(MockEnv::new())
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
fn ed25519_public_key_hex(seed: u8) -> String {
    let key_pair =
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("test Ed25519 keypair");
    hex::encode(key_pair.public_key().to_bytes().1)
}
fn absolute_state_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\iroha\sorafs\reputation")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/var/lib/iroha/sorafs/reputation")
    }
}
fn absolute_trust_policy_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\iroha\reputation-trust-policy.to")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/iroha/reputation-trust-policy.to")
    }
}
fn toml_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "\\\\")
}
fn native_signer_bindings() -> String {
    [
        ("proof_outcome", "proof-outcome", 0x84),
        ("repair", "repair", 0x85),
        ("reserve", "reserve", 0x86),
        ("orderbook", "orderbook", 0x87),
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
handle = "software://sorafs/{handle_role}/por-replay-primary"
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
fn enabled_overlay(
    handle: &str,
    revision: u64,
    archive_id_hex: &str,
    policy_digest_hex: &str,
    signing_public_key_hex: &str,
    poll_interval_ms: u64,
    max_records_per_tick: u32,
) -> String {
    let native_signers = native_signer_bindings();
    let publisher_public_key_hex = ed25519_public_key_hex(0x85);
    let state_dir = toml_path(&absolute_state_dir());
    let trust_policy_path = toml_path(&absolute_trust_policy_path());
    format!(
        r#"
[sorafs.storage]
enabled = true
reputation_trust_policy_path = "{trust_policy_path}"

[sorafs.storage.reputation_runtime]
enabled = true
state_dir = "{state_dir}"
window_start_height = 10
window_end_height = 20
finalized_query_handle = "ledger.finalized.por-replay-primary"
journal_checkpoint_provider_handle = "sealed.reputation.journal.por-replay-primary"
journal_checkpoint_provider_revision = 1
journal_checkpoint_provider_policy_digest_hex = "6060606060606060606060606060606060606060606060606060606060606060"
journal_transaction_submitter_handle = "queue.reputation.por-replay-primary"
journal_transaction_submitter_revision = 11
journal_transaction_submitter_policy_digest_hex = "6161616161616161616161616161616161616161616161616161616161616161"
threshold_signer_handle = "software://sorafs/reputation/por-replay-primary"
threshold_signer_revision = 12
threshold_signer_policy_digest_hex = "6262626262626262626262626262626262626262626262626262626262626262"
governance_dag_handle = "governance.dag.por-replay-primary"
governance_dag_revision = 13
governance_dag_policy_digest_hex = "6363636363636363636363636363636363636363636363636363636363636363"
governance_publisher_peer_id = "12D3KooWPorReplayPrimary"
governance_publisher_public_key_hex = "{publisher_public_key_hex}"

[sorafs.storage.por_replay_archive]
enabled = true
handle = "{handle}"
archive_id_hex = "{archive_id_hex}"
revision = {revision}
policy_digest_hex = "{policy_digest_hex}"
signing_public_key_hex = "{signing_public_key_hex}"
poll_interval_ms = {poll_interval_ms}
max_records_per_tick = {max_records_per_tick}
max_successor_receipts = 1024
max_successor_proof_bytes = 1048576
{native_signers}
"#
    )
}
#[test]
fn enabled_archive_projects_one_exact_non_secret_binding() {
    let public_key_hex = ed25519_public_key_hex(0x83);
    let actual = parse_overlay(&enabled_overlay(
        "object-lock://sorafs/por-replay-archive/primary",
        17,
        &"81".repeat(32),
        &"82".repeat(32),
        &public_key_hex,
        750,
        31,
    ))
    .expect("canonical replay-archive binding");
    let archive = actual
        .torii
        .sorafs_storage
        .por_replay_archive
        .expect("enabled archive");
    assert_eq!(
        archive.handle,
        "object-lock://sorafs/por-replay-archive/primary"
    );
    assert_eq!(archive.archive_id, [0x81; 32]);
    assert_eq!(archive.revision, 17);
    assert_eq!(archive.policy_digest, [0x82; 32]);
    let decoded_public_key = hex::decode(public_key_hex).expect("test key hex");
    let mut expected_public_key = [0_u8; 32];
    expected_public_key.copy_from_slice(&decoded_public_key);
    assert_eq!(archive.signing_public_key, expected_public_key);
    assert_eq!(archive.poll_interval.as_millis(), 750);
    assert_eq!(archive.max_records_per_tick, 31);
    assert_eq!(archive.max_successor_receipts, 1_024);
    assert_eq!(archive.max_successor_proof_bytes, 1_048_576);
}
#[test]
fn enabled_archive_rejects_substituted_zero_noncanonical_and_unbounded_claims() {
    let key = ed25519_public_key_hex(0x83);
    let weak_key = format!("01{}", "00".repeat(31));
    for (label, source, expected) in [
        (
            "test-marked handle",
            enabled_overlay(
                "object-lock://sorafs/por-replay-archive/test-secret",
                17,
                &"81".repeat(32),
                &"82".repeat(32),
                &key,
                750,
                31,
            ),
            "handle must be one canonical production runtime handle",
        ),
        (
            "zero revision",
            enabled_overlay(
                "object-lock://sorafs/por-replay-archive/primary",
                0,
                &"81".repeat(32),
                &"82".repeat(32),
                &key,
                750,
                31,
            ),
            "revision must be nonzero",
        ),
        (
            "zero archive identity",
            enabled_overlay(
                "object-lock://sorafs/por-replay-archive/primary",
                17,
                &"00".repeat(32),
                &"82".repeat(32),
                &key,
                750,
                31,
            ),
            "archive_id_hex must be canonical lowercase non-zero 32-byte hex",
        ),
        (
            "uppercase policy digest",
            enabled_overlay(
                "object-lock://sorafs/por-replay-archive/primary",
                17,
                &"81".repeat(32),
                &"AB".repeat(32),
                &key,
                750,
                31,
            ),
            "policy_digest_hex must be canonical lowercase non-zero 32-byte hex",
        ),
        (
            "weak receipt key",
            enabled_overlay(
                "object-lock://sorafs/por-replay-archive/primary",
                17,
                &"81".repeat(32),
                &"82".repeat(32),
                &weak_key,
                750,
                31,
            ),
            "signing_public_key_hex must be a canonical lowercase strong Ed25519 public key",
        ),
        (
            "too-fast cadence",
            enabled_overlay(
                "object-lock://sorafs/por-replay-archive/primary",
                17,
                &"81".repeat(32),
                &"82".repeat(32),
                &key,
                defaults::sorafs::storage::por_replay_archive::POLL_INTERVAL_MIN_MS - 1,
                31,
            ),
            "poll_interval_ms is outside the supported production range",
        ),
        (
            "unbounded tick",
            enabled_overlay(
                "object-lock://sorafs/por-replay-archive/primary",
                17,
                &"81".repeat(32),
                &"82".repeat(32),
                &key,
                750,
                defaults::sorafs::storage::por_replay_archive::MAX_RECORDS_PER_TICK_LIMIT + 1,
            ),
            "max_records_per_tick is outside the supported production range",
        ),
    ] {
        let error = parse_overlay(&source).expect_err(label);
        assert!(
            error.contains(expected),
            "{label} produced unexpected diagnostic: {error}"
        );
        if label == "test-marked handle" {
            assert!(
                !error.contains("test-secret"),
                "runtime-provider values must not be echoed"
            );
        }
    }
    for (label, source, expected) in [
        (
            "unbounded successor count",
            enabled_overlay(
                "object-lock://sorafs/por-replay-archive/primary",
                17,
                &"81".repeat(32),
                &"82".repeat(32),
                &key,
                750,
                31,
            )
            .replace(
                "max_successor_receipts = 1024",
                &format!(
                    "max_successor_receipts = {}",
                    defaults::sorafs::storage::por_replay_archive::MAX_SUCCESSOR_RECEIPTS_LIMIT + 1
                ),
            ),
            "max_successor_receipts is outside the supported production range",
        ),
        (
            "unbounded successor bytes",
            enabled_overlay(
                "object-lock://sorafs/por-replay-archive/primary",
                17,
                &"81".repeat(32),
                &"82".repeat(32),
                &key,
                750,
                31,
            )
            .replace(
                "max_successor_proof_bytes = 1048576",
                &format!(
                    "max_successor_proof_bytes = {}",
                    defaults::sorafs::storage::por_replay_archive::MAX_SUCCESSOR_PROOF_BYTES_LIMIT
                        + 1
                ),
            ),
            "max_successor_proof_bytes is outside the supported production range",
        ),
    ] {
        let error = parse_overlay(&source).expect_err(label);
        assert!(
            error.contains(expected),
            "{label} produced unexpected diagnostic: {error}"
        );
    }
}
#[test]
fn disabled_archive_rejects_dormant_identity_and_worker_claims() {
    for (source, expected) in [
        (
            r#"
[sorafs.storage.por_replay_archive]
handle = "object-lock://sorafs/por-replay-archive/primary"
"#,
            "identity fields must be absent when disabled",
        ),
        (
            r"
[sorafs.storage.por_replay_archive]
poll_interval_ms = 900
",
            "worker policy must remain at defaults when disabled",
        ),
    ] {
        let error = parse_overlay(source).expect_err("dormant archive claim must fail");
        assert!(
            error.contains(expected),
            "unexpected dormant archive diagnostic: {error}"
        );
    }
}
#[test]
fn enabled_archive_requires_storage_and_committed_reputation_runtime() {
    let source = format!(
        r#"
[sorafs.storage.por_replay_archive]
enabled = true
handle = "object-lock://sorafs/por-replay-archive/primary"
archive_id_hex = "{}"
revision = 1
policy_digest_hex = "{}"
signing_public_key_hex = "{}"
"#,
        "81".repeat(32),
        "82".repeat(32),
        ed25519_public_key_hex(0x83)
    );
    let error = parse_overlay(&source).expect_err("missing producer dependencies must fail");
    assert!(error.contains("requires sorafs.storage.enabled"));
    assert!(error.contains("requires sorafs.storage.reputation_runtime.enabled"));
}
#[test]
fn archive_config_rejects_secret_fields_without_echoing_values() {
    let source = r#"
[sorafs.storage.por_replay_archive]
private_key = "do-not-echo-this-runtime-secret"
"#;
    let error = parse_overlay(source).expect_err("secret-bearing field must be unknown");
    assert!(error.contains("private_key"));
    assert!(
        !error.contains("do-not-echo-this-runtime-secret"),
        "configuration diagnostics must not echo secret values"
    );
}
