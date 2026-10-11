//! Validate the public `SoraFS` reputation finalized-archive policy.

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
fn ed25519_public_key_hex(seed: u8) -> String {
    let key_pair =
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("test Ed25519 keypair");
    hex::encode(key_pair.public_key().to_bytes().1)
}
fn native_signer_bindings() -> String {
    [
        ("proof_outcome", "proof-outcome", 0x72),
        ("repair", "repair", 0x73),
        ("reserve", "reserve", 0x74),
        ("orderbook", "orderbook", 0x75),
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
handle = "software://sorafs/{handle_role}/reputation-primary"
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
    max_record_bytes: u64,
    max_entries: usize,
    max_total_bytes: u64,
    max_kura_tip_lag_blocks: u64,
) -> String {
    let state_dir = toml_path(&absolute_state_dir());
    let trust_policy_path = toml_path(&absolute_trust_policy_path());
    let publisher_public_key_hex = ed25519_public_key_hex(0x71);
    let native_signers = native_signer_bindings();
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
finalized_query_handle = "ledger.finalized.primary"
journal_checkpoint_provider_handle = "sealed.reputation.journal.primary"
journal_checkpoint_provider_revision = 1
journal_checkpoint_provider_policy_digest_hex = "6060606060606060606060606060606060606060606060606060606060606060"
journal_transaction_submitter_handle = "queue.reputation.journal"
journal_transaction_submitter_revision = 11
journal_transaction_submitter_policy_digest_hex = "6161616161616161616161616161616161616161616161616161616161616161"
threshold_signer_handle = "software://sorafs/reputation/primary"
threshold_signer_revision = 12
threshold_signer_policy_digest_hex = "6262626262626262626262626262626262626262626262626262626262626262"
governance_dag_handle = "governance.dag.publisher"
governance_dag_revision = 13
governance_dag_policy_digest_hex = "6363636363636363636363636363636363636363636363636363636363636363"
governance_publisher_peer_id = "12D3KooWProductionPublisher"
governance_publisher_public_key_hex = "{publisher_public_key_hex}"
finalized_archive_max_record_bytes = {max_record_bytes}
finalized_archive_max_entries = {max_entries}
finalized_archive_max_total_bytes = {max_total_bytes}
finalized_archive_max_kura_tip_lag_blocks = {max_kura_tip_lag_blocks}
{native_signers}
"#
    )
}
#[test]
fn explicit_archive_policy_projects_exact_bounds_and_a_derived_private_root() {
    let actual = parse_overlay(&enabled_overlay(
        8 * 1024 * 1024,
        1_234,
        32 * 1024 * 1024,
        0,
    ))
    .expect("valid explicit finalized archive policy");
    let reputation = actual
        .torii
        .sorafs_storage
        .reputation_runtime
        .as_ref()
        .expect("enabled reputation runtime");
    assert_eq!(reputation.state_dir, absolute_state_dir());
    assert_eq!(
        reputation.finalized_archive_root,
        absolute_state_dir()
            .join(defaults::sorafs::storage::reputation_runtime::FINALIZED_ARCHIVE_DIRECTORY_NAME)
    );
    assert_eq!(
        reputation.finalized_archive_max_record_bytes,
        8 * 1024 * 1024
    );
    assert_eq!(reputation.finalized_archive_max_entries, 1_234);
    assert_eq!(
        reputation.finalized_archive_max_total_bytes,
        32 * 1024 * 1024
    );
    assert_eq!(reputation.finalized_archive_max_kura_tip_lag_blocks, 0);
}
#[test]
fn enabled_archive_policy_rejects_zero_inconsistent_overflowing_and_stale_bounds() {
    let usize_max = u64::try_from(usize::MAX).expect("usize must fit in u64");
    let allocation_overflow_record = usize_max / 4 + 1;
    for (record, entries, total, lag, expected) in [
        (
            0,
            1,
            1,
            2,
            "finalized_archive_max_record_bytes must be nonzero",
        ),
        (
            4,
            0,
            4,
            2,
            "finalized_archive_max_entries must be nonzero",
        ),
        (
            8,
            1,
            4,
            2,
            "finalized_archive_max_total_bytes must cover at least one maximum-sized record",
        ),
        (
            allocation_overflow_record,
            1,
            allocation_overflow_record,
            2,
            "cannot produce a bounded decode allocation budget",
        ),
        (
            1,
            1,
            1,
            defaults::sorafs::storage::reputation_runtime::FINALIZED_ARCHIVE_MAX_KURA_TIP_LAG_BLOCKS_LIMIT
                + 1,
            "finalized_archive_max_kura_tip_lag_blocks must be within",
        ),
    ] {
        let error = parse_overlay(&enabled_overlay(record, entries, total, lag))
            .expect_err("invalid finalized archive bounds must fail closed");
        assert!(
            error.contains(expected),
            "unexpected finalized archive diagnostic: {error}"
        );
    }
}
#[test]
fn disabled_runtime_rejects_nondefault_archive_claims() {
    let source = r"
[sorafs.storage.reputation_runtime]
finalized_archive_max_entries = 999999
";
    let error = parse_overlay(source).expect_err("dormant archive policy must fail closed");
    assert!(
        error.contains("finalized archive policy must remain at defaults when disabled"),
        "unexpected disabled archive diagnostic: {error}"
    );
}
#[test]
fn finalized_archive_root_is_not_a_user_settable_path() {
    let source = r#"
[sorafs.storage.reputation_runtime]
finalized_archive_root = "/run/secrets/forbidden-archive-root"
"#;
    let error = parse_overlay(source).expect_err("archive root must be derived internally");
    assert!(
        error.contains("sorafs.storage.reputation_runtime.finalized_archive_root"),
        "unexpected derived-root diagnostic: {error}"
    );
    assert!(
        !error.contains("/run/secrets/forbidden-archive-root"),
        "unknown-field diagnostics must not echo private path material"
    );
}
fn reserve_transparency_overlay(query_handle: &str) -> String {
    let state_dir = if cfg!(target_os = "windows") {
        r"C:\iroha\sorafs\reserve-transparency".to_owned()
    } else {
        "/var/lib/iroha/sorafs/reserve-transparency".to_owned()
    };
    format!(
        r#"
[sorafs.storage.reserve_transparency_runtime]
enabled = true
state_dir = "{}"
finalized_query_handle = "{query_handle}"
poll_interval_ms = 250
retry_max_interval_ms = 4000
page_items = 32
max_pages_per_tick = 12
checkpoint_max_bytes = 32768
"#,
        state_dir.replace('\\', "\\\\")
    )
}
#[test]
fn reserve_transparency_scanner_reuses_exact_reputation_query_binding() {
    let source = format!(
        "{}{}",
        enabled_overlay(8 * 1024 * 1024, 1_234, 32 * 1024 * 1024, 0),
        reserve_transparency_overlay("ledger.finalized.primary")
    );
    let actual = parse_overlay(&source).expect("valid reserve transparency scanner policy");
    let scanner = actual
        .torii
        .sorafs_storage
        .reserve_transparency_runtime
        .expect("scanner enabled");
    assert_eq!(scanner.finalized_query_handle, "ledger.finalized.primary");
    assert_eq!(scanner.poll_interval, std::time::Duration::from_millis(250));
    assert_eq!(
        scanner.retry_max_interval,
        std::time::Duration::from_secs(4)
    );
    assert_eq!(scanner.page_items, 32);
    assert_eq!(scanner.max_pages_per_tick, 12);
    assert_eq!(scanner.checkpoint_max_bytes.0, 32_768);
}
#[test]
fn reserve_transparency_scanner_rejects_substituted_query_handle() {
    let source = format!(
        "{}{}",
        enabled_overlay(8 * 1024 * 1024, 1_234, 32 * 1024 * 1024, 0),
        reserve_transparency_overlay("ledger.finalized.substituted")
    );
    let error = parse_overlay(&source).expect_err("substituted scanner query must fail closed");
    assert!(
        error.contains("must exactly match reputation_runtime.finalized_query_handle"),
        "unexpected query-binding diagnostic: {error}"
    );
}
#[test]
fn disabled_reserve_transparency_scanner_rejects_nondefault_policy() {
    let error = parse_overlay(
        r"
[sorafs.storage.reserve_transparency_runtime]
checkpoint_max_bytes = 4096
",
    )
    .expect_err("disabled scanner policy must remain inert");
    assert!(
        error.contains("bindings and policy must be absent or default when disabled"),
        "unexpected disabled scanner diagnostic: {error}"
    );
}
