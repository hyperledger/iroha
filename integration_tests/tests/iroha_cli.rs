//! Integration tests of the Iroha Client CLI
use integration_tests::{
    binary_resolver::{
        binary_supports_training_job_commands, cli_binary_name,
        find_existing_binary_path_from_roots, find_existing_cli_binary_path_from_roots,
        iroha_cli_test_build_profile_override, iroha_program,
        iroha_program_reuse_existing_or_resolve, irohad_binary_name,
        matching_irohad_binary_path_from_cli_path, newest_existing_binary_path,
        prepare_iroha_cli_test_environment, should_reuse_existing_cli_binary_for_tests_from_value,
        workspace_root,
    },
    process::{CommandTimeoutExt, TokioCommandTimeoutExt, tokio_output_with_timeout},
    sandbox,
};
use iroha::{
    blocking::Client,
    config::{DEFAULT_TRANSACTION_STATUS_TIMEOUT, DEFAULT_TRANSACTION_TIME_TO_LIVE},
    crypto::{ExposedPrivateKey, Hash, KeyPair},
    data_model::{
        Encode,
        account::AccountId,
        asset::{AssetDefinitionId, AssetId},
        permission::Permission,
        prelude::{FindAssetById, FindAssetDefinitions, Grant, Json},
        soracloud::{
            AgentApartmentManifestV1, SoraContainerManifestV1, SoraServiceManifestV1,
            SoraStateMutabilityV1,
        },
    },
};
use iroha_config_base::toml::WriteExt;
use iroha_data_model::prelude::QueryBuilderExt;
use iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition;
use iroha_model_base::domain::DomainId;
use iroha_test_network::NetworkBuilder;
use iroha_test_samples::{BOB_ID, BOB_KEYPAIR, CARPENTER_ID, CARPENTER_KEYPAIR};
use norito::json::{self, Value};
use reqwest::Url;
use std::{
    num::NonZeroU32,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const SORACLOUD_TEST_CONTROL_PLANE_TIMEOUT_SECS: &str = "60";
const SORACLOUD_TEST_RETENTION_EPOCH: &str = "4102444800";
const SORACLOUD_TEST_SUBPROCESS_TIMEOUT_HEADROOM: Duration = Duration::from_secs(15);
const SORACLOUD_TEST_CONTROL_PLANE_POLL_TIMEOUT: Duration = Duration::from_secs(60);
fn canonical_quantity_literal_from_nanos(nanos: u128) -> String {
    const NANOS_PER_UNIT: u128 = 1_000_000_000;
    let whole = nanos / NANOS_PER_UNIT;
    let fractional = nanos % NANOS_PER_UNIT;
    if fractional == 0 {
        return whole.to_string();
    }
    let mut fractional = format!("{fractional:09}");
    while fractional.ends_with('0') {
        fractional.pop();
    }
    format!("{whole}.{fractional}")
}
#[test]
fn nanos_to_quantity_fixture_spelling_is_canonical() {
    assert_eq!(canonical_quantity_literal_from_nanos(0), "0");
    assert_eq!(canonical_quantity_literal_from_nanos(10_000), "0.00001");
    assert_eq!(canonical_quantity_literal_from_nanos(1_000_000_000), "1");
    assert_eq!(
        canonical_quantity_literal_from_nanos(1_234_567_890),
        "1.23456789"
    );
}
fn program() -> PathBuf {
    iroha_program().unwrap()
}
fn program_reuse_existing_or_build() -> PathBuf {
    iroha_program_reuse_existing_or_resolve().unwrap()
}
fn soracloud_fixture(path: &str) -> PathBuf {
    workspace_root().join(path)
}
fn install_soracloud_test_bundle(
    root: &Path,
    label: &str,
    container: &mut SoraContainerManifestV1,
    service: &mut SoraServiceManifestV1,
) -> eyre::Result<PathBuf> {
    let bundle_path = root.join(format!("{label}.bundle"));
    let bundle = format!("iroha:soracloud:integration:{label}:v1");
    std::fs::write(&bundle_path, bundle.as_bytes())?;
    container.bundle_hash = Hash::new(bundle.as_bytes());
    service.container.manifest_hash = Hash::new(Encode::encode(container));
    Ok(bundle_path)
}
const SORACLOUD_HF_LEASE_ASSET_DEFINITION_LITERAL: &str = "5PeSrQmLNwwKtruJvDZrbrm9RuMw";
fn soracloud_hf_lease_asset_definition() -> AssetDefinitionId {
    AssetDefinitionId::parse_address_literal(SORACLOUD_HF_LEASE_ASSET_DEFINITION_LITERAL)
        .expect("test lease asset definition literal should parse")
}
fn numeric_asset_balance_u128(client: &Client, asset_id: &AssetId) -> eyre::Result<Option<u128>> {
    let asset = match client
        .client()
        .query_single(FindAssetById::new(asset_id.clone()))
    {
        Ok(asset) => asset,
        Err(err) => {
            let message = format!("{err:?}");
            if message.contains("Failed to find asset")
                || message.contains("Find(Asset(")
                || message.contains("Find(Account(")
                || message.contains("QueryExecutionFail::Find")
                || message.contains("QueryExecutionFail::NotFound")
            {
                return Ok(None);
            }
            return Err(eyre::eyre!(
                "failed to query `{asset_id}` while verifying soracloud HF lease setup: {message}"
            ));
        }
    };
    if asset.value().scale() != 0 {
        return Err(eyre::eyre!(
            "expected integer numeric value for `{asset_id}`, got scale={}",
            asset.value().scale()
        ));
    }
    Ok(asset.value().as_numeric().try_mantissa_u128())
}
fn assert_soracloud_hf_lease_asset_ready(
    client: &Client,
    accounts: &[AccountId],
    minimum_amount: u32,
) -> eyre::Result<()> {
    let asset_definition_id = soracloud_hf_lease_asset_definition();
    let asset_definition_exists = client
        .client()
        .query(FindAssetDefinitions::new())
        .execute_all()?
        .into_iter()
        .any(|definition| definition.id == asset_definition_id);
    if !asset_definition_exists {
        return Err(eyre::eyre!(
            "soracloud HF lease asset definition `{asset_definition_id}` is missing from test-network genesis"
        ));
    }
    for account_id in accounts {
        let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
        let observed = numeric_asset_balance_u128(client, &asset_id)?;
        let required = u128::from(minimum_amount);
        if observed.is_none_or(|balance| balance < required) {
            return Err(eyre::eyre!(
                "soracloud HF lease asset `{asset_id}` is below required bootstrap balance {required}; observed {observed:?}"
            ));
        }
    }
    Ok(())
}
const SORACLOUD_LIVE_HF_TEST_REPO_ID: &str = "hf-internal-testing/tiny-random-gpt2";
const SORACLOUD_LIVE_HF_TEST_RESOLVED_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
#[test]
fn find_existing_cli_binary_path_from_roots_returns_first_match() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root_a = temp.path().join("target-a");
    let root_b = temp.path().join("target-b");
    let binary_name = if cfg!(windows) { "iroha.exe" } else { "iroha" };
    let expected = root_b.join("debug").join(binary_name);
    std::fs::create_dir_all(expected.parent().expect("parent dir")).expect("create dirs");
    std::fs::write(&expected, b"binary").expect("create fake binary");
    let profiles = vec!["debug".to_owned(), "release".to_owned()];
    let found = find_existing_cli_binary_path_from_roots(&[root_a, root_b], &profiles);
    assert_eq!(found, Some(expected));
}
#[test]
fn find_existing_cli_binary_path_from_roots_returns_none_when_missing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("target");
    std::fs::create_dir_all(&root).expect("create dirs");
    let profiles = vec!["debug".to_owned(), "release".to_owned()];
    let found = find_existing_cli_binary_path_from_roots(&[root], &profiles);
    assert!(found.is_none());
}
#[test]
fn find_existing_binary_path_from_roots_returns_daemon_match() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("target");
    let expected = root.join("debug").join(irohad_binary_name());
    std::fs::create_dir_all(expected.parent().expect("parent dir")).expect("create dirs");
    std::fs::write(&expected, b"binary").expect("create fake binary");
    let profiles = vec!["debug".to_owned(), "release".to_owned()];
    let found = find_existing_binary_path_from_roots(
        std::slice::from_ref(&root),
        &profiles,
        irohad_binary_name(),
    );
    assert_eq!(found, Some(expected));
}
#[test]
fn find_existing_binary_path_from_roots_prefers_newer_match() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root_a = temp.path().join("target-a");
    let root_b = temp.path().join("target-b");
    let older = root_a.join("debug").join(irohad_binary_name());
    let newer = root_b.join("debug").join(irohad_binary_name());
    std::fs::create_dir_all(older.parent().expect("older parent")).expect("create older dirs");
    std::fs::create_dir_all(newer.parent().expect("newer parent")).expect("create newer dirs");
    std::fs::write(&older, b"older").expect("write older binary");
    std::thread::sleep(Duration::from_secs(1));
    std::fs::write(&newer, b"newer").expect("write newer binary");
    let profiles = vec!["debug".to_owned(), "release".to_owned()];
    let found =
        find_existing_binary_path_from_roots(&[root_a, root_b], &profiles, irohad_binary_name());
    assert_eq!(found, Some(newer));
}
#[test]
fn newest_existing_binary_path_prefers_fresher_daemon_over_cli_sibling() {
    let temp = tempfile::tempdir().expect("tempdir");
    let stale = temp
        .path()
        .join("iroha-test-network/debug")
        .join(irohad_binary_name());
    let fresh = temp.path().join("debug").join(irohad_binary_name());
    std::fs::create_dir_all(stale.parent().expect("stale parent")).expect("create stale dirs");
    std::fs::create_dir_all(fresh.parent().expect("fresh parent")).expect("create fresh dirs");
    std::fs::write(&stale, b"stale").expect("write stale daemon");
    std::thread::sleep(Duration::from_secs(1));
    std::fs::write(&fresh, b"fresh").expect("write fresh daemon");
    let selected = newest_existing_binary_path([Some(stale), Some(fresh.clone())]);
    assert_eq!(selected, Some(fresh));
}
#[test]
fn matching_irohad_binary_path_from_cli_path_uses_sibling_binary() {
    let temp = tempfile::tempdir().expect("tempdir");
    let profile_dir = temp.path().join("debug");
    std::fs::create_dir_all(&profile_dir).expect("create dirs");
    let cli = profile_dir.join(cli_binary_name());
    let daemon = profile_dir.join(irohad_binary_name());
    std::fs::write(&cli, b"cli").expect("write cli");
    std::fs::write(&daemon, b"daemon").expect("write daemon");
    let found = matching_irohad_binary_path_from_cli_path(&cli);
    assert_eq!(found, Some(daemon));
}
#[test]
fn binary_supports_training_job_commands_rejects_missing_binary() {
    let missing = PathBuf::from("/definitely/missing/iroha");
    assert!(!binary_supports_training_job_commands(&missing));
}
#[cfg(unix)]
#[test]
fn binary_supports_training_job_commands_rejects_help_without_subcommand() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().expect("tempdir");
    let script = temp.path().join("fake_iroha.sh");
    std::fs::write(&script, "#!/bin/sh\necho 'soracloud help output'\n").expect("write script");
    let mut perms = std::fs::metadata(&script).expect("metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&script, perms).expect("set permissions");
    assert!(!binary_supports_training_job_commands(&script));
}
#[cfg(unix)]
#[test]
fn binary_supports_training_job_commands_accepts_help_with_subcommand() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().expect("tempdir");
    let script = temp.path().join("fake_iroha.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\necho 'Commands:\\n  training-job-start\\n  artifact-register\\n  weight-register'\n",
    )
    .expect("write script");
    let mut perms = std::fs::metadata(&script).expect("metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&script, perms).expect("set permissions");
    assert!(binary_supports_training_job_commands(&script));
}
#[test]
fn should_reuse_existing_cli_binary_for_tests_defaults_to_false() {
    assert!(!should_reuse_existing_cli_binary_for_tests_from_value(None));
    assert!(!should_reuse_existing_cli_binary_for_tests_from_value(
        Some("0")
    ));
    assert!(!should_reuse_existing_cli_binary_for_tests_from_value(
        Some("false")
    ));
}
#[test]
fn should_reuse_existing_cli_binary_for_tests_accepts_truthy_values() {
    assert!(should_reuse_existing_cli_binary_for_tests_from_value(Some(
        "true"
    )));
    assert!(should_reuse_existing_cli_binary_for_tests_from_value(Some(
        "TRUE"
    )));
    assert!(should_reuse_existing_cli_binary_for_tests_from_value(Some(
        "1"
    )));
}
#[test]
fn iroha_cli_test_build_profile_override_defaults_to_debug_when_unset_or_blank() {
    assert_eq!(iroha_cli_test_build_profile_override(None), Some("debug"));
    assert_eq!(
        iroha_cli_test_build_profile_override(Some("")),
        Some("debug")
    );
    assert_eq!(
        iroha_cli_test_build_profile_override(Some("   ")),
        Some("debug")
    );
}
#[test]
fn iroha_cli_test_build_profile_override_preserves_existing_profile() {
    assert_eq!(iroha_cli_test_build_profile_override(Some("release")), None);
    assert_eq!(iroha_cli_test_build_profile_override(Some("debug")), None);
}
fn local_program_config() -> ProgramConfig {
    let key = KeyPair::try_random().expect("generate checked local CLI config keypair");
    let domain_id: DomainId =
        DomainId::try_new("wonderland", "universal").expect("literal domain should parse");
    ProgramConfig {
        torii_url: Url::parse("http://127.0.0.1:8080").expect("literal URL should parse"),
        account_domain: domain_id,
        key,
        status_timeout: DEFAULT_TRANSACTION_STATUS_TIMEOUT,
        ttl: DEFAULT_TRANSACTION_TIME_TO_LIVE,
    }
}
#[test]
fn local_program_config_uses_checked_key_generation() {
    let config = local_program_config();
    assert_eq!(config.torii_url.as_str(), "http://127.0.0.1:8080/");
    assert_eq!(
        config.account_domain,
        DomainId::try_new("wonderland", "universal").expect("literal domain should parse")
    );
    assert_eq!(config.status_timeout, DEFAULT_TRANSACTION_STATUS_TIMEOUT);
    assert_eq!(config.ttl, DEFAULT_TRANSACTION_TIME_TO_LIVE);
}
fn program_config_for_account(
    client: &Client,
    account_domain: &str,
    key: &KeyPair,
) -> ProgramConfig {
    let account_domain = DomainId::try_new(account_domain, "universal")
        .expect("account domain literal should parse");
    let ttl = client
        .client()
        .transaction_ttl()
        .unwrap_or(DEFAULT_TRANSACTION_TIME_TO_LIVE);
    ProgramConfig {
        torii_url: client.client().endpoint().clone(),
        account_domain,
        key: key.clone(),
        status_timeout: client.client().transaction_status_timeout(),
        ttl,
    }
}
struct ProgramConfig {
    torii_url: Url,
    account_domain: DomainId,
    key: KeyPair,
    status_timeout: Duration,
    ttl: Duration,
}
impl From<&Client> for ProgramConfig {
    fn from(value: &Client) -> Self {
        program_config_for_account(value, "wonderland", value.client().key_pair())
    }
}
impl ProgramConfig {
    fn envs(&self) -> impl IntoIterator<Item = (&str, String)> {
        [
            ("CHAIN", iroha_test_network::chain_id().to_string()),
            ("TORII_URL", self.torii_url.to_string()),
            ("ACCOUNT_DOMAIN", self.account_domain.to_string()),
            ("ACCOUNT_PUBLIC_KEY", self.key.public_key().to_string()),
            (
                "ACCOUNT_PRIVATE_KEY",
                ExposedPrivateKey(self.key.private_key().clone()).to_string(),
            ),
            (
                "TRANSACTION_STATUS_TIMEOUT_MS",
                self.status_timeout.as_millis().to_string(),
            ),
            (
                "TRANSACTION_TIME_TO_LIVE_MS",
                self.ttl.as_millis().to_string(),
            ),
        ]
    }
    fn toml(&self) -> toml::Table {
        toml::Table::new()
            .write("chain", iroha_test_network::chain_id().to_string())
            .write("torii_url", self.torii_url.to_string())
            .write(["account", "domain"], self.account_domain.to_string())
            .write(
                ["account", "private_key"],
                ExposedPrivateKey(self.key.private_key().clone()).to_string(),
            )
            .write(["account", "public_key"], self.key.public_key().to_string())
            .write(
                ["transaction", "status_timeout_ms"],
                i64::try_from(self.status_timeout.as_millis()).unwrap_or_else(|_| {
                    i64::try_from(DEFAULT_TRANSACTION_STATUS_TIMEOUT.as_millis())
                        .unwrap_or(i64::MAX)
                }),
            )
            .write(
                ["transaction", "time_to_live_ms"],
                i64::try_from(self.ttl.as_millis()).unwrap_or_else(|_| {
                    i64::try_from(DEFAULT_TRANSACTION_TIME_TO_LIVE.as_millis()).unwrap_or(i64::MAX)
                }),
            )
    }
}
async fn run_soracloud_command(
    cwd: &Path,
    config: &ProgramConfig,
    args: &[&str],
) -> eyre::Result<std::process::Output> {
    let effective_args = soracloud_command_args(args);
    let timeout = soracloud_subprocess_timeout(args);
    let mut command = tokio::process::Command::new(program());
    command
        .current_dir(cwd)
        .arg("soracloud")
        .args(&effective_args)
        .envs(config.envs());
    Ok(tokio_output_with_timeout(&mut command, timeout).await?)
}

struct SoracloudCli<'a> {
    cwd: &'a Path,
    config: &'a ProgramConfig,
}

impl<'a> SoracloudCli<'a> {
    const fn new(cwd: &'a Path, config: &'a ProgramConfig) -> Self {
        Self { cwd, config }
    }

    fn command(&self) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(program());
        command.current_dir(self.cwd).arg("soracloud");
        command
    }

    async fn bounded_output(
        &self,
        mut command: tokio::process::Command,
    ) -> eyre::Result<std::process::Output> {
        command.envs(self.config.envs());
        Ok(command.bounded_output().await?)
    }
}

struct SoracloudSuccessCase {
    failure_context: &'static str,
}

impl SoracloudSuccessCase {
    const fn new(failure_context: &'static str) -> Self {
        Self { failure_context }
    }
}

fn assert_soracloud_success(output: &std::process::Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed with status {} and stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

macro_rules! run_bounded_soracloud_command {
    ($cli:expr; $($arg:expr),+ $(,)?) => {{
        let mut command = $cli.command();
        $(command.arg($arg);)+
        $cli.bounded_output(command).await?
    }};
}

macro_rules! run_bounded_soracloud_success {
    ($cli:expr, $case:expr; $($arg:expr),+ $(,)?) => {{
        let case = $case;
        let output = run_bounded_soracloud_command!($cli; $($arg),+);
        assert_soracloud_success(&output, case.failure_context);
        output
    }};
}

async fn wait_for_soracloud_json_command(
    cwd: &Path,
    config: &ProgramConfig,
    args: &[&str],
    timeout: Duration,
    predicate: impl Fn(&Value) -> bool,
) -> eyre::Result<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        let output = run_soracloud_command(cwd, config, args).await?;
        let detail = if output.status.success() {
            match json::from_slice::<Value>(&output.stdout) {
                Ok(payload) => {
                    if predicate(&payload) {
                        return Ok(payload);
                    }
                    json::to_string_pretty(&payload).unwrap_or_else(|_| format!("{payload:?}"))
                }
                Err(err) => {
                    format!("failed to decode Soracloud JSON payload: {err}")
                }
            }
        } else {
            format!(
                "command `iroha soracloud {}` exited with {} and stderr: {}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
        };
        if Instant::now() >= deadline {
            return Err(eyre::eyre!(
                "timed out waiting for soracloud command convergence after {:?}; last detail: {}",
                timeout,
                detail
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
async fn wait_for_soracloud_status_payload(
    cwd: &Path,
    config: &ProgramConfig,
    torii_url: &str,
    timeout: Duration,
    predicate: impl Fn(&Value) -> bool,
) -> eyre::Result<Value> {
    wait_for_soracloud_json_command(
        cwd,
        config,
        &["status", "--torii-url", torii_url],
        timeout,
        predicate,
    )
    .await
}
async fn wait_for_soracloud_hf_status_payload(
    cwd: &Path,
    config: &ProgramConfig,
    repo_id: &str,
    lease_term_ms: &str,
    account_id: &str,
    torii_url: &str,
    timeout: Duration,
    predicate: impl Fn(&Value) -> bool,
) -> eyre::Result<Value> {
    wait_for_soracloud_json_command(
        cwd,
        config,
        &[
            "hf-status",
            "--repo-id",
            repo_id,
            "--lease-term-ms",
            lease_term_ms,
            "--account-id",
            account_id,
            "--torii-url",
            torii_url,
        ],
        timeout,
        predicate,
    )
    .await
}
fn soracloud_command_args(args: &[&str]) -> Vec<String> {
    let mut effective_args = namespaced_soracloud_command_args(args);
    if effective_args.first().is_some_and(|group| group == "hf") {
        if !args.contains(&"--revision") {
            effective_args.push("--revision".to_owned());
            effective_args.push(SORACLOUD_LIVE_HF_TEST_RESOLVED_REVISION.to_owned());
        }
        if !args.contains(&"--storage-class") {
            effective_args.push("--storage-class".to_owned());
            effective_args.push("warm".to_owned());
        }
    }
    if !args.contains(&"--timeout-secs") {
        effective_args.push("--timeout-secs".to_owned());
        effective_args.push(SORACLOUD_TEST_CONTROL_PLANE_TIMEOUT_SECS.to_owned());
    }
    effective_args
}
fn soracloud_subprocess_timeout(args: &[&str]) -> Duration {
    let control_plane_timeout_secs = args
        .windows(2)
        .find_map(|window| {
            (window[0] == "--timeout-secs")
                .then(|| window[1].parse::<u64>().ok())
                .flatten()
        })
        .unwrap_or_else(|| {
            SORACLOUD_TEST_CONTROL_PLANE_TIMEOUT_SECS
                .parse::<u64>()
                .expect("default Soracloud test timeout is a valid integer")
        });
    Duration::from_secs(control_plane_timeout_secs)
        .saturating_add(SORACLOUD_TEST_SUBPROCESS_TIMEOUT_HEADROOM)
}
fn namespaced_soracloud_command_args(args: &[&str]) -> Vec<String> {
    let Some((command, tail)) = args.split_first() else {
        return Vec::new();
    };
    let namespace = match *command {
        "init" | "plan" | "dev" | "build" | "sync-manifests" | "deploy" | "upgrade" | "status"
        | "config-set" | "config-delete" | "config-status" | "secret-set" | "secret-delete"
        | "secret-status" | "rollback" | "rollout" => Some(("service", *command)),
        "training-job-start"
        | "training-job-checkpoint"
        | "training-job-retry"
        | "training-job-status" => Some(("model", *command)),
        "model-artifact-register" => Some(("model", "artifact-register")),
        "model-artifact-status" => Some(("model", "artifact-status")),
        "model-weight-register" => Some(("model", "weight-register")),
        "model-weight-promote" => Some(("model", "weight-promote")),
        "model-weight-rollback" => Some(("model", "weight-rollback")),
        "model-weight-status" => Some(("model", "weight-status")),
        "model-upload-register" => Some(("model", "upload-register")),
        "model-upload-status" => Some(("model", "upload-status")),
        "hf-join" => Some(("hf", "join")),
        "hf-status" => Some(("hf", "status")),
        "hf-lease-leave" => Some(("hf", "lease-leave")),
        "hf-lease-renew" => Some(("hf", "lease-renew")),
        "agent-deploy" => Some(("agent", "deploy")),
        "agent-lease-renew" => Some(("agent", "lease-renew")),
        "agent-restart" => Some(("agent", "restart")),
        "agent-status" => Some(("agent", "status")),
        "agent-wallet-spend" => Some(("agent", "wallet-spend")),
        "agent-wallet-approve" => Some(("agent", "wallet-approve")),
        "agent-policy-revoke" => Some(("agent", "policy-revoke")),
        "agent-message-send" => Some(("agent", "message-send")),
        "agent-message-ack" => Some(("agent", "message-ack")),
        "agent-mailbox-status" => Some(("agent", "mailbox-status")),
        "agent-artifact-allow" => Some(("agent", "artifact-allow")),
        "agent-autonomy-status" => Some(("agent", "autonomy-status")),
        _ => None,
    };
    match namespace {
        Some((group, command)) => std::iter::once(group)
            .chain(std::iter::once(command))
            .chain(tail.iter().copied())
            .map(ToOwned::to_owned)
            .collect(),
        None => args.iter().map(|arg| (*arg).to_owned()).collect(),
    }
}
#[test]
fn soracloud_command_args_append_timeout_once() {
    assert_eq!(
        soracloud_command_args(&["hf-join", "--repo-id", "openai/gpt-oss"]),
        vec![
            "hf".to_owned(),
            "join".to_owned(),
            "--repo-id".to_owned(),
            "openai/gpt-oss".to_owned(),
            "--revision".to_owned(),
            SORACLOUD_LIVE_HF_TEST_RESOLVED_REVISION.to_owned(),
            "--storage-class".to_owned(),
            "warm".to_owned(),
            "--timeout-secs".to_owned(),
            SORACLOUD_TEST_CONTROL_PLANE_TIMEOUT_SECS.to_owned(),
        ]
    );
    assert_eq!(
        soracloud_command_args(&[
            "hf-status",
            "--repo-id",
            "openai/gpt-oss",
            "--timeout-secs",
            "15",
        ]),
        vec![
            "hf".to_owned(),
            "status".to_owned(),
            "--repo-id".to_owned(),
            "openai/gpt-oss".to_owned(),
            "--timeout-secs".to_owned(),
            "15".to_owned(),
            "--revision".to_owned(),
            SORACLOUD_LIVE_HF_TEST_RESOLVED_REVISION.to_owned(),
            "--storage-class".to_owned(),
            "warm".to_owned(),
        ]
    );
    assert_eq!(
        soracloud_subprocess_timeout(&["hf-join", "--repo-id", "openai/gpt-oss"]),
        Duration::from_secs(75)
    );
    assert_eq!(
        soracloud_subprocess_timeout(&[
            "hf-status",
            "--repo-id",
            "openai/gpt-oss",
            "--timeout-secs",
            "15",
        ]),
        Duration::from_secs(30)
    );
}
fn assert_requires_torii_url(output: &std::process::Output) {
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded with stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--torii-url is required for Soracloud live control-plane access"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn tagged_enum_label<'a>(value: &'a Value, tag: &str) -> Option<&'a str> {
    value.as_object()?.get(tag)?.as_str()
}
#[tokio::test]
async fn can_upgrade_executor() -> eyre::Result<()> {
    prepare_iroha_cli_test_environment();
    let sample_path = workspace_root().join("defaults/executor.to");
    // Assuming Alice already has the CanUpgradeExecutor permission
    let builder = NetworkBuilder::new()
        .with_ivm_fuel(iroha_test_network::IvmFuelConfig::Auto)
        .with_min_peers(4);
    let Some(network) =
        sandbox::start_network_async_or_skip(builder, stringify!(can_upgrade_executor)).await?
    else {
        return Ok(());
    };
    // Use an explicit client.toml to avoid any env resolution pitfalls
    let config = ProgramConfig::from(&network.client());
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let exit_status = tokio::process::Command::new(program())
        .current_dir(dir.path())
        .arg("ops")
        .arg("executor")
        .arg("upgrade")
        .arg("--path")
        .arg(sample_path)
        // Also pass envs to exercise the CLI's env handling and avoid dead-code.
        .envs(config.envs())
        .bounded_status()
        .await?;
    assert!(exit_status.success());
    Ok(())
}
#[tokio::test]
async fn reads_client_toml_by_default() -> eyre::Result<()> {
    prepare_iroha_cli_test_environment();
    let Some(network) = sandbox::start_network_async_or_skip(
        NetworkBuilder::new(),
        stringify!(reads_client_toml_by_default),
    )
    .await?
    else {
        return Ok(());
    };
    let config = ProgramConfig::from(&network.client());
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let exit_status = tokio::process::Command::new(program())
        .current_dir(dir.path())
        .arg("ledger")
        .arg("domain")
        .arg("list")
        .bounded_status()
        .await?;
    assert!(exit_status.success());
    Ok(())
}
#[test]
fn tx_ivm_rejects_missing_gas_limit_without_hanging() -> eyre::Result<()> {
    prepare_iroha_cli_test_environment();
    let dir = tempfile::tempdir()?;
    let config = local_program_config();
    std::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )?;
    let program_path = dir.path().join("hello.to");
    std::fs::write(&program_path, b"fake-ivm-bytecode")?;
    let binary = program_reuse_existing_or_build();
    let started_at = Instant::now();
    let output = std::process::Command::new(binary)
        .current_dir(dir.path())
        .arg("tx")
        .arg("ivm")
        .arg("--fee-payer")
        .arg("authority")
        .arg("--path")
        .arg(&program_path)
        .bounded_output()?;
    let elapsed = started_at.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "iroha tx ivm should fail quickly instead of hanging; elapsed {elapsed:?}"
    );
    assert!(
        !output.status.success(),
        "CLI unexpectedly succeeded with stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("IVM transactions require a signature-bound gas limit")
            && stderr.contains("--gas-limit <u64>"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !stderr.contains("Connection refused"),
        "CLI should reject a missing typed gas limit before any network call: {stderr}"
    );
    Ok(())
}
#[test]
fn tx_ivm_accepts_gas_limit_flag_and_skips_local_missing_intent_error() -> eyre::Result<()> {
    prepare_iroha_cli_test_environment();
    let dir = tempfile::tempdir()?;
    let config = local_program_config();
    std::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )?;
    let program_path = dir.path().join("hello.to");
    std::fs::write(&program_path, b"fake-ivm-bytecode")?;
    let binary = program_reuse_existing_or_build();
    let started_at = Instant::now();
    let output = std::process::Command::new(binary)
        .current_dir(dir.path())
        .arg("tx")
        .arg("ivm")
        .arg("--fee-payer")
        .arg("authority")
        .arg("--path")
        .arg(&program_path)
        .arg("--gas-limit")
        .arg("42")
        .bounded_output()?;
    let elapsed = started_at.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "iroha tx ivm --gas-limit should complete quickly; elapsed {elapsed:?}"
    );
    assert!(
        !output.status.success(),
        "CLI unexpectedly succeeded with stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("require a signature-bound gas limit"),
        "CLI should accept --gas-limit and construct the typed fee intent: {stderr}"
    );
    assert!(
        stderr.contains("Failed to submit an IVM transaction"),
        "unexpected stderr: {stderr}"
    );
    Ok(())
}
// Add more CLI tests here!
#[tokio::test]
async fn soracloud_status_uses_live_torii_control_plane() -> eyre::Result<()> {
    prepare_iroha_cli_test_environment();
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        .with_npos_consensus()
        .with_config_layer(|layer| {
            // The test-network genesis explicitly authors Ed25519, Secp256k1 and BLS.
            layer.write("telemetry_profile", "full");
        });
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(soracloud_status_uses_live_torii_control_plane),
    )
    .await?
    else {
        return Ok(());
    };
    let config = ProgramConfig::from(&network.client());
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let cli = SoracloudCli::new(dir.path(), &config);
    let output = run_bounded_soracloud_command!(
        cli;
        "service", "status",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    assert!(
        output.status.success(),
        "CLI exited with status {} and stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value =
        json::from_slice(&output.stdout).expect("CLI should emit JSON soracloud status payload");
    assert_eq!(
        payload.get("source").and_then(Value::as_str),
        Some("torii_control_plane")
    );
    let network_status = payload
        .get("network_status")
        .and_then(Value::as_object)
        .expect("network_status object present");
    assert_eq!(
        network_status.get("schema_version").and_then(Value::as_u64),
        Some(1)
    );
    assert!(network_status.contains_key("service_health"));
    assert!(network_status.contains_key("routing"));
    assert!(network_status.contains_key("resource_pressure"));
    assert!(network_status.contains_key("failed_admissions"));
    Ok(())
}
#[tokio::test]
async fn soracloud_mutations_use_live_torii_control_plane() -> eyre::Result<()> {
    prepare_iroha_cli_test_environment();
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        .with_config_layer(|layer| {
            // The test-network genesis explicitly authors Ed25519, Secp256k1 and BLS.
            layer.write("telemetry_profile", "full");
        });
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(soracloud_mutations_use_live_torii_control_plane),
    )
    .await?
    else {
        return Ok(());
    };
    let config = ProgramConfig::from(&network.client());
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let container_fixture = soracloud_fixture("fixtures/soracloud/sora_container_manifest_v1.json");
    let service_fixture = soracloud_fixture("fixtures/soracloud/sora_service_manifest_v1.json");
    let mut container: SoraContainerManifestV1 =
        norito::json::from_slice(&std::fs::read(&container_fixture)?)?;
    let mut service_v1: SoraServiceManifestV1 =
        norito::json::from_slice(&std::fs::read(&service_fixture)?)?;
    service_v1.service_version = "1.0.0".to_string();
    let bundle_path = install_soracloud_test_bundle(
        dir.path(),
        "live-control-plane",
        &mut container,
        &mut service_v1,
    )?;
    let mut service_v2 = service_v1.clone();
    service_v2.service_version = "1.1.0".to_string();
    let container_path = dir.path().join("container_manifest.json");
    let service_v1_path = dir.path().join("service_v1.json");
    let service_v2_path = dir.path().join("service_v2.json");
    tokio::fs::write(
        &container_path,
        norito::json::to_vec_pretty(&container).expect("encode container"),
    )
    .await?;
    tokio::fs::write(
        &service_v1_path,
        norito::json::to_vec_pretty(&service_v1).expect("encode service v1"),
    )
    .await?;
    tokio::fs::write(
        &service_v2_path,
        norito::json::to_vec_pretty(&service_v2).expect("encode service v2"),
    )
    .await?;
    let torii_url = network.client().client().endpoint().to_string();
    let deploy = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "deploy",
            "--container",
            container_path.to_string_lossy().as_ref(),
            "--service",
            service_v1_path.to_string_lossy().as_ref(),
            "--bundle-file",
            bundle_path.to_string_lossy().as_ref(),
            "--sorafs-retention-epoch",
            SORACLOUD_TEST_RETENTION_EPOCH,
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&deploy, "deploy");
    let join_payload: Value =
        json::from_slice(&deploy.stdout).expect("CLI should emit deploy JSON payload");
    assert_eq!(
        join_payload.get("current_version").and_then(Value::as_str),
        Some("1.0.0")
    );
    let upgrade = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "upgrade",
            "--container",
            container_path.to_string_lossy().as_ref(),
            "--service",
            service_v2_path.to_string_lossy().as_ref(),
            "--bundle-file",
            bundle_path.to_string_lossy().as_ref(),
            "--sorafs-retention-epoch",
            SORACLOUD_TEST_RETENTION_EPOCH,
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&upgrade, "upgrade");
    let upgrade_payload: Value =
        json::from_slice(&upgrade.stdout).expect("CLI should emit upgrade JSON payload");
    assert_eq!(
        upgrade_payload
            .get("current_version")
            .and_then(Value::as_str),
        Some("1.1.0")
    );
    let rollout_handle = upgrade_payload
        .get("rollout_handle")
        .and_then(Value::as_str)
        .expect("upgrade should return rollout_handle");
    assert_eq!(
        upgrade_payload
            .get("rollout_stage")
            .and_then(Value::as_object)
            .and_then(|stage| stage.get("stage"))
            .and_then(Value::as_str),
        Some("Canary")
    );
    let rollout_governance_hash = Hash::new(b"cli-live-rollout-promote").to_string();
    let rollout = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "rollout",
            "--service-name",
            service_v1.service_name.to_string().as_ref(),
            "--rollout-handle",
            rollout_handle,
            "--promote-to-percent",
            "100",
            "--governance-tx-hash",
            rollout_governance_hash.as_str(),
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&rollout, "rollout");
    let rollout_payload: Value =
        json::from_slice(&rollout.stdout).expect("CLI should emit rollout JSON payload");
    assert_eq!(
        rollout_payload
            .get("current_version")
            .and_then(Value::as_str),
        Some("1.1.0")
    );
    assert_eq!(
        rollout_payload
            .get("stage")
            .and_then(Value::as_object)
            .and_then(|stage| stage.get("stage"))
            .and_then(Value::as_str),
        Some("Promoted")
    );
    assert_eq!(
        rollout_payload
            .get("traffic_percent")
            .and_then(Value::as_u64),
        Some(100)
    );
    let rollback = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "rollback",
            "--service-name",
            service_v1.service_name.to_string().as_ref(),
            "--target-version",
            "1.0.0",
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&rollback, "rollback");
    let rollback_payload: Value =
        json::from_slice(&rollback.stdout).expect("CLI should emit rollback JSON payload");
    assert_eq!(
        rollback_payload
            .get("current_version")
            .and_then(Value::as_str),
        Some("1.0.0")
    );
    let status_payload = wait_for_soracloud_status_payload(
        dir.path(),
        &config,
        torii_url.as_str(),
        SORACLOUD_TEST_CONTROL_PLANE_POLL_TIMEOUT,
        |payload| {
            let Some(network_status) = payload.get("network_status").and_then(Value::as_object)
            else {
                return false;
            };
            let Some(control_plane) = network_status
                .get("control_plane")
                .and_then(Value::as_object)
            else {
                return false;
            };
            if control_plane.get("service_count").and_then(Value::as_u64) != Some(1) {
                return false;
            }
            if control_plane
                .get("audit_event_count")
                .and_then(Value::as_u64)
                != Some(4)
            {
                return false;
            }
            let Some(services) = control_plane.get("services").and_then(Value::as_array) else {
                return false;
            };
            services.len() == 1
                && services[0].get("current_version").and_then(Value::as_str) == Some("1.0.0")
        },
    )
    .await?;
    let network_status = status_payload
        .get("network_status")
        .and_then(Value::as_object)
        .expect("network_status object");
    let control_plane = network_status
        .get("control_plane")
        .and_then(Value::as_object)
        .expect("control_plane object");
    assert_eq!(
        control_plane.get("service_count").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        control_plane
            .get("audit_event_count")
            .and_then(Value::as_u64),
        Some(4)
    );
    let services = control_plane
        .get("services")
        .and_then(Value::as_array)
        .expect("services array");
    assert_eq!(services.len(), 1);
    assert_eq!(
        services[0].get("current_version").and_then(Value::as_str),
        Some("1.0.0")
    );
    Ok(())
}
#[tokio::test]
async fn soracloud_scr_host_admission_rejects_invalid_manifests_live_torii_control_plane()
-> eyre::Result<()> {
    prepare_iroha_cli_test_environment();
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        .with_config_layer(|layer| {
            // The test-network genesis explicitly authors Ed25519, Secp256k1 and BLS.
            layer.write("telemetry_profile", "full");
        });
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(soracloud_scr_host_admission_rejects_invalid_manifests_live_torii_control_plane),
    )
    .await?
    else {
        return Ok(());
    };
    let config = ProgramConfig::from(&network.client());
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let container_fixture = soracloud_fixture("fixtures/soracloud/sora_container_manifest_v1.json");
    let service_fixture = soracloud_fixture("fixtures/soracloud/sora_service_manifest_v1.json");
    let mut container: SoraContainerManifestV1 =
        norito::json::from_slice(&std::fs::read(&container_fixture)?)?;
    let mut service: SoraServiceManifestV1 =
        norito::json::from_slice(&std::fs::read(&service_fixture)?)?;
    service.service_version = "1.0.0".to_string();
    let bundle_path = install_soracloud_test_bundle(
        dir.path(),
        "admission-rejection",
        &mut container,
        &mut service,
    )?;
    let mut over_cap_container = container.clone();
    over_cap_container.resources.cpu_millis = NonZeroU32::new(64_001).expect("non-zero cpu");
    let mut over_cap_service = service.clone();
    over_cap_service.container.manifest_hash = Hash::new(Encode::encode(&over_cap_container));
    let over_cap_container_path = dir.path().join("container_over_cap.json");
    let over_cap_service_path = dir.path().join("service_over_cap.json");
    tokio::fs::write(
        &over_cap_container_path,
        norito::json::to_vec_pretty(&over_cap_container).expect("encode over-cap container"),
    )
    .await?;
    tokio::fs::write(
        &over_cap_service_path,
        norito::json::to_vec_pretty(&over_cap_service).expect("encode over-cap service"),
    )
    .await?;
    let cli = SoracloudCli::new(dir.path(), &config);
    let over_cap_deploy = run_bounded_soracloud_command!(
        cli;
        "service", "deploy",
        "--container", over_cap_container_path.to_string_lossy().into_owned(),
        "--service", over_cap_service_path.to_string_lossy().into_owned(),
        "--bundle-file", bundle_path.to_string_lossy().into_owned(),
        "--sorafs-retention-epoch", SORACLOUD_TEST_RETENTION_EPOCH,
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    assert!(
        !over_cap_deploy.status.success(),
        "deploy with over-cap cpu should fail, stdout: {}, stderr: {}",
        String::from_utf8_lossy(&over_cap_deploy.stdout),
        String::from_utf8_lossy(&over_cap_deploy.stderr)
    );
    assert!(
        String::from_utf8_lossy(&over_cap_deploy.stderr).contains("returned 400"),
        "{}",
        String::from_utf8_lossy(&over_cap_deploy.stderr)
    );
    assert!(
        String::from_utf8_lossy(&over_cap_deploy.stderr)
            .contains("resources.cpu_millis exceeds SCR cap"),
        "{}",
        String::from_utf8_lossy(&over_cap_deploy.stderr)
    );
    let mut no_write_container = container.clone();
    no_write_container.capabilities.allow_state_writes = false;
    assert!(
        service
            .state_bindings
            .iter()
            .any(|binding| binding.mutability != SoraStateMutabilityV1::ReadOnly),
        "fixture should include at least one non-readonly state binding"
    );
    let no_write_container_hash = Hash::new(Encode::encode(&no_write_container));
    let no_write_container_path = dir.path().join("container_no_write.json");
    let no_write_service_path = dir.path().join("service_no_write.json");
    tokio::fs::write(
        &no_write_container_path,
        norito::json::to_vec_pretty(&no_write_container).expect("encode no-write container"),
    )
    .await?;
    let mut no_write_service = service.clone();
    no_write_service.container.manifest_hash = no_write_container_hash;
    tokio::fs::write(
        &no_write_service_path,
        norito::json::to_vec_pretty(&no_write_service).expect("encode no-write service"),
    )
    .await?;
    let no_write_deploy = run_bounded_soracloud_command!(
        cli;
        "service", "deploy",
        "--container", no_write_container_path.to_string_lossy().into_owned(),
        "--service", no_write_service_path.to_string_lossy().into_owned(),
        "--bundle-file", bundle_path.to_string_lossy().into_owned(),
        "--sorafs-retention-epoch", SORACLOUD_TEST_RETENTION_EPOCH,
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    assert!(
        !no_write_deploy.status.success(),
        "deploy with allow_state_writes=false should fail, stdout: {}, stderr: {}",
        String::from_utf8_lossy(&no_write_deploy.stdout),
        String::from_utf8_lossy(&no_write_deploy.stderr)
    );
    let no_write_stderr = String::from_utf8_lossy(&no_write_deploy.stderr);
    assert!(
        no_write_stderr.contains("returned 400") || no_write_stderr.contains("\"command\""),
        "{}",
        no_write_stderr
    );
    assert!(
        no_write_stderr.contains("bundle field")
            && no_write_stderr.contains("allow_state_writes")
            && no_write_stderr.contains("is invalid"),
        "{}",
        no_write_stderr
    );
    assert!(
        no_write_stderr.contains("binding `session_store` requires mutable writes (`ReadWrite`)"),
        "{}",
        no_write_stderr
    );
    Ok(())
}
#[tokio::test]
async fn soracloud_training_and_model_weight_lifecycle_use_live_torii_control_plane()
-> eyre::Result<()> {
    prepare_iroha_cli_test_environment();
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        .with_npos_consensus()
        .with_config_layer(|layer| {
            // The test-network genesis explicitly authors Ed25519, Secp256k1 and BLS.
            layer.write("telemetry_profile", "full");
        });
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(soracloud_training_and_model_weight_lifecycle_use_live_torii_control_plane),
    )
    .await?
    else {
        return Ok(());
    };
    let config = ProgramConfig::from(&network.client());
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let container_fixture = soracloud_fixture("fixtures/soracloud/sora_container_manifest_v1.json");
    let service_fixture = soracloud_fixture("fixtures/soracloud/sora_service_manifest_v1.json");
    let mut container: SoraContainerManifestV1 =
        norito::json::from_slice(&std::fs::read(&container_fixture)?)?;
    let mut service: SoraServiceManifestV1 =
        norito::json::from_slice(&std::fs::read(&service_fixture)?)?;
    container.capabilities.allow_model_training = true;
    service.service_version = "2.0.0".to_string();
    let bundle_path = install_soracloud_test_bundle(
        dir.path(),
        "training-lifecycle",
        &mut container,
        &mut service,
    )?;
    let container_path = dir.path().join("container_training.json");
    let service_path = dir.path().join("service_training.json");
    tokio::fs::write(
        &container_path,
        norito::json::to_vec_pretty(&container).expect("encode container"),
    )
    .await?;
    tokio::fs::write(
        &service_path,
        norito::json::to_vec_pretty(&service).expect("encode service"),
    )
    .await?;
    let cli = SoracloudCli::new(dir.path(), &config);
    let _deploy = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("deploy for training lifecycle");
        "service", "deploy",
        "--container", container_path.to_string_lossy().into_owned(),
        "--service", service_path.to_string_lossy().into_owned(),
        "--bundle-file", bundle_path.to_string_lossy().into_owned(),
        "--sorafs-retention-epoch", SORACLOUD_TEST_RETENTION_EPOCH,
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let service_name = service.service_name.to_string();
    let model_name = "ops_model";
    let dataset_ref = "dataset://ops/synthetic-v1";
    let _training_start_1 = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("training-job-start #1");
        "model", "training-job-start",
        "--service-name", &service_name,
        "--model-name", model_name,
        "--job-id", "job-001",
        "--worker-group-size", "2",
        "--target-steps", "4",
        "--checkpoint-interval-steps", "2",
        "--max-retries", "2",
        "--step-compute-units", "25",
        "--compute-budget-units", "200",
        "--storage-budget-bytes", "8192",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let _checkpoint_1a = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("training-job-checkpoint #1a");
        "model", "training-job-checkpoint",
        "--service-name", &service_name,
        "--job-id", "job-001",
        "--completed-step", "2",
        "--checkpoint-size-bytes", "1024",
        "--metrics-hash", Hash::new(b"metrics-job-001-step-2").to_string(),
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let _checkpoint_1b = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("training-job-checkpoint #1b");
        "model", "training-job-checkpoint",
        "--service-name", &service_name,
        "--job-id", "job-001",
        "--completed-step", "4",
        "--checkpoint-size-bytes", "1536",
        "--metrics-hash", Hash::new(b"metrics-job-001-step-4").to_string(),
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let training_status_1 = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("training-job-status #1");
        "model", "training-job-status",
        "--service-name", &service_name,
        "--job-id", "job-001",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let training_status_payload_1: Value =
        json::from_slice(&training_status_1.stdout).expect("training-job-status #1 json payload");
    let job_1 = training_status_payload_1
        .get("job")
        .and_then(Value::as_object)
        .expect("training status job object");
    assert_eq!(job_1.get("job_id").and_then(Value::as_str), Some("job-001"));
    assert_eq!(
        job_1.get("completed_steps").and_then(Value::as_u64),
        Some(4)
    );
    let _artifact_register_1 = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("model-artifact-register #1");
        "model", "artifact-register",
        "--service-name", &service_name,
        "--model-name", model_name,
        "--training-job-id", "job-001",
        "--weight-artifact-hash", Hash::new(b"weight-artifact-v1").to_string(),
        "--dataset-ref", dataset_ref,
        "--training-config-hash", Hash::new(b"training-config-v1").to_string(),
        "--reproducibility-hash", Hash::new(b"repro-v1").to_string(),
        "--provenance-attestation-hash", Hash::new(b"attestation-v1").to_string(),
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let _weight_register_1 = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("model-weight-register #1");
        "model", "weight-register",
        "--service-name", &service_name,
        "--model-name", model_name,
        "--weight-version", "1.0.0",
        "--training-job-id", "job-001",
        "--weight-artifact-hash", Hash::new(b"weight-artifact-v1").to_string(),
        "--dataset-ref", dataset_ref,
        "--training-config-hash", Hash::new(b"training-config-v1").to_string(),
        "--reproducibility-hash", Hash::new(b"repro-v1").to_string(),
        "--provenance-attestation-hash", Hash::new(b"attestation-v1").to_string(),
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let _training_start_2 = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("training-job-start #2");
        "model", "training-job-start",
        "--service-name", &service_name,
        "--model-name", model_name,
        "--job-id", "job-002",
        "--worker-group-size", "2",
        "--target-steps", "4",
        "--checkpoint-interval-steps", "2",
        "--max-retries", "2",
        "--step-compute-units", "25",
        "--compute-budget-units", "220",
        "--storage-budget-bytes", "8192",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let _checkpoint_2a = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("training-job-checkpoint #2a");
        "model", "training-job-checkpoint",
        "--service-name", &service_name,
        "--job-id", "job-002",
        "--completed-step", "2",
        "--checkpoint-size-bytes", "1024",
        "--metrics-hash", Hash::new(b"metrics-job-002-step-2").to_string(),
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let _checkpoint_2b = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("training-job-checkpoint #2b");
        "model", "training-job-checkpoint",
        "--service-name", &service_name,
        "--job-id", "job-002",
        "--completed-step", "4",
        "--checkpoint-size-bytes", "1536",
        "--metrics-hash", Hash::new(b"metrics-job-002-step-4").to_string(),
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let _artifact_register_2 = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("model-artifact-register #2");
        "model", "artifact-register",
        "--service-name", &service_name,
        "--model-name", model_name,
        "--training-job-id", "job-002",
        "--weight-artifact-hash", Hash::new(b"weight-artifact-v2").to_string(),
        "--dataset-ref", dataset_ref,
        "--training-config-hash", Hash::new(b"training-config-v2").to_string(),
        "--reproducibility-hash", Hash::new(b"repro-v2").to_string(),
        "--provenance-attestation-hash", Hash::new(b"attestation-v2").to_string(),
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let _weight_register_2 = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("model-weight-register #2");
        "model", "weight-register",
        "--service-name", &service_name,
        "--model-name", model_name,
        "--weight-version", "1.1.0",
        "--training-job-id", "job-002",
        "--parent-version", "1.0.0",
        "--weight-artifact-hash", Hash::new(b"weight-artifact-v2").to_string(),
        "--dataset-ref", dataset_ref,
        "--training-config-hash", Hash::new(b"training-config-v2").to_string(),
        "--reproducibility-hash", Hash::new(b"repro-v2").to_string(),
        "--provenance-attestation-hash", Hash::new(b"attestation-v2").to_string(),
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let _promote_v2 = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("model-weight-promote");
        "model", "weight-promote",
        "--service-name", &service_name,
        "--model-name", model_name,
        "--weight-version", "1.1.0",
        "--gate-approved",
        "--gate-report-hash", Hash::new(b"gate-report-v2").to_string(),
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let status_after_promote = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("model-weight-status after promote");
        "model", "weight-status",
        "--service-name", &service_name,
        "--model-name", model_name,
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let status_after_promote_payload: Value =
        json::from_slice(&status_after_promote.stdout).expect("model-weight-status promote json");
    let model_after_promote = status_after_promote_payload
        .get("model")
        .and_then(Value::as_object)
        .expect("model object after promote");
    assert_eq!(
        model_after_promote
            .get("current_version")
            .and_then(Value::as_str),
        Some("1.1.0")
    );
    assert_eq!(
        model_after_promote
            .get("version_count")
            .and_then(Value::as_u64),
        Some(2)
    );
    let _rollback = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("model-weight-rollback");
        "model", "weight-rollback",
        "--service-name", &service_name,
        "--model-name", model_name,
        "--target-version", "1.0.0",
        "--reason", "roll back to baseline",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let status_after_rollback = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("model-weight-status after rollback");
        "model", "weight-status",
        "--service-name", &service_name,
        "--model-name", model_name,
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let status_after_rollback_payload: Value =
        json::from_slice(&status_after_rollback.stdout).expect("model-weight-status rollback json");
    let model_after_rollback = status_after_rollback_payload
        .get("model")
        .and_then(Value::as_object)
        .expect("model object after rollback");
    assert_eq!(
        model_after_rollback
            .get("current_version")
            .and_then(Value::as_str),
        Some("1.0.0")
    );
    let artifact_status_2 = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("model-artifact-status #2");
        "model", "artifact-status",
        "--service-name", &service_name,
        "--training-job-id", "job-002",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let artifact_status_payload_2: Value =
        json::from_slice(&artifact_status_2.stdout).expect("model-artifact-status #2 json");
    let artifact_2 = artifact_status_payload_2
        .get("artifact")
        .and_then(Value::as_object)
        .expect("artifact object #2");
    assert_eq!(
        artifact_2.get("training_job_id").and_then(Value::as_str),
        Some("job-002")
    );
    assert_eq!(
        artifact_2
            .get("consumed_by_version")
            .and_then(Value::as_str),
        Some("1.1.0")
    );
    Ok(())
}
#[tokio::test]
async fn soracloud_hf_shared_lease_commands_use_live_torii_control_plane() -> eyre::Result<()> {
    prepare_iroha_cli_test_environment();
    let lease_asset_definition = soracloud_hf_lease_asset_definition();
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        .with_npos_consensus()
        .with_config_layer(move |layer| {
            // The test-network genesis explicitly authors Ed25519, Secp256k1 and BLS.
            layer.write("telemetry_profile", "full");
        });
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(soracloud_hf_shared_lease_commands_use_live_torii_control_plane),
    )
    .await?
    else {
        return Ok(());
    };
    assert_soracloud_hf_lease_asset_ready(
        &network.client(),
        std::slice::from_ref(network.client().client().account()),
        100_000,
    )?;
    let config = ProgramConfig::from(&network.client());
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let repo_id = SORACLOUD_LIVE_HF_TEST_REPO_ID;
    let service_name_a = "hf_lease_a";
    let service_name_b = "hf_lease_b";
    let service_name_renew = "hf_lease_renew";
    let apartment_name = "ops_agent";
    let lease_term_ms = "60000".to_string();
    let base_fee = canonical_quantity_literal_from_nanos(10_000);
    let lease_asset_definition = lease_asset_definition.to_string();
    let torii_url = network.client().client().endpoint().to_string();
    let account_id = network.client().client().account().to_string();
    let deploy = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-join",
            "--repo-id",
            repo_id,
            "--service-name",
            service_name_a,
            "--apartment-name",
            apartment_name,
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--lease-asset-definition",
            lease_asset_definition.as_str(),
            "--base-fee",
            base_fee.as_str(),
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&deploy, "hf-join");
    let join_payload: Value = json::from_slice(&deploy.stdout).expect("hf-join json");
    assert_eq!(
        join_payload
            .get("action")
            .and_then(|value| tagged_enum_label(value, "action")),
        Some("CreateWindow")
    );
    let join_source = join_payload
        .get("source")
        .and_then(Value::as_object)
        .expect("hf-join source object");
    assert_eq!(
        join_source.get("resolved_revision").and_then(Value::as_str),
        Some(SORACLOUD_LIVE_HF_TEST_RESOLVED_REVISION)
    );
    let join_member = join_payload
        .get("member")
        .and_then(Value::as_object)
        .expect("hf-join member object");
    assert_eq!(
        join_member.get("last_charge").and_then(Value::as_str),
        Some(base_fee.as_str())
    );
    let rebind = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-join",
            "--repo-id",
            repo_id,
            "--service-name",
            service_name_b,
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--lease-asset-definition",
            lease_asset_definition.as_str(),
            "--base-fee",
            base_fee.as_str(),
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&rebind, "hf-join rebind");
    let rebind_payload: Value = json::from_slice(&rebind.stdout).expect("hf rebind json");
    assert_eq!(
        rebind_payload
            .get("action")
            .and_then(|value| tagged_enum_label(value, "action")),
        Some("Join")
    );
    let rebind_member = rebind_payload
        .get("member")
        .and_then(Value::as_object)
        .expect("hf rebind member object");
    assert_eq!(
        rebind_member.get("last_charge").and_then(Value::as_str),
        Some("0")
    );
    let rebind_services = rebind_member
        .get("service_bindings")
        .and_then(Value::as_array)
        .expect("hf rebind service bindings");
    assert_eq!(rebind_services.len(), 2);
    assert!(
        rebind_services
            .iter()
            .any(|value| value.as_str() == Some(service_name_a))
    );
    assert!(
        rebind_services
            .iter()
            .any(|value| value.as_str() == Some(service_name_b))
    );
    let status = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-status",
            "--repo-id",
            repo_id,
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--account-id",
            account_id.as_str(),
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&status, "hf-status");
    let status_payload: Value = json::from_slice(&status.stdout).expect("hf-status json");
    let status_pool = status_payload
        .get("pool")
        .and_then(Value::as_object)
        .expect("hf status pool object");
    assert_eq!(
        status_pool
            .get("active_member_count")
            .and_then(Value::as_u64),
        Some(1)
    );
    let status_member = status_payload
        .get("member")
        .and_then(Value::as_object)
        .expect("hf status member object");
    let status_services = status_member
        .get("service_bindings")
        .and_then(Value::as_array)
        .expect("hf status service bindings");
    assert_eq!(status_services.len(), 2);
    let leave = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-lease-leave",
            "--repo-id",
            repo_id,
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--service-name",
            service_name_a,
            "--apartment-name",
            apartment_name,
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&leave, "hf-lease-leave");
    let leave_payload: Value = json::from_slice(&leave.stdout).expect("hf leave json");
    assert_eq!(
        leave_payload
            .get("action")
            .and_then(|value| tagged_enum_label(value, "action")),
        Some("Leave")
    );
    let leave_pool = leave_payload
        .get("pool")
        .and_then(Value::as_object)
        .expect("hf leave pool object");
    assert_eq!(
        leave_pool
            .get("status")
            .and_then(|value| tagged_enum_label(value, "status")),
        Some("Draining")
    );
    let leave_member = leave_payload
        .get("member")
        .and_then(Value::as_object)
        .expect("hf leave member object");
    assert_eq!(
        leave_member
            .get("status")
            .and_then(|value| tagged_enum_label(value, "status")),
        Some("Left")
    );
    let renew = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-lease-renew",
            "--repo-id",
            repo_id,
            "--service-name",
            service_name_renew,
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--lease-asset-definition",
            lease_asset_definition.as_str(),
            "--base-fee",
            base_fee.as_str(),
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&renew, "hf-lease-renew");
    let renew_payload: Value = json::from_slice(&renew.stdout).expect("hf renew json");
    assert_eq!(
        renew_payload
            .get("action")
            .and_then(|value| tagged_enum_label(value, "action")),
        Some("Renew")
    );
    let renew_member = renew_payload
        .get("member")
        .and_then(Value::as_object)
        .expect("hf renew member object");
    assert_eq!(
        renew_member
            .get("status")
            .and_then(|value| tagged_enum_label(value, "status")),
        Some("Active")
    );
    assert_eq!(
        renew_member.get("last_charge").and_then(Value::as_str),
        Some(base_fee.as_str())
    );
    let status_after_renew = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-status",
            "--repo-id",
            repo_id,
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--account-id",
            account_id.as_str(),
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&status_after_renew, "hf-status after renew");
    let status_after_renew_payload: Value =
        json::from_slice(&status_after_renew.stdout).expect("hf status after renew json");
    let renewed_member = status_after_renew_payload
        .get("member")
        .and_then(Value::as_object)
        .expect("hf renewed member object");
    assert_eq!(
        renewed_member
            .get("status")
            .and_then(|value| tagged_enum_label(value, "status")),
        Some("Active")
    );
    let renewed_services = renewed_member
        .get("service_bindings")
        .and_then(Value::as_array)
        .expect("hf renewed service bindings");
    assert_eq!(renewed_services.len(), 1);
    assert_eq!(renewed_services[0].as_str(), Some(service_name_renew));
    Ok(())
}
#[tokio::test]
async fn soracloud_hf_pre_expiry_renewal_queues_and_promotes_next_window() -> eyre::Result<()> {
    prepare_iroha_cli_test_environment();
    let lease_asset_definition = soracloud_hf_lease_asset_definition();
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        .with_npos_consensus()
        .with_config_layer(move |layer| {
            // The test-network genesis explicitly authors Ed25519, Secp256k1 and BLS.
            layer.write("telemetry_profile", "full");
        });
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(soracloud_hf_pre_expiry_renewal_queues_and_promotes_next_window),
    )
    .await?
    else {
        return Ok(());
    };
    assert_soracloud_hf_lease_asset_ready(
        &network.client(),
        std::slice::from_ref(network.client().client().account()),
        100_000,
    )?;
    let config = ProgramConfig::from(&network.client());
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let repo_id = SORACLOUD_LIVE_HF_TEST_REPO_ID;
    let initial_service_name = "hf_queue_a";
    let queued_service_name = "hf_queue_next";
    let promoted_service_name = "hf_queue_promoted";
    let lease_term_ms_value = 30_000_u64;
    let lease_term_ms = lease_term_ms_value.to_string();
    let base_fee = canonical_quantity_literal_from_nanos(10_000);
    let renewed_fee = canonical_quantity_literal_from_nanos(12_000);
    let lease_asset_definition = lease_asset_definition.to_string();
    let torii_url = network.client().client().endpoint().to_string();
    let account_id = network.client().client().account().to_string();
    let deploy = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-join",
            "--repo-id",
            repo_id,
            "--service-name",
            initial_service_name,
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--lease-asset-definition",
            lease_asset_definition.as_str(),
            "--base-fee",
            base_fee.as_str(),
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&deploy, "initial hf-join");
    let join_payload: Value = json::from_slice(&deploy.stdout).expect("initial deploy json");
    assert_eq!(
        join_payload
            .get("action")
            .and_then(|value| tagged_enum_label(value, "action")),
        Some("CreateWindow")
    );
    let renew = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-lease-renew",
            "--repo-id",
            repo_id,
            "--service-name",
            queued_service_name,
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--lease-asset-definition",
            lease_asset_definition.as_str(),
            "--base-fee",
            renewed_fee.as_str(),
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&renew, "pre-expiry hf-lease-renew");
    let renew_payload: Value = json::from_slice(&renew.stdout).expect("renew json");
    assert_eq!(
        renew_payload
            .get("action")
            .and_then(|value| tagged_enum_label(value, "action")),
        Some("Renew")
    );
    let renew_pool = renew_payload
        .get("pool")
        .and_then(Value::as_object)
        .expect("renew pool");
    assert_eq!(
        renew_pool
            .get("status")
            .and_then(|value| tagged_enum_label(value, "status")),
        Some("Active")
    );
    let queued_next_window = renew_pool
        .get("queued_next_window")
        .and_then(Value::as_object)
        .expect("queued next window");
    assert_eq!(
        queued_next_window
            .get("service_name")
            .and_then(Value::as_str),
        Some(queued_service_name)
    );
    assert_eq!(
        queued_next_window.get("base_fee").and_then(Value::as_str),
        Some(renewed_fee.as_str())
    );
    assert_eq!(
        renew_payload
            .get("member")
            .and_then(Value::as_object)
            .and_then(|member| member.get("last_charge"))
            .and_then(Value::as_str),
        Some(renewed_fee.as_str())
    );
    let current_window_expires_at_ms = renew_pool
        .get("window_expires_at_ms")
        .and_then(Value::as_u64)
        .expect("current window expiry");
    let blocked_leave = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-lease-leave",
            "--repo-id",
            repo_id,
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--service-name",
            initial_service_name,
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert!(
        !blocked_leave.status.success(),
        "queued sponsor leave unexpectedly succeeded with stdout: {}",
        String::from_utf8_lossy(&blocked_leave.stdout)
    );
    let blocked_leave_stderr = String::from_utf8_lossy(&blocked_leave.stderr);
    assert!(
        blocked_leave_stderr.contains("cannot leave before it activates"),
        "unexpected queued sponsor leave stderr: {blocked_leave_stderr}"
    );
    // Wait until just after the authoritative current window expires. Sleeping
    // for a full extra lease term from the renew response can overshoot on
    // slower localnets and land in the post-queued `CreateWindow` path instead
    // of exercising queued-window promotion.
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let promote_after_ms = u128::from(current_window_expires_at_ms).saturating_add(250);
    let wait_ms = promote_after_ms
        .saturating_sub(now_ms)
        .min(u128::from(u64::MAX)) as u64;
    tokio::time::sleep(Duration::from_millis(wait_ms)).await;
    let promote = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-join",
            "--repo-id",
            repo_id,
            "--service-name",
            promoted_service_name,
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--lease-asset-definition",
            lease_asset_definition.as_str(),
            "--base-fee",
            renewed_fee.as_str(),
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&promote, "promotion hf-join");
    let promote_payload: Value = json::from_slice(&promote.stdout).expect("promote json");
    assert_eq!(
        promote_payload
            .get("action")
            .and_then(|value| tagged_enum_label(value, "action")),
        Some("Join")
    );
    assert_eq!(
        promote_payload
            .get("member")
            .and_then(Value::as_object)
            .and_then(|member| member.get("last_charge"))
            .and_then(Value::as_str),
        Some("0")
    );
    let status = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-status",
            "--repo-id",
            repo_id,
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--account-id",
            account_id.as_str(),
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&status, "post-promotion hf-status");
    let status_payload: Value = json::from_slice(&status.stdout).expect("status json");
    let status_pool = status_payload
        .get("pool")
        .and_then(Value::as_object)
        .expect("status pool");
    assert_eq!(
        status_pool
            .get("active_member_count")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert!(
        status_pool
            .get("queued_next_window")
            .is_none_or(Value::is_null),
        "queued next window should be cleared after promotion: {status_pool:?}"
    );
    assert_eq!(
        status_pool.get("base_fee").and_then(Value::as_str),
        Some(renewed_fee.as_str())
    );
    let status_member = status_payload
        .get("member")
        .and_then(Value::as_object)
        .expect("status member");
    let status_services = status_member
        .get("service_bindings")
        .and_then(Value::as_array)
        .expect("status service bindings");
    assert!(
        status_services
            .iter()
            .any(|value| value.as_str() == Some(initial_service_name))
    );
    assert!(
        status_services
            .iter()
            .any(|value| value.as_str() == Some(queued_service_name))
    );
    assert!(
        status_services
            .iter()
            .any(|value| value.as_str() == Some(promoted_service_name))
    );
    Ok(())
}
#[tokio::test]
async fn soracloud_hf_shared_lease_prorates_refunds_across_multiple_accounts() -> eyre::Result<()> {
    prepare_iroha_cli_test_environment();
    let lease_asset_definition = soracloud_hf_lease_asset_definition();
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        .with_npos_consensus()
        .with_config_layer(move |layer| {
            // The test-network genesis explicitly authors Ed25519, Secp256k1 and BLS.
            layer.write("telemetry_profile", "full");
        })
        .with_genesis_instruction(Grant::account_permission(
            Permission::new("CanManageSoracloud".into(), Json::new(())),
            BOB_ID.clone(),
        ))
        .with_genesis_instruction(Grant::account_permission(
            Permission::new("CanManageSoracloud".into(), Json::new(())),
            CARPENTER_ID.clone(),
        ))
        .with_genesis_instruction(Grant::account_permission(
            CanTransferAssetWithDefinition {
                asset_definition: lease_asset_definition.clone(),
            },
            BOB_ID.clone(),
        ))
        .with_genesis_instruction(Grant::account_permission(
            CanTransferAssetWithDefinition {
                asset_definition: lease_asset_definition.clone(),
            },
            CARPENTER_ID.clone(),
        ));
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(soracloud_hf_shared_lease_prorates_refunds_across_multiple_accounts),
    )
    .await?
    else {
        return Ok(());
    };
    assert_soracloud_hf_lease_asset_ready(
        &network.client(),
        &[
            network.client().client().account().clone(),
            BOB_ID.clone(),
            CARPENTER_ID.clone(),
        ],
        100_000,
    )?;
    let alice_config = ProgramConfig::from(&network.client());
    let bob_config = program_config_for_account(&network.client(), "wonderland", &BOB_KEYPAIR);
    let carpenter_config = program_config_for_account(
        &network.client(),
        "garden_of_live_flowers",
        &CARPENTER_KEYPAIR,
    );
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&alice_config.toml())?.as_bytes(),
    )
    .await?;
    let repo_id = SORACLOUD_LIVE_HF_TEST_REPO_ID;
    let torii_url = network.client().client().endpoint().to_string();
    let lease_term_ms = 60_000_u64;
    let lease_term_ms_literal = lease_term_ms.to_string();
    let base_fee_subunits = 10_000_u128;
    let base_fee = canonical_quantity_literal_from_nanos(base_fee_subunits);
    let lease_asset_definition = lease_asset_definition.to_string();
    let alice_account_id = network.client().client().account().to_string();
    let bob_account_id = BOB_ID.to_string();
    let carpenter_account_id = CARPENTER_ID.to_string();
    let alice_join = run_soracloud_command(
        dir.path(),
        &alice_config,
        &[
            "hf-join",
            "--repo-id",
            repo_id,
            "--service-name",
            "hf_lease_alice",
            "--lease-term-ms",
            lease_term_ms_literal.as_str(),
            "--lease-asset-definition",
            lease_asset_definition.as_str(),
            "--base-fee",
            base_fee.as_str(),
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&alice_join, "alice hf-join");
    let alice_join_payload: Value =
        json::from_slice(&alice_join.stdout).expect("alice hf-join json");
    assert_eq!(
        alice_join_payload
            .get("action")
            .and_then(|value| tagged_enum_label(value, "action")),
        Some("CreateWindow")
    );
    assert_eq!(
        alice_join_payload
            .get("member")
            .and_then(Value::as_object)
            .and_then(|member| member.get("last_charge"))
            .and_then(Value::as_str),
        Some(base_fee.as_str())
    );
    let bob_join = run_soracloud_command(
        dir.path(),
        &bob_config,
        &[
            "hf-join",
            "--repo-id",
            repo_id,
            "--service-name",
            "hf_lease_bob",
            "--lease-term-ms",
            lease_term_ms_literal.as_str(),
            "--lease-asset-definition",
            lease_asset_definition.as_str(),
            "--base-fee",
            base_fee.as_str(),
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&bob_join, "bob hf-join");
    let bob_join_payload: Value = json::from_slice(&bob_join.stdout).expect("bob deploy json");
    assert_eq!(
        bob_join_payload
            .get("action")
            .and_then(|value| tagged_enum_label(value, "action")),
        Some("Join")
    );
    let bob_status_payload = wait_for_soracloud_hf_status_payload(
        dir.path(),
        &bob_config,
        repo_id,
        lease_term_ms_literal.as_str(),
        bob_account_id.as_str(),
        torii_url.as_str(),
        SORACLOUD_TEST_CONTROL_PLANE_POLL_TIMEOUT,
        |payload| {
            payload
                .get("pool")
                .and_then(Value::as_object)
                .and_then(|pool| pool.get("active_member_count"))
                .and_then(Value::as_u64)
                == Some(2)
                && payload
                    .get("latest_audit_event")
                    .and_then(Value::as_object)
                    .and_then(|event| event.get("action"))
                    .and_then(|value| tagged_enum_label(value, "action"))
                    == Some("Join")
                && payload
                    .get("latest_audit_event")
                    .and_then(Value::as_object)
                    .and_then(|event| event.get("account_id"))
                    .and_then(Value::as_str)
                    == Some(bob_account_id.as_str())
        },
    )
    .await?;
    let bob_pool = bob_status_payload
        .get("pool")
        .and_then(Value::as_object)
        .expect("bob pool");
    assert_eq!(
        bob_pool.get("active_member_count").and_then(Value::as_u64),
        Some(2)
    );
    let bob_latest_event = bob_status_payload
        .get("latest_audit_event")
        .and_then(Value::as_object)
        .expect("bob latest audit event");
    assert_eq!(
        bob_latest_event
            .get("action")
            .and_then(|value| tagged_enum_label(value, "action")),
        Some("Join")
    );
    assert_eq!(
        bob_latest_event.get("account_id").and_then(Value::as_str),
        Some(bob_account_id.as_str())
    );
    let bob_remaining_ms = bob_latest_event
        .get("lease_expires_at_ms")
        .and_then(Value::as_u64)
        .expect("bob lease_expires_at_ms")
        .saturating_sub(
            bob_latest_event
                .get("occurred_at_ms")
                .and_then(Value::as_u64)
                .expect("bob occurred_at_ms"),
        );
    let bob_expected_charge =
        (base_fee_subunits * u128::from(bob_remaining_ms) / u128::from(lease_term_ms)) / 2;
    let bob_expected_charge_quantity = canonical_quantity_literal_from_nanos(bob_expected_charge);
    assert_eq!(
        bob_join_payload
            .get("member")
            .and_then(Value::as_object)
            .and_then(|member| member.get("last_charge"))
            .and_then(Value::as_str),
        Some(bob_expected_charge_quantity.as_str())
    );
    let carpenter_join = run_soracloud_command(
        dir.path(),
        &carpenter_config,
        &[
            "hf-join",
            "--repo-id",
            repo_id,
            "--service-name",
            "hf_lease_carpenter",
            "--lease-term-ms",
            lease_term_ms_literal.as_str(),
            "--lease-asset-definition",
            lease_asset_definition.as_str(),
            "--base-fee",
            base_fee.as_str(),
            "--torii-url",
            torii_url.as_str(),
        ],
    )
    .await?;
    assert_soracloud_success(&carpenter_join, "carpenter hf-join");
    let carpenter_join_payload: Value =
        json::from_slice(&carpenter_join.stdout).expect("carpenter deploy json");
    assert_eq!(
        carpenter_join_payload
            .get("action")
            .and_then(|value| tagged_enum_label(value, "action")),
        Some("Join")
    );
    let carpenter_status_payload = wait_for_soracloud_hf_status_payload(
        dir.path(),
        &carpenter_config,
        repo_id,
        lease_term_ms_literal.as_str(),
        carpenter_account_id.as_str(),
        torii_url.as_str(),
        SORACLOUD_TEST_CONTROL_PLANE_POLL_TIMEOUT,
        |payload| {
            payload
                .get("pool")
                .and_then(Value::as_object)
                .and_then(|pool| pool.get("active_member_count"))
                .and_then(Value::as_u64)
                == Some(3)
                && payload
                    .get("latest_audit_event")
                    .and_then(Value::as_object)
                    .and_then(|event| event.get("action"))
                    .and_then(|value| tagged_enum_label(value, "action"))
                    == Some("Join")
                && payload
                    .get("latest_audit_event")
                    .and_then(Value::as_object)
                    .and_then(|event| event.get("account_id"))
                    .and_then(Value::as_str)
                    == Some(carpenter_account_id.as_str())
        },
    )
    .await?;
    let carpenter_pool = carpenter_status_payload
        .get("pool")
        .and_then(Value::as_object)
        .expect("carpenter pool");
    assert_eq!(
        carpenter_pool
            .get("active_member_count")
            .and_then(Value::as_u64),
        Some(3)
    );
    let carpenter_latest_event = carpenter_status_payload
        .get("latest_audit_event")
        .and_then(Value::as_object)
        .expect("carpenter latest audit event");
    assert_eq!(
        carpenter_latest_event
            .get("action")
            .and_then(|value| tagged_enum_label(value, "action")),
        Some("Join")
    );
    assert_eq!(
        carpenter_latest_event
            .get("account_id")
            .and_then(Value::as_str),
        Some(carpenter_account_id.as_str())
    );
    let carpenter_remaining_ms = carpenter_latest_event
        .get("lease_expires_at_ms")
        .and_then(Value::as_u64)
        .expect("carpenter lease_expires_at_ms")
        .saturating_sub(
            carpenter_latest_event
                .get("occurred_at_ms")
                .and_then(Value::as_u64)
                .expect("carpenter occurred_at_ms"),
        );
    let carpenter_expected_charge =
        (base_fee_subunits * u128::from(carpenter_remaining_ms) / u128::from(lease_term_ms)) / 3;
    let carpenter_expected_charge_quantity =
        canonical_quantity_literal_from_nanos(carpenter_expected_charge);
    assert_eq!(
        carpenter_join_payload
            .get("member")
            .and_then(Value::as_object)
            .and_then(|member| member.get("last_charge"))
            .and_then(Value::as_str),
        Some(carpenter_expected_charge_quantity.as_str())
    );
    let alice_status_payload = wait_for_soracloud_hf_status_payload(
        dir.path(),
        &alice_config,
        repo_id,
        lease_term_ms_literal.as_str(),
        alice_account_id.as_str(),
        torii_url.as_str(),
        SORACLOUD_TEST_CONTROL_PLANE_POLL_TIMEOUT,
        |payload| {
            payload
                .get("pool")
                .and_then(Value::as_object)
                .and_then(|pool| pool.get("active_member_count"))
                .and_then(Value::as_u64)
                == Some(3)
                && payload
                    .get("member")
                    .and_then(Value::as_object)
                    .and_then(|member| member.get("total_refunded"))
                    .and_then(Value::as_str)
                    .is_some()
        },
    )
    .await?;
    let alice_member = alice_status_payload
        .get("member")
        .and_then(Value::as_object)
        .expect("alice member");
    let bob_final_status_payload = wait_for_soracloud_hf_status_payload(
        dir.path(),
        &bob_config,
        repo_id,
        lease_term_ms_literal.as_str(),
        bob_account_id.as_str(),
        torii_url.as_str(),
        SORACLOUD_TEST_CONTROL_PLANE_POLL_TIMEOUT,
        |payload| {
            payload
                .get("pool")
                .and_then(Value::as_object)
                .and_then(|pool| pool.get("active_member_count"))
                .and_then(Value::as_u64)
                == Some(3)
                && payload
                    .get("member")
                    .and_then(Value::as_object)
                    .and_then(|member| member.get("total_refunded"))
                    .and_then(Value::as_str)
                    .is_some()
        },
    )
    .await?;
    let bob_member = bob_final_status_payload
        .get("member")
        .and_then(Value::as_object)
        .expect("bob member");
    let carpenter_member = carpenter_status_payload
        .get("member")
        .and_then(Value::as_object)
        .expect("carpenter member");
    let alice_join_order = (
        alice_member
            .get("joined_at_ms")
            .and_then(Value::as_u64)
            .expect("alice joined_at_ms"),
        alice_account_id.as_str(),
    );
    let bob_join_order = (
        bob_member
            .get("joined_at_ms")
            .and_then(Value::as_u64)
            .expect("bob joined_at_ms"),
        bob_account_id.as_str(),
    );
    let carpenter_base_refund = carpenter_expected_charge / 2;
    let carpenter_remainder = carpenter_expected_charge % 2;
    let (alice_carpenter_refund, bob_carpenter_refund) = if alice_join_order <= bob_join_order {
        (
            carpenter_base_refund + carpenter_remainder,
            carpenter_base_refund,
        )
    } else {
        (
            carpenter_base_refund,
            carpenter_base_refund + carpenter_remainder,
        )
    };
    let alice_expected_refund_quantity =
        canonical_quantity_literal_from_nanos(bob_expected_charge + alice_carpenter_refund);
    let bob_expected_refund_quantity = canonical_quantity_literal_from_nanos(bob_carpenter_refund);
    assert_eq!(
        alice_status_payload
            .get("pool")
            .and_then(Value::as_object)
            .and_then(|pool| pool.get("active_member_count"))
            .and_then(Value::as_u64),
        Some(3)
    );
    assert_eq!(
        bob_final_status_payload
            .get("pool")
            .and_then(Value::as_object)
            .and_then(|pool| pool.get("active_member_count"))
            .and_then(Value::as_u64),
        Some(3)
    );
    assert_eq!(
        carpenter_status_payload
            .get("pool")
            .and_then(Value::as_object)
            .and_then(|pool| pool.get("active_member_count"))
            .and_then(Value::as_u64),
        Some(3)
    );
    assert_eq!(
        alice_member.get("total_paid").and_then(Value::as_str),
        Some(base_fee.as_str())
    );
    assert_eq!(
        alice_member.get("total_refunded").and_then(Value::as_str),
        Some(alice_expected_refund_quantity.as_str())
    );
    assert_eq!(
        bob_member.get("total_paid").and_then(Value::as_str),
        Some(bob_expected_charge_quantity.as_str())
    );
    assert_eq!(
        bob_member.get("total_refunded").and_then(Value::as_str),
        Some(bob_expected_refund_quantity.as_str())
    );
    assert_eq!(
        carpenter_member.get("total_paid").and_then(Value::as_str),
        Some(carpenter_expected_charge_quantity.as_str())
    );
    assert_eq!(
        carpenter_member
            .get("total_refunded")
            .and_then(Value::as_str),
        Some("0")
    );
    Ok(())
}
#[tokio::test]
async fn soracloud_templates_deploy_site_and_webapp_with_rollout_and_rollback() -> eyre::Result<()>
{
    prepare_iroha_cli_test_environment();
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        .with_config_layer(|layer| {
            layer.write("telemetry_profile", "full");
        });
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(soracloud_templates_deploy_site_and_webapp_with_rollout_and_rollback),
    )
    .await?
    else {
        return Ok(());
    };
    let config = ProgramConfig::from(&network.client());
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let site_dir = dir.path().join("soracloud_site");
    let webapp_dir = dir.path().join("soracloud_webapp");
    let cli = SoracloudCli::new(dir.path(), &config);
    let _site_init = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("site init");
        "service", "init",
        "--template", "site",
        "--service-name", "docs_portal",
        "--service-version", "1.0.0",
        "--output-dir", site_dir.to_string_lossy().into_owned(),
    );
    let _webapp_init = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("webapp init");
        "service", "init",
        "--template", "webapp",
        "--service-name", "agent_console",
        "--service-version", "1.0.0",
        "--output-dir", webapp_dir.to_string_lossy().into_owned(),
    );
    let site_service_path = site_dir.join("service_manifest.json");
    let webapp_service_path = webapp_dir.join("service_manifest.json");
    let site_container_path = site_dir.join("container_manifest.json");
    let webapp_container_path = webapp_dir.join("container_manifest.json");
    let mut site_container: SoraContainerManifestV1 =
        norito::json::from_slice(&std::fs::read(&site_container_path)?)?;
    let mut webapp_container: SoraContainerManifestV1 =
        norito::json::from_slice(&std::fs::read(&webapp_container_path)?)?;
    let mut site_service: SoraServiceManifestV1 =
        norito::json::from_slice(&std::fs::read(&site_service_path)?)?;
    let mut webapp_service: SoraServiceManifestV1 =
        norito::json::from_slice(&std::fs::read(&webapp_service_path)?)?;
    let site_bundle_path =
        install_soracloud_test_bundle(&site_dir, "site", &mut site_container, &mut site_service)?;
    let webapp_bundle_path = install_soracloud_test_bundle(
        &webapp_dir,
        "webapp",
        &mut webapp_container,
        &mut webapp_service,
    )?;
    std::fs::write(
        &site_container_path,
        norito::json::to_vec_pretty(&site_container)?,
    )?;
    std::fs::write(
        &site_service_path,
        norito::json::to_vec_pretty(&site_service)?,
    )?;
    std::fs::write(
        &webapp_container_path,
        norito::json::to_vec_pretty(&webapp_container)?,
    )?;
    std::fs::write(
        &webapp_service_path,
        norito::json::to_vec_pretty(&webapp_service)?,
    )?;
    let site_package_json = std::fs::read_to_string(site_dir.join("site/package.json"))?;
    let webapp_frontend_package_json =
        std::fs::read_to_string(webapp_dir.join("webapp/frontend/package.json"))?;
    assert!(
        site_package_json.contains("\"build\": \"vite build\""),
        "site template must include a vite build script"
    );
    assert!(
        webapp_frontend_package_json.contains("\"build\": \"vite build\""),
        "webapp frontend template must include a vite build script"
    );
    assert_eq!(
        site_service
            .route
            .as_ref()
            .map(|route| route.path_prefix.as_str()),
        Some("/")
    );
    assert_eq!(
        webapp_service
            .route
            .as_ref()
            .map(|route| route.path_prefix.as_str()),
        Some("/api")
    );
    let site_deploy = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("site deploy");
        "service", "deploy",
        "--container", site_container_path.to_string_lossy().into_owned(),
        "--service", site_service_path.to_string_lossy().into_owned(),
        "--bundle-file", site_bundle_path.to_string_lossy().into_owned(),
        "--sorafs-retention-epoch", SORACLOUD_TEST_RETENTION_EPOCH,
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let site_join_payload: Value =
        json::from_slice(&site_deploy.stdout).expect("site deploy JSON payload");
    assert_eq!(
        site_join_payload
            .get("current_version")
            .and_then(Value::as_str),
        Some("1.0.0")
    );
    let webapp_deploy = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("webapp deploy");
        "service", "deploy",
        "--container", webapp_container_path.to_string_lossy().into_owned(),
        "--service", webapp_service_path.to_string_lossy().into_owned(),
        "--bundle-file", webapp_bundle_path.to_string_lossy().into_owned(),
        "--sorafs-retention-epoch", SORACLOUD_TEST_RETENTION_EPOCH,
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let webapp_join_payload: Value =
        json::from_slice(&webapp_deploy.stdout).expect("webapp deploy JSON payload");
    assert_eq!(
        webapp_join_payload
            .get("current_version")
            .and_then(Value::as_str),
        Some("1.0.0")
    );
    let mut site_service_v2 = site_service.clone();
    site_service_v2.service_version = "1.1.0".to_string();
    let site_service_v2_path = site_dir.join("service_manifest_v2.json");
    tokio::fs::write(
        &site_service_v2_path,
        norito::json::to_vec_pretty(&site_service_v2).expect("encode site service v2"),
    )
    .await?;
    let site_upgrade = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("site upgrade");
        "service", "upgrade",
        "--container", site_container_path.to_string_lossy().into_owned(),
        "--service", site_service_v2_path.to_string_lossy().into_owned(),
        "--bundle-file", site_bundle_path.to_string_lossy().into_owned(),
        "--sorafs-retention-epoch", SORACLOUD_TEST_RETENTION_EPOCH,
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let site_upgrade_payload: Value =
        json::from_slice(&site_upgrade.stdout).expect("site upgrade JSON payload");
    assert_eq!(
        site_upgrade_payload
            .get("current_version")
            .and_then(Value::as_str),
        Some("1.1.0")
    );
    let rollout_handle = site_upgrade_payload
        .get("rollout_handle")
        .and_then(Value::as_str)
        .expect("site upgrade should emit rollout handle");
    let site_rollout = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("site rollout");
        "service", "rollout",
        "--service-name", "docs_portal",
        "--rollout-handle", rollout_handle,
        "--promote-to-percent", "100",
        "--governance-tx-hash", Hash::new(b"site-template-rollout").to_string(),
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let site_rollout_payload: Value =
        json::from_slice(&site_rollout.stdout).expect("site rollout JSON payload");
    assert_eq!(
        site_rollout_payload
            .get("stage")
            .and_then(Value::as_object)
            .and_then(|stage| stage.get("stage"))
            .and_then(Value::as_str),
        Some("Promoted")
    );
    let site_rollback = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("site rollback");
        "service", "rollback",
        "--service-name", "docs_portal",
        "--target-version", "1.0.0",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let site_rollback_payload: Value =
        json::from_slice(&site_rollback.stdout).expect("site rollback JSON payload");
    assert_eq!(
        site_rollback_payload
            .get("current_version")
            .and_then(Value::as_str),
        Some("1.0.0")
    );
    let status = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("status");
        "service", "status",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let status_payload: Value =
        json::from_slice(&status.stdout).expect("CLI should emit soracloud status payload");
    let network_status = status_payload
        .get("network_status")
        .and_then(Value::as_object)
        .expect("network_status object");
    let control_plane = network_status
        .get("control_plane")
        .and_then(Value::as_object)
        .expect("control_plane object");
    assert_eq!(
        control_plane.get("service_count").and_then(Value::as_u64),
        Some(2)
    );
    let services = control_plane
        .get("services")
        .and_then(Value::as_array)
        .expect("services array");
    let site_snapshot = services
        .iter()
        .find(|service| {
            service
                .get("service_name")
                .and_then(Value::as_str)
                .is_some_and(|name| name == "docs_portal")
        })
        .expect("docs_portal service snapshot");
    let webapp_snapshot = services
        .iter()
        .find(|service| {
            service
                .get("service_name")
                .and_then(Value::as_str)
                .is_some_and(|name| name == "agent_console")
        })
        .expect("agent_console service snapshot");
    assert_eq!(
        site_snapshot.get("current_version").and_then(Value::as_str),
        Some("1.0.0")
    );
    assert_eq!(
        webapp_snapshot
            .get("current_version")
            .and_then(Value::as_str),
        Some("1.0.0")
    );
    assert_eq!(
        site_snapshot
            .get("latest_revision")
            .and_then(Value::as_object)
            .and_then(|revision| revision.get("route_path_prefix"))
            .and_then(Value::as_str),
        Some("/")
    );
    assert_eq!(
        webapp_snapshot
            .get("latest_revision")
            .and_then(Value::as_object)
            .and_then(|revision| revision.get("route_path_prefix"))
            .and_then(Value::as_str),
        Some("/api")
    );
    Ok(())
}
#[tokio::test]
async fn soracloud_agent_autonomy_controls_use_live_torii_control_plane() -> eyre::Result<()> {
    prepare_iroha_cli_test_environment();
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        .with_config_layer(|layer| {
            layer.write("telemetry_profile", "full");
        });
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(soracloud_agent_autonomy_controls_use_live_torii_control_plane),
    )
    .await?
    else {
        return Ok(());
    };
    let config = ProgramConfig::from(&network.client());
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let mut manifest: AgentApartmentManifestV1 = norito::json::from_slice(&std::fs::read(
        soracloud_fixture("fixtures/soracloud/agent_apartment_manifest_v1.json"),
    )?)?;
    manifest
        .policy_capabilities
        .push("agent.autonomy.run".parse().expect("valid capability"));
    manifest.validate().expect("manifest should remain valid");
    let manifest_path = dir.path().join("agent_apartment_manifest.json");
    tokio::fs::write(
        &manifest_path,
        norito::json::to_vec_pretty(&manifest).expect("encode apartment manifest"),
    )
    .await?;
    let cli = SoracloudCli::new(dir.path(), &config);
    let deploy = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("agent deploy");
        "agent", "deploy",
        "--manifest", manifest_path.to_string_lossy().into_owned(),
        "--lease-blocks", "30",
        "--autonomy-budget-units", "500",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let join_payload: Value = json::from_slice(&deploy.stdout).expect("agent deploy JSON payload");
    assert_eq!(
        join_payload
            .get("action")
            .and_then(Value::as_object)
            .and_then(|action| action.get("action"))
            .and_then(Value::as_str),
        Some("Deploy")
    );
    assert_eq!(
        join_payload
            .get("budget_remaining_units")
            .and_then(Value::as_u64),
        Some(500)
    );
    let allow = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("artifact allow");
        "agent", "artifact-allow",
        "--apartment-name", "ops_agent",
        "--artifact-hash", "hash:ABCD0123#01",
        "--provenance-hash", "hash:PROV0001#01",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let allow_payload: Value = json::from_slice(&allow.stdout).expect("agent allow JSON payload");
    assert_eq!(
        allow_payload.get("allowlist_count").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        allow_payload
            .get("budget_remaining_units")
            .and_then(Value::as_u64),
        Some(500)
    );
    let status = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("autonomy status");
        "agent", "autonomy-status",
        "--apartment-name", "ops_agent",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let status_payload: Value =
        json::from_slice(&status.stdout).expect("autonomy status JSON payload");
    assert_eq!(
        status_payload
            .get("allowlist_count")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        status_payload.get("run_count").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        status_payload
            .get("budget_remaining_units")
            .and_then(Value::as_u64),
        Some(500)
    );
    let revoke = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("policy revoke");
        "agent", "policy-revoke",
        "--apartment-name", "ops_agent",
        "--capability", "agent.autonomy.run",
        "--reason", "manual-review",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let revoke_payload: Value =
        json::from_slice(&revoke.stdout).expect("policy revoke JSON payload");
    assert_eq!(
        revoke_payload
            .get("revoked_policy_capability_count")
            .and_then(Value::as_u64),
        Some(1)
    );
    Ok(())
}
#[tokio::test]
async fn soracloud_agent_wallet_mailbox_and_lease_recovery_use_live_torii_control_plane()
-> eyre::Result<()> {
    prepare_iroha_cli_test_environment();
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        .with_config_layer(|layer| {
            layer.write("telemetry_profile", "full");
        });
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(soracloud_agent_wallet_mailbox_and_lease_recovery_use_live_torii_control_plane),
    )
    .await?
    else {
        return Ok(());
    };
    let config = ProgramConfig::from(&network.client());
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let mut sender: AgentApartmentManifestV1 = norito::json::from_slice(&std::fs::read(
        soracloud_fixture("fixtures/soracloud/agent_apartment_manifest_v1.json"),
    )?)?;
    sender
        .policy_capabilities
        .push("agent.mailbox.send".parse().expect("valid capability"));
    sender
        .validate()
        .expect("sender manifest should remain valid");
    let mut recipient = sender.clone();
    recipient.apartment_name = "worker_agent".parse().expect("valid apartment name");
    recipient
        .policy_capabilities
        .retain(|capability| capability.as_ref() != "agent.mailbox.send");
    recipient
        .policy_capabilities
        .push("agent.mailbox.receive".parse().expect("valid capability"));
    recipient
        .validate()
        .expect("recipient manifest should remain valid");
    let sender_manifest_path = dir.path().join("sender_agent_manifest.json");
    let recipient_manifest_path = dir.path().join("recipient_agent_manifest.json");
    tokio::fs::write(
        &sender_manifest_path,
        norito::json::to_vec_pretty(&sender).expect("encode sender manifest"),
    )
    .await?;
    tokio::fs::write(
        &recipient_manifest_path,
        norito::json::to_vec_pretty(&recipient).expect("encode recipient manifest"),
    )
    .await?;
    let cli = SoracloudCli::new(dir.path(), &config);
    let _sender_deploy = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("sender deploy");
        "agent", "deploy",
        "--manifest", sender_manifest_path.to_string_lossy().into_owned(),
        "--lease-blocks", "1",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let _recipient_deploy = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("recipient deploy");
        "agent", "deploy",
        "--manifest", recipient_manifest_path.to_string_lossy().into_owned(),
        "--lease-blocks", "30",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let expired_wallet = run_bounded_soracloud_command!(
        cli;
        "agent", "wallet-spend",
        "--apartment-name", "ops_agent",
        "--request-id", "expired-wallet-request-1",
        "--asset-definition", "61CtjvNd9T3THAR65GsMVHr82Bjc",
        "--amount", "0.000001",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    assert!(
        !expired_wallet.status.success(),
        "wallet spend with expired lease should fail, stdout: {}, stderr: {}",
        String::from_utf8_lossy(&expired_wallet.stdout),
        String::from_utf8_lossy(&expired_wallet.stderr)
    );
    assert!(
        String::from_utf8_lossy(&expired_wallet.stderr).contains("lease expired"),
        "unexpected lease-expiry rejection error: {}",
        String::from_utf8_lossy(&expired_wallet.stderr)
    );
    let _renew = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("lease renew");
        "agent", "lease-renew",
        "--apartment-name", "ops_agent",
        "--lease-blocks", "20",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let restart = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("restart");
        "agent", "restart",
        "--apartment-name", "ops_agent",
        "--reason", "manual-restart",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let restart_payload: Value = json::from_slice(&restart.stdout).expect("restart JSON payload");
    assert_eq!(
        restart_payload.get("restart_count").and_then(Value::as_u64),
        Some(1)
    );
    let status = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("agent status");
        "agent", "status",
        "--apartment-name", "ops_agent",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let status_payload: Value =
        json::from_slice(&status.stdout).expect("agent status JSON payload");
    let apartments = status_payload
        .get("apartments")
        .and_then(Value::as_array)
        .expect("apartments array");
    assert_eq!(apartments.len(), 1);
    let apartment = &apartments[0];
    assert_eq!(
        apartment
            .get("status")
            .and_then(Value::as_object)
            .and_then(|status| status.get("status"))
            .and_then(Value::as_str),
        Some("Running")
    );
    assert_eq!(
        apartment.get("restart_count").and_then(Value::as_u64),
        Some(1)
    );
    let request_id = "integration-wallet-request-1";
    let wallet_request = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("wallet spend");
        "agent", "wallet-spend",
        "--apartment-name", "ops_agent",
        "--request-id", request_id,
        "--asset-definition", "61CtjvNd9T3THAR65GsMVHr82Bjc",
        "--amount", "0.001",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let wallet_request_payload: Value =
        json::from_slice(&wallet_request.stdout).expect("wallet request JSON payload");
    assert_eq!(
        wallet_request_payload
            .get("request_id")
            .and_then(Value::as_str),
        Some(request_id)
    );
    assert_eq!(
        wallet_request_payload
            .get("pending_request_count")
            .and_then(Value::as_u64),
        Some(1)
    );
    let wallet_approve = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("wallet approve");
        "agent", "wallet-approve",
        "--apartment-name", "ops_agent",
        "--request-id", request_id,
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let wallet_approve_payload: Value =
        json::from_slice(&wallet_approve.stdout).expect("wallet approve JSON payload");
    assert_eq!(
        wallet_approve_payload
            .get("pending_request_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    let message_send = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("message send");
        "agent", "message-send",
        "--from-apartment", "ops_agent",
        "--to-apartment", "worker_agent",
        "--channel", "ops.sync",
        "--payload", "rotate-key-42",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let message_send_payload: Value =
        json::from_slice(&message_send.stdout).expect("message send JSON payload");
    let message_id = message_send_payload
        .get("message_id")
        .and_then(Value::as_str)
        .expect("message id present")
        .to_owned();
    assert_eq!(
        message_send_payload
            .get("pending_message_count")
            .and_then(Value::as_u64),
        Some(1)
    );
    let mailbox_status_queued = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("mailbox status (queued)");
        "agent", "mailbox-status",
        "--apartment-name", "worker_agent",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let mailbox_status_queued_payload: Value =
        json::from_slice(&mailbox_status_queued.stdout).expect("mailbox status JSON payload");
    assert_eq!(
        mailbox_status_queued_payload
            .get("pending_message_count")
            .and_then(Value::as_u64),
        Some(1)
    );
    let queued_messages = mailbox_status_queued_payload
        .get("messages")
        .and_then(Value::as_array)
        .expect("mailbox messages array");
    assert_eq!(queued_messages.len(), 1);
    assert_eq!(
        queued_messages[0].get("message_id").and_then(Value::as_str),
        Some(message_id.as_str())
    );
    let message_ack = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("message ack");
        "agent", "message-ack",
        "--apartment-name", "worker_agent",
        "--message-id", message_id,
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let message_ack_payload: Value =
        json::from_slice(&message_ack.stdout).expect("message ack JSON payload");
    assert_eq!(
        message_ack_payload
            .get("pending_message_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    let mailbox_status_empty = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("mailbox status (empty)");
        "agent", "mailbox-status",
        "--apartment-name", "worker_agent",
        "--torii-url", network.client().client().endpoint().to_string(),
    );
    let mailbox_status_empty_payload: Value =
        json::from_slice(&mailbox_status_empty.stdout).expect("mailbox status JSON payload");
    assert_eq!(
        mailbox_status_empty_payload
            .get("pending_message_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    let empty_messages = mailbox_status_empty_payload
        .get("messages")
        .and_then(Value::as_array)
        .expect("empty mailbox messages array");
    assert!(empty_messages.is_empty());
    Ok(())
}
#[tokio::test]
async fn soracloud_agent_runtime_state_recovers_after_peer_restart_live_torii_control_plane()
-> eyre::Result<()> {
    prepare_iroha_cli_test_environment();
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        .with_config_layer(|layer| {
            layer.write("telemetry_profile", "full");
        });
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(
            soracloud_agent_runtime_state_recovers_after_peer_restart_live_torii_control_plane
        ),
    )
    .await?
    else {
        return Ok(());
    };
    let config = ProgramConfig::from(&network.client());
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let mut sender: AgentApartmentManifestV1 = norito::json::from_slice(&std::fs::read(
        soracloud_fixture("fixtures/soracloud/agent_apartment_manifest_v1.json"),
    )?)?;
    let mailbox_send_capability = "agent.mailbox.send".parse().expect("valid capability");
    if !sender
        .policy_capabilities
        .contains(&mailbox_send_capability)
    {
        sender.policy_capabilities.push(mailbox_send_capability);
    }
    sender
        .validate()
        .expect("sender manifest should remain valid");
    let mut recipient = sender.clone();
    recipient.apartment_name = "worker_agent".parse().expect("valid apartment name");
    recipient
        .policy_capabilities
        .retain(|capability| capability.as_ref() != "agent.mailbox.send");
    recipient
        .policy_capabilities
        .push("agent.mailbox.receive".parse().expect("valid capability"));
    recipient
        .validate()
        .expect("recipient manifest should remain valid");
    let sender_manifest_path = dir.path().join("sender_agent_manifest.json");
    let recipient_manifest_path = dir.path().join("recipient_agent_manifest.json");
    tokio::fs::write(
        &sender_manifest_path,
        norito::json::to_vec_pretty(&sender).expect("encode sender manifest"),
    )
    .await?;
    tokio::fs::write(
        &recipient_manifest_path,
        norito::json::to_vec_pretty(&recipient).expect("encode recipient manifest"),
    )
    .await?;
    let restart_peer = network.peers().first().expect("network peer").clone();
    let restart_torii_url = restart_peer.torii_url();
    let cli = SoracloudCli::new(dir.path(), &config);
    let _sender_deploy = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("sender deploy");
        "agent", "deploy",
        "--manifest", sender_manifest_path.to_string_lossy().into_owned(),
        "--lease-blocks", "80",
        "--autonomy-budget-units", "500",
        "--torii-url", &restart_torii_url,
    );
    let _recipient_deploy = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("recipient deploy");
        "agent", "deploy",
        "--manifest", recipient_manifest_path.to_string_lossy().into_owned(),
        "--lease-blocks", "80",
        "--autonomy-budget-units", "250",
        "--torii-url", &restart_torii_url,
    );
    let _allow = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("artifact allow");
        "agent", "artifact-allow",
        "--apartment-name", "ops_agent",
        "--artifact-hash", "hash:ABCD0123#01",
        "--provenance-hash", "hash:PROV0001#01",
        "--torii-url", &restart_torii_url,
    );
    let request_id = "restart-wallet-request-1";
    let wallet_request = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("wallet request");
        "agent", "wallet-spend",
        "--apartment-name", "ops_agent",
        "--request-id", request_id,
        "--asset-definition", "61CtjvNd9T3THAR65GsMVHr82Bjc",
        "--amount", "0.001",
        "--torii-url", &restart_torii_url,
    );
    let wallet_request_payload: Value =
        json::from_slice(&wallet_request.stdout).expect("wallet request JSON payload");
    assert_eq!(
        wallet_request_payload
            .get("request_id")
            .and_then(Value::as_str),
        Some(request_id)
    );
    assert_eq!(
        wallet_request_payload
            .get("pending_request_count")
            .and_then(Value::as_u64),
        Some(1)
    );
    let message_send = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("message send");
        "agent", "message-send",
        "--from-apartment", "ops_agent",
        "--to-apartment", "worker_agent",
        "--channel", "ops.sync",
        "--payload", "rotate-key-42",
        "--torii-url", &restart_torii_url,
    );
    let message_send_payload: Value =
        json::from_slice(&message_send.stdout).expect("message send JSON payload");
    let message_id = message_send_payload
        .get("message_id")
        .and_then(Value::as_str)
        .expect("message id present")
        .to_owned();
    let config_layers: Vec<_> = network.config_layers().collect();
    restart_peer.shutdown().await;
    let restart_timeout = network.peer_startup_timeout();
    tokio::time::timeout(
        restart_timeout,
        restart_peer.start_checked(config_layers.iter(), None),
    )
    .await
    .map_err(|_| {
        eyre::eyre!(
            "restarted peer did not become healthy within {:?}",
            restart_timeout
        )
    })??;
    let status_after_restart = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("agent status after restart");
        "agent", "status",
        "--apartment-name", "ops_agent",
        "--torii-url", &restart_torii_url,
    );
    let status_after_restart_payload: Value =
        json::from_slice(&status_after_restart.stdout).expect("agent status JSON payload");
    let apartments = status_after_restart_payload
        .get("apartments")
        .and_then(Value::as_array)
        .expect("apartments array");
    assert_eq!(apartments.len(), 1);
    let apartment = &apartments[0];
    assert_eq!(
        apartment
            .get("status")
            .and_then(Value::as_object)
            .and_then(|status| status.get("status"))
            .and_then(Value::as_str),
        Some("Running")
    );
    assert_eq!(
        apartment
            .get("pending_wallet_request_count")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        apartment.get("autonomy_run_count").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        apartment.get("process_generation").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        apartment.get("checkpoint_count").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        apartment
            .get("persistent_state_key_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        apartment
            .get("persistent_state_total_bytes")
            .and_then(Value::as_u64),
        Some(0)
    );
    assert!(
        apartment
            .get("lease_remaining_blocks")
            .and_then(Value::as_u64)
            .is_some_and(|ticks| ticks > 0)
    );
    let process_generation_before_manual_restart = apartment
        .get("process_generation")
        .and_then(Value::as_u64)
        .expect("process_generation in status after peer restart");
    let manual_restart = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("manual agent restart after peer restart");
        "agent", "restart",
        "--apartment-name", "ops_agent",
        "--reason", "resume-after-peer-restart",
        "--torii-url", &restart_torii_url,
    );
    let manual_restart_payload: Value =
        json::from_slice(&manual_restart.stdout).expect("manual restart payload");
    let process_generation_after_manual_restart = manual_restart_payload
        .get("process_generation")
        .and_then(Value::as_u64)
        .expect("process_generation after manual restart");
    assert_eq!(
        process_generation_after_manual_restart,
        process_generation_before_manual_restart.saturating_add(1)
    );
    let autonomy_status_after_restart = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("autonomy status after restart");
        "agent", "autonomy-status",
        "--apartment-name", "ops_agent",
        "--torii-url", &restart_torii_url,
    );
    let autonomy_status_after_restart_payload: Value =
        json::from_slice(&autonomy_status_after_restart.stdout).expect("autonomy status payload");
    assert_eq!(
        autonomy_status_after_restart_payload
            .get("run_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        autonomy_status_after_restart_payload
            .get("budget_remaining_units")
            .and_then(Value::as_u64),
        Some(500)
    );
    assert_eq!(
        autonomy_status_after_restart_payload
            .get("process_generation")
            .and_then(Value::as_u64),
        Some(process_generation_after_manual_restart)
    );
    assert_eq!(
        autonomy_status_after_restart_payload
            .get("checkpoint_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        autonomy_status_after_restart_payload
            .get("persistent_state_key_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        autonomy_status_after_restart_payload
            .get("persistent_state_total_bytes")
            .and_then(Value::as_u64),
        Some(0)
    );
    let mailbox_status_after_restart = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("mailbox status after restart");
        "agent", "mailbox-status",
        "--apartment-name", "worker_agent",
        "--torii-url", &restart_torii_url,
    );
    let mailbox_status_after_restart_payload: Value =
        json::from_slice(&mailbox_status_after_restart.stdout).expect("mailbox status payload");
    assert_eq!(
        mailbox_status_after_restart_payload
            .get("pending_message_count")
            .and_then(Value::as_u64),
        Some(1)
    );
    let queued_messages = mailbox_status_after_restart_payload
        .get("messages")
        .and_then(Value::as_array)
        .expect("mailbox messages array");
    assert_eq!(queued_messages.len(), 1);
    assert_eq!(
        queued_messages[0].get("message_id").and_then(Value::as_str),
        Some(message_id.as_str())
    );
    let wallet_approve_after_restart = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("wallet approve after restart");
        "agent", "wallet-approve",
        "--apartment-name", "ops_agent",
        "--request-id", request_id,
        "--torii-url", &restart_torii_url,
    );
    let wallet_approve_after_restart_payload: Value =
        json::from_slice(&wallet_approve_after_restart.stdout).expect("wallet approve payload");
    assert_eq!(
        wallet_approve_after_restart_payload
            .get("pending_request_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    let message_ack_after_restart = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("message ack after restart");
        "agent", "message-ack",
        "--apartment-name", "worker_agent",
        "--message-id", message_id,
        "--torii-url", &restart_torii_url,
    );
    let message_ack_after_restart_payload: Value =
        json::from_slice(&message_ack_after_restart.stdout).expect("message ack payload");
    assert_eq!(
        message_ack_after_restart_payload
            .get("pending_message_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    let mailbox_status_empty = run_bounded_soracloud_success!(
        cli,
        SoracloudSuccessCase::new("mailbox status final check");
        "agent", "mailbox-status",
        "--apartment-name", "worker_agent",
        "--torii-url", &restart_torii_url,
    );
    let mailbox_status_empty_payload: Value =
        json::from_slice(&mailbox_status_empty.stdout).expect("mailbox status payload");
    assert_eq!(
        mailbox_status_empty_payload
            .get("pending_message_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    Ok(())
}
#[tokio::test]
async fn soracloud_agent_autonomy_control_commands_require_torii_url() -> eyre::Result<()> {
    let config = local_program_config();
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let mut manifest: AgentApartmentManifestV1 = norito::json::from_slice(&std::fs::read(
        soracloud_fixture("fixtures/soracloud/agent_apartment_manifest_v1.json"),
    )?)?;
    manifest
        .policy_capabilities
        .push("agent.autonomy.run".parse().expect("valid capability"));
    manifest.validate().expect("manifest should remain valid");
    let manifest_path = dir.path().join("agent_apartment_manifest.json");
    tokio::fs::write(
        &manifest_path,
        norito::json::to_vec_pretty(&manifest).expect("encode apartment manifest"),
    )
    .await?;
    let deploy = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "agent-deploy",
            "--manifest",
            &manifest_path.to_string_lossy(),
            "--autonomy-budget-units",
            "500",
        ],
    )
    .await?;
    assert_requires_torii_url(&deploy);
    let allow = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "agent-artifact-allow",
            "--apartment-name",
            "ops_agent",
            "--artifact-hash",
            "hash:ABCD0123#01",
            "--provenance-hash",
            "hash:PROV0001#01",
        ],
    )
    .await?;
    assert_requires_torii_url(&allow);
    let status = run_soracloud_command(
        dir.path(),
        &config,
        &["agent-autonomy-status", "--apartment-name", "ops_agent"],
    )
    .await?;
    assert_requires_torii_url(&status);
    let revoke = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "agent-policy-revoke",
            "--apartment-name",
            "ops_agent",
            "--capability",
            "agent.autonomy.run",
            "--reason",
            "manual-review",
        ],
    )
    .await?;
    assert_requires_torii_url(&revoke);
    Ok(())
}
#[tokio::test]
async fn soracloud_agent_wallet_and_mailbox_commands_require_torii_url() -> eyre::Result<()> {
    let config = local_program_config();
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let mut sender: AgentApartmentManifestV1 = norito::json::from_slice(&std::fs::read(
        soracloud_fixture("fixtures/soracloud/agent_apartment_manifest_v1.json"),
    )?)?;
    sender
        .policy_capabilities
        .push("agent.mailbox.send".parse().expect("valid capability"));
    sender
        .validate()
        .expect("sender manifest should remain valid");
    let mut recipient = sender.clone();
    recipient.apartment_name = "worker_agent".parse().expect("valid apartment name");
    recipient
        .policy_capabilities
        .retain(|capability| capability.as_ref() != "agent.mailbox.send");
    recipient
        .policy_capabilities
        .push("agent.mailbox.receive".parse().expect("valid capability"));
    recipient
        .validate()
        .expect("recipient manifest should remain valid");
    let sender_manifest_path = dir.path().join("sender_agent_manifest.json");
    let recipient_manifest_path = dir.path().join("recipient_agent_manifest.json");
    tokio::fs::write(
        &sender_manifest_path,
        norito::json::to_vec_pretty(&sender).expect("encode sender manifest"),
    )
    .await?;
    tokio::fs::write(
        &recipient_manifest_path,
        norito::json::to_vec_pretty(&recipient).expect("encode recipient manifest"),
    )
    .await?;
    let sender_deploy = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "agent-deploy",
            "--manifest",
            &sender_manifest_path.to_string_lossy(),
        ],
    )
    .await?;
    assert_requires_torii_url(&sender_deploy);
    let recipient_deploy = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "agent-deploy",
            "--manifest",
            &recipient_manifest_path.to_string_lossy(),
        ],
    )
    .await?;
    assert_requires_torii_url(&recipient_deploy);
    let wallet_request = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "agent-wallet-spend",
            "--apartment-name",
            "ops_agent",
            "--request-id",
            "requires-url-wallet-request-1",
            "--asset-definition",
            "61CtjvNd9T3THAR65GsMVHr82Bjc",
            "--amount",
            "0.001",
        ],
    )
    .await?;
    assert_requires_torii_url(&wallet_request);
    let wallet_approve = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "agent-wallet-approve",
            "--apartment-name",
            "ops_agent",
            "--request-id",
            "req-1",
        ],
    )
    .await?;
    assert_requires_torii_url(&wallet_approve);
    let wallet_revoke = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "agent-policy-revoke",
            "--apartment-name",
            "ops_agent",
            "--capability",
            "wallet.sign",
            "--reason",
            "rotated",
        ],
    )
    .await?;
    assert_requires_torii_url(&wallet_revoke);
    let message_send = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "agent-message-send",
            "--from-apartment",
            "ops_agent",
            "--to-apartment",
            "worker_agent",
            "--channel",
            "ops.sync",
            "--payload",
            "rotate-key-42",
        ],
    )
    .await?;
    assert_requires_torii_url(&message_send);
    let message_ack = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "agent-message-ack",
            "--apartment-name",
            "worker_agent",
            "--message-id",
            "msg-1",
        ],
    )
    .await?;
    assert_requires_torii_url(&message_ack);
    let mailbox_status = run_soracloud_command(
        dir.path(),
        &config,
        &["agent-mailbox-status", "--apartment-name", "worker_agent"],
    )
    .await?;
    assert_requires_torii_url(&mailbox_status);
    Ok(())
}
#[tokio::test]
async fn soracloud_agent_lease_commands_require_torii_url() -> eyre::Result<()> {
    let config = local_program_config();
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let manifest: AgentApartmentManifestV1 = norito::json::from_slice(&std::fs::read(
        soracloud_fixture("fixtures/soracloud/agent_apartment_manifest_v1.json"),
    )?)?;
    let manifest_path = dir.path().join("agent_apartment_manifest.json");
    tokio::fs::write(
        &manifest_path,
        norito::json::to_vec_pretty(&manifest).expect("encode apartment manifest"),
    )
    .await?;
    let deploy = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "agent-deploy",
            "--manifest",
            &manifest_path.to_string_lossy(),
            "--lease-blocks",
            "1",
        ],
    )
    .await?;
    assert_requires_torii_url(&deploy);
    let renew = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "agent-lease-renew",
            "--apartment-name",
            "ops_agent",
            "--lease-blocks",
            "20",
        ],
    )
    .await?;
    assert_requires_torii_url(&renew);
    let wallet = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "agent-wallet-spend",
            "--apartment-name",
            "ops_agent",
            "--request-id",
            "nested-requires-url-wallet-request-1",
            "--asset-definition",
            "61CtjvNd9T3THAR65GsMVHr82Bjc",
            "--amount",
            "0.000001",
        ],
    )
    .await?;
    assert_requires_torii_url(&wallet);
    let restart = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "agent-restart",
            "--apartment-name",
            "ops_agent",
            "--reason",
            "operator-check",
        ],
    )
    .await?;
    assert_requires_torii_url(&restart);
    let status = run_soracloud_command(
        dir.path(),
        &config,
        &["agent-status", "--apartment-name", "ops_agent"],
    )
    .await?;
    assert_requires_torii_url(&status);
    Ok(())
}
#[tokio::test]
async fn soracloud_hf_shared_lease_commands_require_torii_url() -> eyre::Result<()> {
    let config = local_program_config();
    let dir = tempfile::tempdir()?;
    tokio::fs::write(
        dir.path().join("client.toml"),
        toml::to_string(&config.toml())?.as_bytes(),
    )
    .await?;
    let lease_term_ms = "60000".to_string();
    let base_fee = canonical_quantity_literal_from_nanos(10_000);
    let lease_asset_definition = soracloud_hf_lease_asset_definition().to_string();
    let deploy = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-join",
            "--repo-id",
            "openai/gpt-oss",
            "--service-name",
            "hf_lease_a",
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--lease-asset-definition",
            lease_asset_definition.as_str(),
            "--base-fee",
            base_fee.as_str(),
        ],
    )
    .await?;
    assert_requires_torii_url(&deploy);
    let retired_base_fee_flag = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-join",
            "--repo-id",
            "openai/gpt-oss",
            "--service-name",
            "hf_lease_a",
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--lease-asset-definition",
            lease_asset_definition.as_str(),
            "--base-fee-nanos",
            "10000",
        ],
    )
    .await?;
    assert!(
        !retired_base_fee_flag.status.success(),
        "retired --base-fee-nanos flag must be rejected"
    );
    let retired_base_fee_stderr = String::from_utf8_lossy(&retired_base_fee_flag.stderr);
    assert!(
        retired_base_fee_stderr.contains("--base-fee-nanos")
            && retired_base_fee_stderr.contains("unexpected argument"),
        "unexpected retired flag stderr: {retired_base_fee_stderr}"
    );
    let status = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-status",
            "--repo-id",
            "openai/gpt-oss",
            "--lease-term-ms",
            lease_term_ms.as_str(),
        ],
    )
    .await?;
    assert_requires_torii_url(&status);
    let leave = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-lease-leave",
            "--repo-id",
            "openai/gpt-oss",
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--service-name",
            "hf_lease_a",
        ],
    )
    .await?;
    assert_requires_torii_url(&leave);
    let renew = run_soracloud_command(
        dir.path(),
        &config,
        &[
            "hf-lease-renew",
            "--repo-id",
            "openai/gpt-oss",
            "--service-name",
            "hf_lease_renew",
            "--lease-term-ms",
            lease_term_ms.as_str(),
            "--lease-asset-definition",
            lease_asset_definition.as_str(),
            "--base-fee",
            base_fee.as_str(),
        ],
    )
    .await?;
    assert_requires_torii_url(&renew);
    Ok(())
}
