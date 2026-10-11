//! Smoke tests that exercise the compiled `iroha` binary directly.
//!
//! These tests provide basic coverage that the CLI binary starts up, renders help text, and reports
//! the current version string. They help catch regression where the clap command tree fails to
//! build or the binary cannot launch in automated environments.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#[path = "cli_smoke/consensus_status.rs"]
mod consensus_status;
#[path = "cli_smoke/incentives_dispute.rs"]
mod incentives_dispute;
#[path = "cli_smoke/zk_ivm_jobs.rs"]
mod zk_ivm_jobs;
#[path = "cli_smoke/zk_memo.rs"]
mod zk_memo;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use blake3::hash;
use iroha::{
    account_address::{encode_account_id_to_canonical_hex, encode_account_id_to_i105},
    data_model::isi::{
        InstructionBox, TransferBox,
        repo::RepoInstructionBox,
        settlement::{SettlementAtomicity, SettlementInstructionBox},
    },
};
use iroha_crypto::{Algorithm, Hash as CryptoHash, KeyPair, Sm2PrivateKey};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    isi::oracle::AggregateOracleFeed,
    oracle::FeedId,
    soranet::incentives::{RelayBondLedgerEntryV1, RelayEpochMetricsV1, RelayRewardInstructionV1},
};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::numeric::{Quantity, XorQuantity};
use norito::{
    decode_from_bytes,
    derive::NoritoSerialize,
    json,
    json::{Map, Value},
    to_bytes,
};
use sorafs_orchestrator::treasury::{LedgerTransferRecord, TransferKind};
use std::{
    ffi::OsStr,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Output, Stdio},
    sync::LazyLock,
    thread,
    time::{Duration, Instant},
};
fn cli_binary() -> &'static str {
    env!("CARGO_BIN_EXE_iroha")
}
const ALICE_PUBLIC_KEY: &str =
    "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
const ALICE_PRIVATE_KEY: &str =
    "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53";
const BOB_PUBLIC_KEY: &str =
    "ed012004FF5B81046DDCCF19E2E451C45DFB6F53759D4EB30FA2EFA807284D1CC33016";
const MOCK_NETWORK_ID: &str =
    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0";
static ALICE_ACCOUNT_LITERAL: LazyLock<String> =
    LazyLock::new(|| account_literal_from_public_key(ALICE_PUBLIC_KEY));
static BOB_ACCOUNT_LITERAL: LazyLock<String> =
    LazyLock::new(|| account_literal_from_public_key(BOB_PUBLIC_KEY));
const SAMPLE_BUDGET_APPROVAL_ID: &str =
    "4f1a7b86d6c16245d9b5c0e9bd4732a6d01356f3172bbfa5ef5d9cde8790f221";
fn xor_asset_id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::try_new("sora", "universal").unwrap(),
        "xor".parse().unwrap(),
    )
}
fn xor_quantity_from_value(value: &Value) -> XorQuantity {
    let raw = value.as_str().expect("XOR quantity must be a JSON string");
    let quantity = raw.parse::<XorQuantity>().expect("canonical XOR quantity");
    assert_eq!(
        quantity.to_string(),
        raw,
        "XOR quantity must use its canonical exact decimal spelling"
    );
    quantity
}
fn assert_quantity_xor(amount: &Quantity, expected: &str) {
    let expected = expected
        .parse::<XorQuantity>()
        .expect("expected canonical XOR quantity")
        .into_quantity();
    assert_eq!(
        amount, &expected,
        "XOR quantity mismatch for amount {amount}"
    );
}
fn sample_reward_config_json() -> Value {
    let bond_asset_id = xor_asset_id().to_string();
    norito::json!({
        "policy": {
            "minimum_exit_bond": "1000",
            "bond_asset_id": bond_asset_id,
            "uptime_floor_per_mille": 900,
            "slash_penalty_basis_points": 250,
            "activation_grace_epochs": 0
        },
        "base_reward": "100",
        "uptime_weight_per_mille": 500,
        "bandwidth_weight_per_mille": 500,
        "compliance_penalty_basis_points": 0,
        "bandwidth_target_bytes": 1_000,
        "budget_approval_id": SAMPLE_BUDGET_APPROVAL_ID,
        "metrics_log_path": null
    })
}
fn fixture_key_pair_from_seed(seed: Vec<u8>) -> KeyPair {
    KeyPair::try_from_seed(seed, Algorithm::Ed25519)
        .expect("fixture seed must derive a valid keypair")
}
fn fixture_key_pair(seed: u8) -> KeyPair {
    fixture_key_pair_from_seed(vec![seed; 32])
}
fn account_id(name: &str) -> AccountId {
    let digest = hash(name.as_bytes());
    let mut seed = digest.as_bytes().to_vec();
    seed.resize(32, 0);
    let key_pair = fixture_key_pair_from_seed(seed);
    AccountId::new(key_pair.public_key().clone())
}
fn account_literal_from_public_key(public_key: &str) -> String {
    let public_key = public_key.parse().expect("public key");
    AccountId::new(public_key).to_string()
}
fn alice_account_literal() -> &'static str {
    ALICE_ACCOUNT_LITERAL.as_str()
}
fn bob_account_literal() -> &'static str {
    BOB_ACCOUNT_LITERAL.as_str()
}
fn account_literal(account: &AccountId) -> String {
    account.to_string()
}
fn account_literal_for(name: &str) -> String {
    let account = account_id(name);
    account_literal(&account)
}
fn parse_account_literal(literal: &str) -> AccountId {
    AccountId::parse_encoded(literal).expect("account literal should parse as encoded account id")
}
fn account_id_for_domain(_label: &str, seed: u8) -> AccountId {
    let key_pair = fixture_key_pair(seed);
    AccountId::new(key_pair.public_key().clone())
}
#[test]
fn fixture_key_pair_uses_checked_seed_derivation() {
    assert_eq!(fixture_key_pair(0x11).algorithm(), Algorithm::Ed25519);
    assert!(
        KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
        "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
    );
}
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("workspace root")
}
fn sample_metrics() -> RelayEpochMetricsV1 {
    RelayEpochMetricsV1 {
        relay_id: [0x11; 32],
        epoch: 7,
        uptime_seconds: 3_600,
        scheduled_uptime_seconds: 3_600,
        verified_bandwidth_bytes: 1_000,
        compliance: iroha_data_model::soranet::incentives::RelayComplianceStatusV1::Clean,
        reward_score: 0,
        confidence_floor_per_mille: 1_000,
        measurement_ids: Vec::new(),
        metadata: Metadata::default(),
    }
}
fn sample_bond_entry() -> RelayBondLedgerEntryV1 {
    RelayBondLedgerEntryV1 {
        relay_id: [0x11; 32],
        bonded_amount: Quantity::from(2_000_u32),
        bond_asset_id: xor_asset_id(),
        bonded_since_unix: 1,
        exit_capable: true,
    }
}
#[derive(Debug, NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "cli_smoke::TestLedgerExport",
    frame = "iroha::commands::sorafs::LedgerExportFile"
)]
struct TestLedgerExport {
    version: u16,
    transfers: Vec<LedgerTransferRecord>,
}
fn encode_ledger_export(export: &TestLedgerExport) -> Vec<u8> {
    to_bytes(export).expect("encode ledger export")
}

#[test]
fn ledger_export_fixture_declares_its_shared_frame_without_header_rewriting() {
    use norito::NoritoSchema as _;
    let export = TestLedgerExport {
        version: 1,
        transfers: Vec::new(),
    };
    let bytes = encode_ledger_export(&export);
    assert_eq!(
        TestLedgerExport::nominal_name(),
        "cli_smoke::TestLedgerExport"
    );
    assert_eq!(
        TestLedgerExport::frame_name(),
        "iroha::commands::sorafs::LedgerExportFile"
    );
    assert_ne!(
        TestLedgerExport::nominal_name(),
        TestLedgerExport::frame_name()
    );
    assert_eq!(
        &bytes[6..22],
        &norito::schema::identity::frame_hash::<TestLedgerExport>()
    );
    assert_eq!(bytes, to_bytes(&export).expect("canonical fixture frame"));
}
fn parse_instruction_stdout(stdout: &str) -> Vec<InstructionBox> {
    norito::json::from_str(stdout.trim()).expect("instruction output JSON")
}
fn repo_instruction(instruction: &InstructionBox) -> &RepoInstructionBox {
    instruction
        .as_any()
        .downcast_ref::<RepoInstructionBox>()
        .expect("repo instruction payload")
}
fn transfer_parts(instruction: &InstructionBox) -> (&AssetId, &Quantity, &AccountId) {
    let transfer_box = instruction
        .as_any()
        .downcast_ref::<TransferBox>()
        .expect("transfer instruction payload");
    match transfer_box {
        TransferBox::Asset(inner) => (&inner.source, &inner.object, &inner.destination),
        _ => panic!("expected asset transfer"),
    }
}
fn write_reward_config_file(dir: &torii_mock_support::TempDir) -> std::path::PathBuf {
    let config_path = dir.path().join("reward_config.json");
    let bytes = norito::json::to_vec(&sample_reward_config_json()).expect("encode config");
    fs::write(&config_path, bytes).expect("write config");
    config_path
}
#[test]
fn incentives_init_fails_without_budget_id() {
    let temp_dir = torii_mock_support::TempDir::new("incentives_missing_budget").expect("temp dir");
    let mut config = sample_reward_config_json();
    if let Some(object) = config.as_object_mut() {
        object.insert("budget_approval_id".to_string(), Value::Null);
    }
    let config_path = temp_dir.path().join("reward_config_missing.json");
    let bytes = norito::json::to_vec(&config).expect("encode config");
    fs::write(&config_path, bytes).expect("write config");
    let state_path = state_path(&temp_dir, "payout_state.json");
    let output = command()
        .args([
            "app",
            "sorafs",
            "incentives",
            "service",
            "init",
            "--state",
            state_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
            "--treasury-account",
            alice_account_literal(),
        ])
        .output()
        .expect("execute incentives service init");
    assert!(
        !output.status.success(),
        "init should fail when budget_approval_id is missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("budget_approval_id"),
        "stderr should mention missing budget_approval_id, got: {stderr}"
    );
}
fn write_metrics_file(
    dir: &torii_mock_support::TempDir,
    metrics: &RelayEpochMetricsV1,
) -> std::path::PathBuf {
    let file_name = format!("metrics-epoch-{}.to", metrics.epoch);
    let path = dir.path().join(file_name);
    let bytes = to_bytes(metrics).expect("encode metrics");
    fs::write(&path, bytes).expect("write metrics");
    path
}
fn write_bond_file(
    dir: &torii_mock_support::TempDir,
    bond: &RelayBondLedgerEntryV1,
) -> std::path::PathBuf {
    let path = dir.path().join("bond.to");
    let bytes = to_bytes(bond).expect("encode bond");
    fs::write(&path, bytes).expect("write bond");
    path
}
fn write_metrics_snapshot(dir: &Path, metrics: &RelayEpochMetricsV1, suffix: &str) -> PathBuf {
    let relay_hex = hex::encode(metrics.relay_id);
    let file_name = format!("relay-{}-epoch-{}-{}.to", relay_hex, metrics.epoch, suffix);
    let path = dir.join(file_name);
    let bytes = to_bytes(metrics).expect("encode metrics snapshot");
    fs::write(&path, bytes).expect("write metrics snapshot");
    path
}
fn proposal_id_hex(contract_address: &str, code: &[u8; 32], abi: &[u8; 32]) -> String {
    use iroha_data_model::governance::types::{
        AbiVersion, ContractAbiHash, ContractCodeHash, DeployContractProposal, ProposalKind,
    };
    let proposal = ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator: parse_account_literal(alice_account_literal()),
        contract_address: contract_address
            .parse()
            .expect("canonical contract address"),
        code_hash: ContractCodeHash::new(*code),
        abi_hash: ContractAbiHash::new(*abi),
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    });
    hex::encode(proposal.fingerprint())
}
fn write_daemon_config(
    dir: &torii_mock_support::TempDir,
    relay_hex: &str,
    beneficiary: &str,
    bond_path: &Path,
) -> PathBuf {
    let config_path = dir.path().join("daemon_config.json");
    let mut relay_entry = Map::new();
    relay_entry.insert("relay_id".to_string(), Value::String(relay_hex.to_string()));
    relay_entry.insert(
        "beneficiary".to_string(),
        Value::String(beneficiary.to_string()),
    );
    relay_entry.insert(
        "bond_path".to_string(),
        Value::String(bond_path.to_string_lossy().into_owned()),
    );
    let mut root = Map::new();
    root.insert(
        "relays".to_string(),
        Value::Array(vec![Value::Object(relay_entry)]),
    );
    let config_json = Value::Object(root);
    let bytes = norito::json::to_vec(&config_json).expect("encode daemon config");
    fs::write(&config_path, bytes).expect("write daemon config");
    config_path
}
fn state_path(dir: &torii_mock_support::TempDir, name: &str) -> std::path::PathBuf {
    dir.path().join(name)
}
fn read_state(path: &std::path::Path) -> Value {
    let bytes = fs::read(path).expect("read incentives state");
    norito::json::from_slice(&bytes).expect("decode incentives state")
}
fn settlement_instruction(instruction: &InstructionBox) -> &SettlementInstructionBox {
    instruction
        .as_any()
        .downcast_ref::<SettlementInstructionBox>()
        .expect("settlement instruction payload")
}
const CLI_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const CLI_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(10);
struct TestCommand {
    inner: Command,
    timeout: Duration,
}
impl TestCommand {
    fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            inner: Command::new(program),
            timeout: CLI_COMMAND_TIMEOUT,
        }
    }
    fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.inner.arg(arg);
        self
    }
    fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.inner.args(args);
        self
    }
    fn current_dir(&mut self, dir: impl AsRef<Path>) -> &mut Self {
        self.inner.current_dir(dir);
        self
    }
    fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Self {
        self.inner.env(key, value);
        self
    }
    fn output(&mut self) -> io::Result<Output> {
        self.inner
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = self.inner.spawn()?;
        let stdout = child.stdout.take().map(read_pipe);
        let stderr = child.stderr.take().map(read_pipe);
        let Some(status) = wait_for_exit(&mut child, self.timeout)? else {
            let _ = child.kill();
            let _ = child.wait();
            let _ = join_pipe(stdout);
            let _ = join_pipe(stderr);
            return Err(command_timeout_error(&self.inner, self.timeout));
        };
        Ok(Output {
            status,
            stdout: join_pipe(stdout),
            stderr: join_pipe(stderr),
        })
    }
    fn status(&mut self) -> io::Result<ExitStatus> {
        self.inner.stdin(Stdio::null());
        let mut child = self.inner.spawn()?;
        let Some(status) = wait_for_exit(&mut child, self.timeout)? else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(command_timeout_error(&self.inner, self.timeout));
        };
        Ok(status)
    }
}
fn read_pipe<R>(mut pipe: R) -> thread::JoinHandle<Vec<u8>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.read_to_end(&mut bytes);
        bytes
    })
}
fn join_pipe(handle: Option<thread::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default()
}
fn wait_for_exit(
    child: &mut std::process::Child,
    timeout: Duration,
) -> io::Result<Option<ExitStatus>> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Ok(None);
        }
        thread::sleep(CLI_COMMAND_POLL_INTERVAL.min(timeout - elapsed));
    }
}
fn command_timeout_error(command: &Command, timeout: Duration) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("command {command:?} timed out after {timeout:?}"),
    )
}
fn command() -> TestCommand {
    let mut cmd = TestCommand::new(cli_binary());
    // Disable ANSI color codes so the assertions can match plain text.
    cmd.env("NO_COLOR", "1");
    cmd.env("CLICOLOR", "0");
    cmd
}
#[test]
fn taira_doctor_bypasses_default_and_explicit_client_config_loading() {
    let temp_dir =
        torii_mock_support::TempDir::new("taira_doctor_configless").expect("temp directory");
    let malformed_config = temp_dir.path().join("malformed-client.toml");
    fs::write(&malformed_config, b"this is not = [valid toml")
        .expect("write malformed client config");

    for config in [None, Some(malformed_config.as_path())] {
        let mut cmd = command();
        cmd.current_dir(temp_dir.path()).arg("--machine");
        if let Some(config) = config {
            cmd.arg("--config").arg(config);
        }
        let output = cmd
            .args([
                "taira",
                "doctor",
                "--public-root",
                "ftp://taira.invalid",
                "--json",
            ])
            .output()
            .expect("run configless Taira doctor");
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty(), "command errors belong on stderr");
        let error: Value =
            json::from_slice(&output.stderr).expect("decode machine-mode error JSON");
        assert_eq!(
            error.pointer("/error/kind").and_then(Value::as_str),
            Some("command")
        );
        assert_eq!(
            error.pointer("/error/exit_code").and_then(Value::as_u64),
            Some(1)
        );
        let mut chain = vec![
            error
                .pointer("/error/message")
                .and_then(Value::as_str)
                .expect("error message")
                .to_owned(),
        ];
        chain.extend(
            error
                .pointer("/error/causes")
                .and_then(Value::as_array)
                .expect("error causes")
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
        let chain = chain.join("\n");
        assert!(chain.contains("unsupported URL scheme `ftp`"), "{chain}");
        assert!(!chain.contains("Failed to load config"));
    }
}
#[test]
fn taira_mutation_commands_remain_config_required() {
    let temp_dir =
        torii_mock_support::TempDir::new("taira_mutations_require_config").expect("temp directory");
    for command_args in [
        vec![
            "taira",
            "write-canary",
            "--operation",
            "onboarding",
            "--onboarding-token-file",
            "missing.token",
            "--json",
        ],
        vec![
            "taira",
            "inrou-canary",
            "--stage-dir",
            "missing-stage",
            "--mode",
            "deploy",
            "--operation",
            "bundle-pin",
            "--json",
        ],
    ] {
        let output = command()
            .current_dir(temp_dir.path())
            .arg("--machine")
            .args(command_args)
            .args([
                "--authorization-sha256",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "--authorization-nonce",
                "cccccccccccccccccccccccccccccccc",
                "--mutation-phase",
                "pre_edge",
                "--idempotency-key",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--execution-expires-at-unix-ms",
                "2000000000000",
                "--prepare-envelope",
                "--prepared-output-fd",
                "3",
            ])
            .output()
            .expect("run config-required Taira mutation command");
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stdout.is_empty(), "config errors belong on stderr");
        let error: Value =
            json::from_slice(&output.stderr).expect("decode machine-mode error JSON");
        assert_eq!(
            error.pointer("/error/kind").and_then(Value::as_str),
            Some("config")
        );
        assert_eq!(
            error.pointer("/error/exit_code").and_then(Value::as_u64),
            Some(3)
        );
    }
}
#[test]
fn taira_doctor_rejects_irrelevant_transaction_and_signing_globals() {
    let output = command()
        .args([
            "--machine",
            "--verbose",
            "--fee-payer",
            "authority",
            "taira",
            "doctor",
            "--public-root",
            "ftp://taira.invalid",
        ])
        .output()
        .expect("run Taira doctor with irrelevant globals");
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty(), "input errors belong on stderr");
    let error: Value = json::from_slice(&output.stderr).expect("decode machine-mode error JSON");
    assert_eq!(
        error.pointer("/error/kind").and_then(Value::as_str),
        Some("input")
    );
    let message = error
        .pointer("/error/message")
        .and_then(Value::as_str)
        .expect("error message");
    assert!(message.contains("--verbose"));
    assert!(message.contains("--fee-payer"));
}
#[test]
fn soracles_aggregate_output_emits_instruction_payload() {
    use torii_mock_support::{TempDir, write_client_config};
    let temp_dir = TempDir::new("soracles_aggregate").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, "http://localhost").expect("write config");
    let request_hash = CryptoHash::new(b"soracles-cli-smoke-request");
    let evidence_hash = CryptoHash::new(b"soracles-cli-smoke-evidence");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .arg("--emit-instructions")
        .args([
            "app",
            "soracles",
            "tx",
            "aggregate",
            "--feed-id",
            "cli_smoke_feed",
            "--slot",
            "42",
            "--request-hash",
            &request_hash.to_string(),
            "--evidence-hash",
            &evidence_hash.to_string(),
        ])
        .output()
        .expect("execute soracles aggregate output command");
    assert!(
        output.status.success(),
        "soracles aggregate --output failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let instructions = parse_instruction_stdout(&stdout);
    assert_eq!(instructions.len(), 1);
    let aggregate = instructions[0]
        .as_any()
        .downcast_ref::<AggregateOracleFeed>()
        .expect("aggregate oracle instruction payload");
    let expected_feed: FeedId = "cli_smoke_feed".parse().expect("feed id");
    assert_eq!(aggregate.feed_id, expected_feed);
    assert_eq!(aggregate.slot, 42);
    assert_eq!(aggregate.request_hash, request_hash);
    assert_eq!(aggregate.evidence_hashes, vec![evidence_hash]);
}
#[test]
fn help_displays_top_level_usage() {
    let output = command()
        .arg("--help")
        .output()
        .expect("failed to execute iroha --help");
    assert!(
        output.status.success(),
        "expected --help to succeed, got status {:?} with stderr {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USAGE") || stdout.contains("Usage"),
        "help output did not contain a usage section: {stdout}"
    );
    assert!(
        stdout.contains("iroha [OPTIONS] <COMMAND>"),
        "unexpected help synopsis: {stdout}"
    );
}
#[test]
fn version_matches_package_metadata() {
    let output = command()
        .arg("--version")
        .output()
        .expect("failed to execute iroha --version");
    assert!(
        output.status.success(),
        "expected --version to succeed, got status {:?} with stderr {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected_version = env!("CARGO_PKG_VERSION");
    assert!(
        stdout.contains(expected_version),
        "version output `{stdout}` did not contain crate version {expected_version}"
    );
}
fn expect_subcommand_help(args: &[&str], expected_snippet: &str) {
    let output = command()
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to execute iroha {args:?}: {err}"));
    assert!(
        output.status.success(),
        "expected iroha {:?} to succeed, got status {:?} with stderr {}",
        args,
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(expected_snippet),
        "help output for {args:?} missing `{expected_snippet}`\nstdout:{stdout}"
    );
}
#[test]
fn multisig_help_is_accessible() {
    expect_subcommand_help(
        &["ledger", "multisig", "--help"],
        "Register a multisig account",
    );
}
#[test]
fn gov_help_lists_commands() {
    expect_subcommand_help(
        &["app", "gov", "--help"],
        "Propose deployment of IVM bytecode",
    );
}
#[test]
fn sorafs_fetch_help_is_accessible() {
    expect_subcommand_help(
        &["app", "sorafs", "fetch", "--help"],
        "Orchestrate multi-provider chunk fetches",
    );
}
#[test]
fn sorafs_repair_help_is_accessible() {
    expect_subcommand_help(
        &["app", "sorafs", "repair", "--help"],
        "Repair queue helpers",
    );
}
#[test]
fn sorafs_gc_help_is_accessible() {
    expect_subcommand_help(&["app", "sorafs", "gc", "--help"], "GC inspection helpers");
}
#[test]
fn sorafs_reserve_quote_outputs_breakdown() {
    let output = command()
        .args([
            "app",
            "sorafs",
            "reserve",
            "quote",
            "--storage-class",
            "hot",
            "--tier",
            "tier-a",
            "--duration",
            "monthly",
            "--gib",
            "10",
            "--reserve-balance",
            "1.5",
        ])
        .output()
        .expect("failed to execute sorafs reserve quote");
    assert!(
        output.status.success(),
        "reserve quote failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value =
        norito::json::from_str(stdout.trim()).expect("reserve quote should return JSON");
    let inputs = value
        .get("inputs")
        .and_then(Value::as_object)
        .expect("inputs object");
    assert_eq!(inputs.get("tier").and_then(Value::as_str), Some("tier-a"));
    let quote = value
        .get("quote")
        .and_then(Value::as_object)
        .expect("quote object");
    let rent_raw = quote.get("monthly_rent").expect("monthly_rent present");
    assert_eq!(
        xor_quantity_from_value(rent_raw),
        "120".parse::<XorQuantity>().expect("canonical quantity")
    );
}
#[test]
fn sorafs_reserve_ledger_emits_instructions() {
    use torii_mock_support::TempDir;
    let temp_dir = TempDir::new("sorafs_reserve_ledger").expect("temp dir");
    let quote_path = temp_dir.path().join("reserve_quote.json");
    let quote_arg = quote_path.to_str().expect("utf8 path");
    let quote_status = command()
        .args([
            "app",
            "sorafs",
            "reserve",
            "quote",
            "--storage-class",
            "hot",
            "--tier",
            "tier-a",
            "--duration",
            "monthly",
            "--gib",
            "10",
            "--quote-out",
            quote_arg,
        ])
        .status()
        .expect("execute sorafs reserve quote");
    assert!(quote_status.success(), "reserve quote command failed");
    let reserve_account = account_id("reserve-sorafs");
    let reserve_account_label = account_literal(&reserve_account);
    let asset_definition_arg = xor_asset_id().to_string();
    let provider_account = parse_account_literal(alice_account_literal());
    let treasury_account = parse_account_literal(bob_account_literal());
    let output = command()
        .args([
            "app",
            "sorafs",
            "reserve",
            "ledger",
            "--quote",
            quote_arg,
            "--provider-account",
            alice_account_literal(),
            "--treasury-account",
            bob_account_literal(),
            "--reserve-account",
            &reserve_account_label,
            "--asset-definition",
            &asset_definition_arg,
        ])
        .output()
        .expect("execute sorafs reserve ledger");
    assert!(
        output.status.success(),
        "reserve ledger failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let plan: Value =
        norito::json::from_str(stdout.trim()).expect("reserve ledger output should be JSON");
    let rent_due = plan
        .get("rent_due")
        .map(xor_quantity_from_value)
        .expect("rent due present");
    assert_eq!(
        rent_due,
        "120".parse::<XorQuantity>().expect("canonical quantity")
    );
    let reserve_shortfall = plan
        .get("reserve_shortfall")
        .map(xor_quantity_from_value)
        .expect("reserve shortfall present");
    assert_eq!(
        reserve_shortfall,
        "240".parse::<XorQuantity>().expect("canonical quantity")
    );
    assert!(
        plan.get("rent_due_micro_xor").is_none()
            && plan.get("reserve_shortfall_micro_xor").is_none(),
        "retired implicit-unit aliases must not be emitted"
    );
    let instructions_value = plan
        .get("instructions")
        .and_then(Value::as_array)
        .expect("instructions array");
    assert_eq!(instructions_value.len(), 2, "two transfers expected");
    let instruction_bytes =
        norito::json::to_vec(instructions_value).expect("serialize instructions array");
    let instructions: Vec<InstructionBox> =
        norito::json::from_slice(&instruction_bytes).expect("decode instruction array");
    assert_eq!(instructions.len(), 2);
    let (rent_source, rent_amount_numeric, rent_destination) = transfer_parts(&instructions[0]);
    assert_eq!(
        rent_source,
        &AssetId::new(xor_asset_id(), provider_account.clone())
    );
    assert_eq!(rent_destination, &treasury_account);
    assert_quantity_xor(rent_amount_numeric, "120");
    let (reserve_source, reserve_amount_numeric, reserve_destination) =
        transfer_parts(&instructions[1]);
    assert_eq!(
        reserve_source,
        &AssetId::new(xor_asset_id(), provider_account.clone())
    );
    assert_eq!(reserve_destination, &reserve_account);
    assert_quantity_xor(reserve_amount_numeric, "240");
}
#[test]
fn sorafs_reserve_lifecycle_projects_credit_draw() {
    use torii_mock_support::TempDir;
    let temp_dir = TempDir::new("sorafs_reserve_lifecycle").expect("temp dir");
    let quote_path = temp_dir.path().join("reserve_quote.json");
    let quote_arg = quote_path.to_str().expect("utf8 path");
    let quote_status = command()
        .args([
            "app",
            "sorafs",
            "reserve",
            "quote",
            "--storage-class",
            "hot",
            "--tier",
            "tier-a",
            "--duration",
            "monthly",
            "--gib",
            "10",
            "--quote-out",
            quote_arg,
        ])
        .status()
        .expect("execute sorafs reserve quote");
    assert!(quote_status.success(), "reserve quote command failed");
    let output = command()
        .args([
            "app",
            "sorafs",
            "reserve",
            "lifecycle",
            "--quote",
            quote_arg,
            "--days-past-due",
            "3",
        ])
        .output()
        .expect("execute sorafs reserve lifecycle");
    assert!(
        output.status.success(),
        "reserve lifecycle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lifecycle: Value =
        norito::json::from_str(stdout.trim()).expect("reserve lifecycle output should be JSON");
    assert_eq!(
        lifecycle.get("stage").and_then(Value::as_str),
        Some("grace")
    );
    assert_eq!(
        lifecycle
            .get("credit_draw")
            .map(xor_quantity_from_value)
            .expect("credit draw present"),
        "120".parse::<XorQuantity>().expect("canonical quantity")
    );
    assert_eq!(
        lifecycle
            .get("credit_shortfall")
            .map(xor_quantity_from_value)
            .expect("credit shortfall present"),
        XorQuantity::zero()
    );
    assert!(
        lifecycle.get("credit_draw_micro_xor").is_none()
            && lifecycle.get("credit_shortfall_micro_xor").is_none(),
        "retired implicit-unit aliases must not be emitted"
    );
    assert_eq!(
        lifecycle.get("disable_adverts").and_then(Value::as_bool),
        Some(false)
    );
}
#[test]
fn sorafs_reserve_help_lists_local_projection_commands() {
    let output = command()
        .args(["app", "sorafs", "reserve", "--help"])
        .output()
        .expect("execute sorafs reserve help");
    assert!(
        output.status.success(),
        "reserve help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in ["quote", "ledger", "lifecycle"] {
        assert!(
            stdout.contains(expected),
            "reserve help did not include `{expected}`:\n{stdout}"
        );
    }
}
#[test]
fn da_get_help_is_accessible() {
    expect_subcommand_help(
        &["app", "da", "get", "--help"],
        "Fetch blobs via the multi-source orchestrator",
    );
}
#[test]
fn gov_protected_set_produces_instruction_skeleton() {
    use torii_mock_support::{TempDir, write_client_config};
    let temp_dir = TempDir::new("gov_protected_set").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, "http://localhost").expect("write config");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .args(["app", "gov", "protected", "set", "--namespaces", "apps"])
        .output()
        .expect("failed to execute iroha app gov protected set");
    assert!(
        output.status.success(),
        "protected set failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: norito::json::Value =
        norito::json::from_str(stdout.trim()).expect("parse protected set output");
    let instructions = value
        .get("tx_instructions")
        .and_then(|v| v.as_array())
        .expect("tx_instructions array");
    assert_eq!(
        instructions.len(),
        1,
        "expected single instruction skeleton"
    );
    let entry = &instructions[0];
    assert!(entry.get("wire_id").is_some(), "wire_id missing");
    assert!(entry.get("payload_hex").is_some(), "payload_hex missing");
}
#[test]
fn gov_deploy_meta_outputs_metadata_stub() {
    use torii_mock_support::{TempDir, write_client_config};
    let temp_dir = TempDir::new("gov_deploy_meta").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, "http://localhost").expect("write config");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "gov",
            "deploy",
            "meta",
            "--contract-address",
            "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        ])
        .output()
        .expect("failed to execute iroha app gov deploy meta");
    assert!(
        output.status.success(),
        "deploy meta failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: norito::json::Value =
        norito::json::from_str(stdout.trim()).expect("parse deploy meta output");
    assert_eq!(
        value.get("gov_contract_address").and_then(|v| v.as_str()),
        Some("irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw")
    );
    assert!(
        value.get("gov_manifest_approvers").is_none(),
        "unexpected manifest approvers: {value:?}"
    );
}
#[test]
fn gov_deploy_meta_accepts_manifest_approvers() {
    use torii_mock_support::{TempDir, write_client_config};
    let temp_dir = TempDir::new("gov_deploy_meta_approvers").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, "http://localhost").expect("write config");
    let validator = account_literal_for("validator");
    let bob = account_literal_for("bob");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "gov",
            "deploy",
            "meta",
            "--contract-address",
            "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        ])
        .args(["--approver", validator.as_str(), "--approver", bob.as_str()])
        .output()
        .expect("failed to execute iroha app gov deploy meta");
    assert!(
        output.status.success(),
        "deploy meta failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: norito::json::Value =
        norito::json::from_str(stdout.trim()).expect("parse deploy meta output");
    let approvers = value
        .get("gov_manifest_approvers")
        .and_then(|v| v.as_array())
        .expect("approvers array");
    let collected: Vec<_> = approvers
        .iter()
        .map(|entry| entry.as_str().unwrap_or(""))
        .collect();
    assert_eq!(collected, vec![validator.as_str(), bob.as_str()]);
}
#[test]
fn gov_propose_deploy_against_mock() {
    use iroha_data_model::{
        governance::types::{
            AbiVersion, ContractAbiHash, ContractCodeHash, DeployContractProposal, ProposalKind,
        },
        isi::governance::ProposeDeployContract,
    };
    use torii_mock_support::{
        SpawnError, TempDir, ToriiMockProcess, configure_governance, write_client_config,
    };
    let mock = match ToriiMockProcess::spawn() {
        Ok(proc) => proc,
        Err(SpawnError::PythonUnavailable | SpawnError::PermissionDenied) => {
            eprintln!("skipping gov_propose_deploy_against_mock: mock server unavailable");
            return;
        }
        Err(err) => panic!("failed to start Torii mock: {err}"),
    };
    let code_hash_bytes = [0x00; 32];
    let abi_hash_bytes = [0x11; 32];
    let contract_address: iroha_data_model::smart_contract::ContractAddress =
        "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
            .parse()
            .expect("contract address");
    let proposal = ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator: parse_account_literal(alice_account_literal()),
        contract_address: contract_address.clone(),
        code_hash: ContractCodeHash::new(code_hash_bytes),
        abi_hash: ContractAbiHash::new(abi_hash_bytes),
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    });
    let proposal_id = hex::encode(proposal.fingerprint());
    let instruction: iroha_data_model::isi::InstructionBox = ProposeDeployContract {
        contract_address: contract_address.clone(),
        code_hash: ContractCodeHash::new(code_hash_bytes),
        abi_hash: ContractAbiHash::new(abi_hash_bytes),
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    }
    .into();
    let (wire_id, framed) = iroha_data_model::isi::framed_instruction_payload(&instruction)
        .expect("frame deploy proposal instruction");
    let wire_id = wire_id.to_owned();
    let payload_hex = hex::encode(framed);
    let mut config_payload_map = json::Map::new();
    config_payload_map.insert("referenda".to_string(), json::Value::Array(Vec::new()));
    let mut response_map = json::Map::new();
    response_map.insert(
        "proposal_id".to_string(),
        json::Value::String(proposal_id.clone()),
    );
    response_map.insert(
        "tx_instructions".to_string(),
        norito::json!([{
            "wire_id": wire_id,
            "payload_hex": payload_hex,
        }]),
    );
    config_payload_map.insert(
        "propose_deploy_response".to_string(),
        json::Value::Object(response_map),
    );
    let config_payload = json::Value::Object(config_payload_map);
    configure_governance(mock.base_url(), &config_payload).expect("configure governance");
    let temp_dir = TempDir::new("gov_propose_deploy").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, mock.base_url()).expect("write config");
    let code_hash = hex::encode(code_hash_bytes);
    let abi_hash = hex::encode(abi_hash_bytes);
    let contract_address = contract_address.to_string();
    let summary = command()
        .arg("--config")
        .arg(&config_path)
        .arg("--output-format")
        .arg("text")
        .args([
            "app",
            "gov",
            "deploy",
            "propose",
            "--contract-address",
            contract_address.as_str(),
            "--code-hash",
            code_hash.as_str(),
            "--abi-hash",
            abi_hash.as_str(),
        ])
        .output()
        .expect("invoke iroha app gov deploy propose --output-format text");
    assert!(
        summary.status.success(),
        "expected deploy propose summary to succeed, stderr: {}",
        String::from_utf8_lossy(&summary.stderr)
    );
    let summary_out = String::from_utf8_lossy(&summary.stdout);
    assert_eq!(
        summary_out.trim_end(),
        format!("deploy propose: proposal_id={proposal_id}")
    );
    let json_output = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "gov",
            "deploy",
            "propose",
            "--contract-address",
            contract_address.as_str(),
            "--code-hash",
            code_hash.as_str(),
            "--abi-hash",
            abi_hash.as_str(),
        ])
        .output()
        .expect("invoke iroha app gov deploy propose");
    assert!(
        json_output.status.success(),
        "expected deploy propose JSON to succeed, stderr: {}",
        String::from_utf8_lossy(&json_output.stderr)
    );
    let value: norito::json::Value =
        norito::json::from_slice(&json_output.stdout).expect("parse deploy propose JSON");
    assert!(value.get("ok").is_none());
    assert_eq!(
        value
            .get("proposal_id")
            .and_then(norito::json::Value::as_str),
        Some(proposal_id.as_str())
    );
}
#[test]
fn gov_protected_namespaces_flow_against_mock() {
    use torii_mock_support::{
        SpawnError, TempDir, ToriiMockProcess, configure_governance, write_client_config,
    };
    let mock = match ToriiMockProcess::spawn() {
        Ok(proc) => proc,
        Err(SpawnError::PythonUnavailable | SpawnError::PermissionDenied) => {
            eprintln!(
                "skipping gov_protected_namespaces_flow_against_mock: mock server unavailable"
            );
            return;
        }
        Err(err) => panic!("failed to start Torii mock: {err}"),
    };
    let config_payload = norito::json!({
        "protected_namespaces": {
            "found": true,
            "namespaces": ["apps"]
        }
    });
    configure_governance(mock.base_url(), &config_payload).expect("configure governance");
    let temp_dir = TempDir::new("gov_protected_flow").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, mock.base_url()).expect("write config");
    let initial = command()
        .arg("--config")
        .arg(&config_path)
        .args(["app", "gov", "protected", "get"])
        .output()
        .expect("invoke iroha app gov protected get");
    assert!(
        initial.status.success(),
        "expected protected get to succeed, stderr: {}",
        String::from_utf8_lossy(&initial.stderr)
    );
    let initial_value: norito::json::Value =
        norito::json::from_slice(&initial.stdout).expect("parse protected get");
    assert_eq!(
        initial_value
            .get("namespaces")
            .and_then(norito::json::Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    let apply = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "gov",
            "protected",
            "apply",
            "--namespaces",
            "apps,system",
        ])
        .output()
        .expect("invoke iroha app gov protected apply");
    assert!(
        apply.status.success(),
        "expected protected apply to succeed, stderr: {}",
        String::from_utf8_lossy(&apply.stderr)
    );
    let apply_value: norito::json::Value =
        norito::json::from_slice(&apply.stdout).expect("parse protected apply JSON");
    assert_eq!(
        apply_value
            .get("applied")
            .and_then(norito::json::Value::as_u64),
        Some(2)
    );
    let after = command()
        .arg("--config")
        .arg(&config_path)
        .args(["app", "gov", "protected", "get"])
        .output()
        .expect("invoke iroha app gov protected get after apply");
    assert!(
        after.status.success(),
        "expected protected get after apply to succeed, stderr: {}",
        String::from_utf8_lossy(&after.stderr)
    );
    let after_value: norito::json::Value =
        norito::json::from_slice(&after.stdout).expect("parse protected get JSON");
    let namespaces = after_value
        .get("namespaces")
        .and_then(norito::json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let collected: Vec<_> = namespaces
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    assert_eq!(collected, vec!["apps", "system"]);
}
#[test]
fn retired_server_contract_deployment_commands_are_absent() {
    for args in [
        vec!["contract", "deploy"],
        vec!["contract", "app", "plan"],
        vec!["contract", "app", "deploy"],
        vec!["contract", "app", "resume"],
        vec!["contract", "dev", "deploy"],
        vec!["contract", "dev", "resume"],
    ] {
        let output = command()
            .args(&args)
            .output()
            .expect("invoke retired contract deployment command");
        assert!(
            !output.status.success(),
            "retired contract deployment command remained available: {args:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"),
            "retired command failed for an unexpected reason: {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
#[test]
#[allow(clippy::too_many_lines)]
fn gov_governance_queries_against_mock() {
    use torii_mock_support::{
        SpawnError, TempDir, ToriiMockProcess, configure_governance, write_client_config,
    };
    let mock = match ToriiMockProcess::spawn() {
        Ok(proc) => proc,
        Err(SpawnError::PythonUnavailable | SpawnError::PermissionDenied) => {
            eprintln!("skipping gov_governance_queries_against_mock: mock server unavailable");
            return;
        }
        Err(err) => panic!("failed to start Torii mock: {err}"),
    };
    let proposal_id =
        "feedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed".to_string();
    let proposal_key = proposal_id.to_lowercase();
    let mut proposal_payload = json::Map::new();
    proposal_payload.insert("found".to_string(), json::Value::Bool(true));
    let mut proposal_status = json::Map::new();
    proposal_status.insert(
        "status".to_string(),
        json::Value::String("Approved".to_string()),
    );
    proposal_payload.insert("proposal".to_string(), json::Value::Object(proposal_status));
    let mut proposals_map = json::Map::new();
    proposals_map.insert(proposal_key.clone(), json::Value::Object(proposal_payload));
    let referenda = json::Value::Array(vec![norito::json!({
        "id": "ref-plain",
        "referendum": {
            "id": "ref-plain",
            "mode": "Plain",
            "status": "Open"
        }
    })]);
    let mut lock_accounts = json::Map::new();
    lock_accounts.insert(
        alice_account_literal().to_string(),
        norito::json!({
            "amount": "500",
            "expiry_height": 10,
            "direction": 0
        }),
    );
    let locks = norito::json!({
        "ref-plain": {
            "found": true,
            "referendum_id": "ref-plain",
            "locks": {
                "locks": lock_accounts
            }
        }
    });
    let tallies = norito::json!({
        "ref-plain": {
            "referendum_id": "ref-plain",
            "approve": 5,
            "reject": 2,
            "abstain": 1
        }
    });
    let unlock_stats = norito::json!({
        "height_current": 100,
        "expired_locks_now": 3,
        "referenda_with_expired": 2,
        "last_sweep_height": 90
    });
    let mut config_payload_map = json::Map::new();
    config_payload_map.insert("referenda".to_string(), referenda);
    config_payload_map.insert("proposals".to_string(), json::Value::Object(proposals_map));
    config_payload_map.insert("locks".to_string(), locks);
    config_payload_map.insert("tallies".to_string(), tallies);
    config_payload_map.insert("unlock_stats".to_string(), unlock_stats);
    let config_payload = json::Value::Object(config_payload_map);
    configure_governance(mock.base_url(), &config_payload).expect("configure governance");
    let temp_dir = TempDir::new("gov_queries").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, mock.base_url()).expect("write config");
    let proposal = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "gov",
            "proposal",
            "get",
            "--id",
            proposal_id.as_str(),
        ])
        .output()
        .expect("invoke iroha app gov proposal get");
    assert!(
        proposal.status.success(),
        "expected proposal get to succeed, stderr: {}",
        String::from_utf8_lossy(&proposal.stderr)
    );
    let proposal_value: norito::json::Value =
        norito::json::from_slice(&proposal.stdout).expect("parse proposal get JSON");
    assert_eq!(
        proposal_value
            .get("found")
            .and_then(norito::json::Value::as_bool),
        Some(true)
    );
    let locks = command()
        .arg("--config")
        .arg(&config_path)
        .args(["app", "gov", "locks", "get", "--referendum-id", "ref-plain"])
        .output()
        .expect("invoke iroha app gov locks get");
    assert!(
        locks.status.success(),
        "expected locks get to succeed, stderr: {}",
        String::from_utf8_lossy(&locks.stderr)
    );
    let locks_value: norito::json::Value =
        norito::json::from_slice(&locks.stdout).expect("parse locks get JSON");
    assert_eq!(
        locks_value
            .get("referendum_id")
            .and_then(norito::json::Value::as_str),
        Some("ref-plain")
    );
    let referendum = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "gov",
            "referendum",
            "get",
            "--referendum-id",
            "ref-plain",
        ])
        .output()
        .expect("invoke iroha app gov referendum get");
    assert!(
        referendum.status.success(),
        "expected referendum get to succeed, stderr: {}",
        String::from_utf8_lossy(&referendum.stderr)
    );
    let tally = command()
        .arg("--config")
        .arg(&config_path)
        .args(["app", "gov", "tally", "get", "--referendum-id", "ref-plain"])
        .output()
        .expect("invoke iroha app gov tally get");
    assert!(
        tally.status.success(),
        "expected tally get to succeed, stderr: {}",
        String::from_utf8_lossy(&tally.stderr)
    );
    let tally_value: norito::json::Value =
        norito::json::from_slice(&tally.stdout).expect("parse tally get JSON");
    assert_eq!(
        tally_value
            .get("approve")
            .and_then(norito::json::Value::as_u64),
        Some(5)
    );
    let unlocks = command()
        .arg("--config")
        .arg(&config_path)
        .args(["app", "gov", "unlock", "stats"])
        .output()
        .expect("invoke iroha app gov unlock stats");
    assert!(
        unlocks.status.success(),
        "expected unlock stats to succeed, stderr: {}",
        String::from_utf8_lossy(&unlocks.stderr)
    );
    let unlock_value: norito::json::Value =
        norito::json::from_slice(&unlocks.stdout).expect("parse unlock stats JSON");
    assert_eq!(
        unlock_value
            .get("height_current")
            .and_then(norito::json::Value::as_u64),
        Some(100)
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn gov_vote_plain_against_mock() {
    use iroha::data_model::isi::{InstructionBox, governance::CastPlainBallot};
    use torii_mock_support::{
        SpawnError, TempDir, ToriiMockProcess, configure_governance, write_client_config,
    };
    let mock = match ToriiMockProcess::spawn() {
        Ok(proc) => proc,
        Err(SpawnError::PythonUnavailable | SpawnError::PermissionDenied) => {
            eprintln!("skipping gov_vote_plain_against_mock: mock server unavailable");
            return;
        }
        Err(err) => panic!("failed to start Torii mock: {err}"),
    };
    let owner = parse_account_literal(alice_account_literal());
    let owner_str = owner.to_string();
    let instruction = InstructionBox::from(CastPlainBallot {
        referendum_id: "ref-plain".to_owned(),
        owner: owner.clone(),
        amount: 500_u64.into(),
        duration_blocks: 128,
        direction: 0,
    });
    let payload_hex = hex::encode(norito::to_bytes(&instruction).expect("encode ballot"));
    let config_payload = norito::json!({
        "referenda": [{
            "id": "ref-plain",
            "referendum": {
                "id": "ref-plain",
                "mode": "Plain",
                "status": "Open"
            },
            "ballot_plain_request": {
                "authority": owner_str,
                "network_id": MOCK_NETWORK_ID,
                "referendum_id": "ref-plain",
                "owner": owner_str,
                "amount": "500",
                "duration_blocks": 128,
                "direction": "Aye"
            },
            "ballot_plain_response": {
                "ok": true,
                "accepted": true,
                "reason": "",
                "tx_instructions": [{
                    "wire_id": "CastPlainBallot",
                    "payload_hex": payload_hex,
                }]
            }
        }]
    });
    configure_governance(mock.base_url(), &config_payload)
        .expect("configure governance responses in mock");
    let temp_dir = TempDir::new("gov_vote_plain").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, mock.base_url()).expect("write config");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "gov",
            "vote",
            "--referendum-id",
            "ref-plain",
            "--mode",
            "plain",
            "--owner",
            &owner_str,
            "--amount",
            "500",
            "--duration-blocks",
            "128",
            "--direction",
            "Aye",
        ])
        .output()
        .expect("failed to execute iroha app gov vote (plain)");
    assert!(
        output.status.success(),
        "expected gov vote plain to succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: norito::json::Value =
        norito::json::from_slice(&output.stdout).expect("vote plain output JSON");
    assert_eq!(
        value.get("ok").and_then(norito::json::Value::as_bool),
        Some(true)
    );
    let instructions = value
        .get("tx_instructions")
        .and_then(norito::json::Value::as_array)
        .expect("instructions array");
    assert_eq!(
        instructions.len(),
        1,
        "expected single instruction skeleton"
    );
    let entry = instructions[0]
        .as_object()
        .expect("instruction should be an object");
    assert_eq!(
        entry.get("owner").and_then(norito::json::Value::as_str),
        Some(owner_str.as_str())
    );
    assert_eq!(
        entry.get("direction").and_then(norito::json::Value::as_str),
        Some("Aye")
    );
    assert!(
        entry.contains_key("payload_fingerprint_hex"),
        "payload fingerprint annotation missing"
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn gov_vote_plain_emits_summary_and_json() {
    use iroha::data_model::isi::{InstructionBox, governance::CastPlainBallot};
    use torii_mock_support::{
        SpawnError, TempDir, ToriiMockProcess, configure_governance, write_client_config,
    };
    let mock = match ToriiMockProcess::spawn() {
        Ok(proc) => proc,
        Err(SpawnError::PythonUnavailable | SpawnError::PermissionDenied) => {
            eprintln!("skipping gov_vote_plain_emits_summary_and_json: mock server unavailable");
            return;
        }
        Err(err) => panic!("failed to start Torii mock: {err}"),
    };
    let owner = parse_account_literal(alice_account_literal());
    let owner_str = owner.to_string();
    let instruction = InstructionBox::from(CastPlainBallot {
        referendum_id: "ref-plain".to_owned(),
        owner: owner.clone(),
        amount: 500_u64.into(),
        duration_blocks: 128,
        direction: 0,
    });
    let payload_bytes = norito::to_bytes(&instruction).expect("encode ballot");
    let payload_hex = hex::encode(&payload_bytes);
    let fingerprint = CryptoHash::new(&payload_bytes).to_string();
    let config_payload = norito::json!({
        "referenda": [{
            "id": "ref-plain",
            "referendum": {
                "id": "ref-plain",
                "mode": "Plain",
                "status": "Open"
            },
            "ballot_plain_request": {
                "authority": owner_str,
                "network_id": MOCK_NETWORK_ID,
                "referendum_id": "ref-plain",
                "owner": owner_str,
                "amount": "500",
                "duration_blocks": 128,
                "direction": "Aye"
            },
            "ballot_plain_response": {
                "ok": true,
                "accepted": true,
                "reason": "",
                "tx_instructions": [{
                    "wire_id": "CastPlainBallot",
                    "payload_hex": payload_hex,
                }]
            }
        }]
    });
    configure_governance(mock.base_url(), &config_payload)
        .expect("configure governance responses in mock");
    let temp_dir = TempDir::new("gov_vote_plain_summary").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, mock.base_url()).expect("write config");
    let summary = command()
        .arg("--config")
        .arg(&config_path)
        .arg("--output-format")
        .arg("text")
        .args([
            "app",
            "gov",
            "vote",
            "--referendum-id",
            "ref-plain",
            "--mode",
            "plain",
            "--owner",
            &owner_str,
            "--amount",
            "500",
            "--duration-blocks",
            "128",
            "--direction",
            "Aye",
        ])
        .output()
        .expect("failed to execute iroha app gov vote --output-format text");
    assert!(
        summary.status.success(),
        "expected gov vote plain summary to succeed, stderr: {}",
        String::from_utf8_lossy(&summary.stderr)
    );
    let summary_text = String::from_utf8_lossy(&summary.stdout);
    let expected_summary = format!(
        "vote plain: referendum_id=ref-plain ok=true accepted=true instrs=1 fingerprint={fingerprint} owner={owner_str} amount=500 duration_blocks=128 direction=Aye"
    );
    assert_eq!(summary_text.trim_end(), expected_summary);
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "gov",
            "vote",
            "--referendum-id",
            "ref-plain",
            "--mode",
            "plain",
            "--owner",
            &owner_str,
            "--amount",
            "500",
            "--duration-blocks",
            "128",
            "--direction",
            "Aye",
        ])
        .output()
        .expect("failed to execute iroha app gov vote");
    assert!(
        output.status.success(),
        "expected gov vote plain to succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: norito::json::Value =
        norito::json::from_slice(&output.stdout).expect("vote plain output JSON");
    assert_eq!(
        value.get("ok").and_then(norito::json::Value::as_bool),
        Some(true)
    );
    let instructions = value
        .get("tx_instructions")
        .and_then(norito::json::Value::as_array)
        .expect("instructions array");
    assert_eq!(
        instructions.len(),
        1,
        "expected single instruction skeleton"
    );
    let entry = instructions[0]
        .as_object()
        .expect("instruction should be an object");
    assert_eq!(
        entry.get("wire_id").and_then(norito::json::Value::as_str),
        Some("CastPlainBallot")
    );
    assert_eq!(
        entry
            .get("payload_fingerprint_hex")
            .and_then(norito::json::Value::as_str),
        Some(fingerprint.as_str())
    );
    assert_eq!(
        entry.get("owner").and_then(norito::json::Value::as_str),
        Some(owner_str.as_str())
    );
    assert_eq!(
        entry.get("direction").and_then(norito::json::Value::as_str),
        Some("Aye")
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn sorafs_incentives_service_cli_roundtrip() {
    use torii_mock_support::TempDir;
    let temp_dir = TempDir::new("incentives_service_cli_roundtrip").expect("temp dir");
    let state_path = state_path(&temp_dir, "payout_state.json");
    let config_path = write_reward_config_file(&temp_dir);
    let state_str = state_path.to_str().expect("utf-8 state path");
    let config_str = config_path.to_str().expect("utf-8 config path");
    let treasury = account_id("treasury");
    let treasury_literal = account_literal(&treasury);
    let output = command()
        .args([
            "app",
            "sorafs",
            "incentives",
            "service",
            "init",
            "--state",
            state_str,
            "--config",
            config_str,
            "--treasury-account",
            treasury_literal.as_str(),
        ])
        .output()
        .expect("execute incentives service init");
    assert!(
        output.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(state_path.exists(), "state file not created");
    let state_json = read_state(&state_path);
    assert_eq!(state_json["version"].as_u64(), Some(1));
    let treasury_json_literal = treasury.canonical_i105().expect("treasury i105");
    assert_eq!(
        state_json["treasury_account"].as_str(),
        Some(treasury_json_literal.as_str())
    );
    let metrics = sample_metrics();
    let metrics_path = write_metrics_file(&temp_dir, &metrics);
    let bond = sample_bond_entry();
    let bond_path = write_bond_file(&temp_dir, &bond);
    let instruction_out = temp_dir.path().join("instruction.to");
    let beneficiary_literal = account_literal_for("beneficiary");
    let output = command()
        .args([
            "app",
            "sorafs",
            "incentives",
            "service",
            "process",
            "--state",
            state_str,
            "--metrics",
            metrics_path.to_str().unwrap(),
            "--bond",
            bond_path.to_str().unwrap(),
            "--beneficiary",
            beneficiary_literal.as_str(),
            "--instruction-out",
            instruction_out.to_str().unwrap(),
            "--pretty",
        ])
        .output()
        .expect("execute incentives service process");
    assert!(
        output.status.success(),
        "process failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = norito::json::from_slice(&output.stdout).expect("parse process summary");
    assert_eq!(summary["epoch"].as_u64(), Some(u64::from(metrics.epoch)));
    let instruction_bytes = fs::read(&instruction_out).expect("read instruction");
    let instruction: RelayRewardInstructionV1 =
        decode_from_bytes(&instruction_bytes).expect("decode instruction");
    assert_eq!(instruction.epoch, metrics.epoch);
    let state_json = read_state(&state_path);
    let payouts = state_json["payouts"].as_array().expect("payouts array");
    assert_eq!(payouts.len(), 1);
    let relay_hex = hex::encode(metrics.relay_id);
    let operator_literal = account_literal_for("operator");
    let output = command()
        .args([
            "app",
            "sorafs",
            "incentives",
            "service",
            "dispute",
            "file",
            "--state",
            state_str,
            "--relay-id",
            &relay_hex,
            "--epoch",
            &metrics.epoch.to_string(),
            "--submitted-by",
            operator_literal.as_str(),
            "--requested-amount",
            "120",
            "--reason",
            "missing bandwidth",
            "--filed-at",
            "9999",
            "--adjust-credit",
            "25",
            "--pretty",
        ])
        .output()
        .expect("execute dispute file");
    assert!(
        output.status.success(),
        "dispute file failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let dispute_json: Value = norito::json::from_slice(&output.stdout).expect("parse file output");
    let dispute_id = dispute_json["id"].as_u64().expect("dispute id");
    let state_json = read_state(&state_path);
    assert_eq!(state_json["disputes"].as_array().unwrap().len(), 1);
    let transfer_path = temp_dir.path().join("credit_transfer.to");
    let output = command()
        .args([
            "app",
            "sorafs",
            "incentives",
            "service",
            "dispute",
            "resolve",
            "--state",
            state_str,
            "--dispute-id",
            &dispute_id.to_string(),
            "--resolution",
            "credit",
            "--amount",
            "25",
            "--notes",
            "approved",
            "--resolved-at",
            "10500",
            "--transfer-out",
            transfer_path.to_str().unwrap(),
            "--pretty",
        ])
        .output()
        .expect("execute dispute resolve");
    assert!(
        output.status.success(),
        "dispute resolve failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let transfer_bytes = fs::read(&transfer_path).expect("read transfer");
    let transfer_instr: InstructionBox =
        decode_from_bytes(&transfer_bytes).expect("decode transfer");
    let transfer_box = transfer_instr
        .as_any()
        .downcast_ref::<TransferBox>()
        .expect("transfer payload");
    let TransferBox::Asset(transfer) = transfer_box else {
        panic!("expected asset transfer, got {transfer_box:?}");
    };
    assert_eq!(transfer.object, Quantity::from(25_u32));
    assert_eq!(transfer.destination, account_id("beneficiary"));
    assert_eq!(transfer.source.account, treasury);
    let state_json = read_state(&state_path);
    let disputes = state_json["disputes"].as_array().unwrap();
    let status = disputes[0]
        .get("status")
        .and_then(|s| s.get("details"))
        .expect("status details");
    let resolution_kind = status
        .get("kind")
        .and_then(|k| k.get("kind"))
        .and_then(Value::as_str)
        .expect("resolution kind");
    assert_eq!(resolution_kind, "Credit");
    let output = command()
        .args([
            "app",
            "sorafs",
            "incentives",
            "service",
            "dashboard",
            "--state",
            state_str,
        ])
        .output()
        .expect("execute dashboard");
    assert!(
        output.status.success(),
        "dashboard failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let dashboard: Value = norito::json::from_slice(&output.stdout).expect("parse dashboard");
    assert_eq!(dashboard["total_relays"].as_u64(), Some(1));
    assert_eq!(dashboard["total_open_disputes"].as_u64(), Some(0));
}
#[test]
#[allow(clippy::too_many_lines)]
fn sorafs_incentives_service_cli_process_batch_and_reconcile() {
    use torii_mock_support::TempDir;
    let temp_dir = TempDir::new("incentives_service_cli_process_batch").expect("temp dir");
    let state_path = state_path(&temp_dir, "payout_state.json");
    let config_path = write_reward_config_file(&temp_dir);
    let state_str = state_path.to_str().expect("utf-8 state path");
    let config_str = config_path.to_str().expect("utf-8 config path");
    let treasury = account_id("treasury");
    let treasury_literal = account_literal(&treasury);
    let output = command()
        .args([
            "app",
            "sorafs",
            "incentives",
            "service",
            "init",
            "--state",
            state_str,
            "--config",
            config_str,
            "--treasury-account",
            treasury_literal.as_str(),
        ])
        .output()
        .expect("execute incentives service init");
    assert!(
        output.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metrics_a = sample_metrics();
    let mut metrics_b = metrics_a.clone();
    metrics_b.epoch += 1;
    metrics_b.verified_bandwidth_bytes += 500;
    let metrics_a_path = write_metrics_file(&temp_dir, &metrics_a);
    let metrics_b_path = write_metrics_file(&temp_dir, &metrics_b);
    let bond_path = write_bond_file(&temp_dir, &sample_bond_entry());
    let beneficiary_a_literal = account_literal_for("beneficiary-a");
    let beneficiary_b_literal = account_literal_for("beneficiary-b");
    let output = command()
        .args([
            "app",
            "sorafs",
            "incentives",
            "service",
            "process",
            "--state",
            state_str,
            "--metrics",
            metrics_a_path.to_str().unwrap(),
            "--metrics",
            metrics_b_path.to_str().unwrap(),
            "--bond",
            bond_path.to_str().unwrap(),
            "--beneficiary",
            beneficiary_a_literal.as_str(),
            "--beneficiary",
            beneficiary_b_literal.as_str(),
            "--pretty",
        ])
        .output()
        .expect("execute incentives service process batch");
    assert!(
        output.status.success(),
        "batch process failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = norito::json::from_slice(&output.stdout).expect("parse batch summary");
    let payouts = summary.as_array().expect("batch summary must be an array");
    assert_eq!(payouts.len(), 2);
    let state_json = read_state(&state_path);
    assert_eq!(
        state_json["payouts"]
            .as_array()
            .expect("payouts array")
            .len(),
        2
    );
    let treasury_account = treasury.clone();
    let treasury_json_literal = treasury.canonical_i105().expect("treasury i105");
    assert_eq!(
        state_json["treasury_account"]
            .as_str()
            .expect("treasury account string"),
        treasury_json_literal.as_str()
    );
    let payout_values = state_json["payouts"].as_array().expect("payouts array");
    let mut expected_transfers = Vec::new();
    for payout in payout_values {
        let bytes = norito::json::to_vec(payout).expect("encode payout json");
        let instruction: RelayRewardInstructionV1 =
            norito::json::from_slice(&bytes).expect("decode instruction json");
        if instruction.is_zero_amount() {
            continue;
        }
        expected_transfers.push(LedgerTransferRecord {
            relay_id: instruction.relay_id,
            epoch: instruction.epoch,
            kind: TransferKind::Payout,
            dispute_id: None,
            amount: instruction.payout_amount.clone(),
            source_asset: AssetId::new(
                instruction.payout_asset_id.clone(),
                treasury_account.clone(),
            ),
            destination: instruction.beneficiary.clone(),
        });
    }
    let export_file = temp_dir.path().join("ledger_export.to");
    let export_bytes = encode_ledger_export(&TestLedgerExport {
        version: 1,
        transfers: expected_transfers.clone(),
    });
    fs::write(&export_file, export_bytes).expect("write export");
    let output = command()
        .args([
            "app",
            "sorafs",
            "incentives",
            "service",
            "reconcile",
            "--state",
            state_str,
            "--ledger-export",
            export_file.to_str().unwrap(),
        ])
        .output()
        .expect("execute incentives service reconcile");
    assert!(
        output.status.success(),
        "reconcile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reconcile_summary: Value =
        norito::json::from_slice(&output.stdout).expect("parse reconcile summary");
    assert_eq!(reconcile_summary["clean"].as_bool(), Some(true));
    assert_eq!(
        reconcile_summary["matched_transfers"].as_u64(),
        Some(expected_transfers.len() as u64)
    );
    assert_eq!(
        reconcile_summary["total_expected_transfers"].as_u64(),
        Some(expected_transfers.len() as u64)
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn gov_vote_zk_against_mock() {
    use iroha::data_model::isi::{InstructionBox, governance::CastZkBallot};
    use torii_mock_support::{
        SpawnError, TempDir, ToriiMockProcess, configure_governance, write_client_config,
    };
    let mock = match ToriiMockProcess::spawn() {
        Ok(proc) => proc,
        Err(SpawnError::PythonUnavailable | SpawnError::PermissionDenied) => {
            eprintln!("skipping gov_vote_zk_against_mock: mock server unavailable");
            return;
        }
        Err(err) => panic!("failed to start Torii mock: {err}"),
    };
    let owner = parse_account_literal(alice_account_literal());
    let owner_str = owner.to_string();
    let nullifier = "11".repeat(32);
    let hint_payload = norito::json!({
        "owner": owner_str,
        "amount": "700",
        "duration_blocks": 256,
        "direction": "Nay",
        "nullifier": nullifier,
    });
    let public_inputs_json =
        String::from_utf8(norito::json::to_vec(&hint_payload).expect("serialize hints to JSON"))
            .expect("hints JSON is utf8");
    let instruction = InstructionBox::from(CastZkBallot {
        election_id: "ref-zk".to_owned(),
        proof_b64: "AAA=".to_owned(),
        public_inputs_json,
    });
    let payload_hex = hex::encode(norito::to_bytes(&instruction).expect("encode zk ballot"));
    let config_payload = norito::json!({
        "referenda": [{
            "id": "ref-zk",
            "referendum": {
                "id": "ref-zk",
                "mode": "Zk",
                "status": "Open"
            },
            "ballot_zk_request": {
                "authority": owner_str,
                "network_id": MOCK_NETWORK_ID,
                "election_id": "ref-zk",
                "backend": "halo2/ipa",
                "envelope_b64": "AAA=",
                "owner": owner_str,
                "amount": "700",
                "duration_blocks": 256,
                "direction": "Nay",
                "nullifier": nullifier
            },
            "ballot_zk_response": {
                "ok": true,
                "accepted": false,
                "reason": "staged",
                "tx_instructions": [{
                    "wire_id": "CastZkBallot",
                    "payload_hex": payload_hex,
                }]
            }
        }]
    });
    configure_governance(mock.base_url(), &config_payload)
        .expect("configure governance responses in mock");
    let temp_dir = TempDir::new("gov_vote_zk").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, mock.base_url()).expect("write config");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "gov",
            "vote",
            "--referendum-id",
            "ref-zk",
            "--mode",
            "zk",
            "--backend",
            "halo2/ipa",
            "--envelope-b64",
            "AAA=",
            "--owner",
            &owner_str,
            "--amount",
            "700",
            "--duration-blocks",
            "256",
            "--direction",
            "Nay",
            "--nullifier",
            &nullifier,
        ])
        .output()
        .expect("failed to execute iroha app gov vote (zk)");
    assert!(
        output.status.success(),
        "expected gov vote zk to succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: norito::json::Value =
        norito::json::from_slice(&output.stdout).expect("vote zk output JSON");
    let instructions = value
        .get("tx_instructions")
        .and_then(norito::json::Value::as_array)
        .expect("instructions array");
    assert_eq!(
        instructions.len(),
        1,
        "expected single instruction skeleton"
    );
    let entry = instructions[0]
        .as_object()
        .expect("instruction should be an object");
    assert_eq!(
        entry.get("owner").and_then(norito::json::Value::as_str),
        Some(owner_str.as_str())
    );
    assert_eq!(
        entry
            .get("duration_blocks")
            .and_then(norito::json::Value::as_str),
        Some("256")
    );
    assert_eq!(
        entry.get("direction").and_then(norito::json::Value::as_str),
        Some("Nay")
    );
    assert_eq!(
        entry.get("nullifier").and_then(norito::json::Value::as_str),
        Some(nullifier.as_str())
    );
    assert!(
        entry.contains_key("payload_fingerprint_hex"),
        "payload fingerprint annotation missing"
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn gov_vote_zk_emits_summary_and_json() {
    use iroha::data_model::isi::{InstructionBox, governance::CastZkBallot};
    use torii_mock_support::{
        SpawnError, TempDir, ToriiMockProcess, configure_governance, write_client_config,
    };
    let mock = match ToriiMockProcess::spawn() {
        Ok(proc) => proc,
        Err(SpawnError::PythonUnavailable | SpawnError::PermissionDenied) => {
            eprintln!("skipping gov_vote_zk_emits_summary_and_json: mock server unavailable");
            return;
        }
        Err(err) => panic!("failed to start Torii mock: {err}"),
    };
    let owner = parse_account_literal(alice_account_literal());
    let owner_str = owner.to_string();
    let amount = "900";
    let duration_blocks = 512u64;
    let duration_blocks_str = duration_blocks.to_string();
    let direction = "Nay";
    let nullifier = "22".repeat(32);
    let hint_payload = norito::json!({
        "owner": owner_str,
        "amount": amount,
        "duration_blocks": duration_blocks,
        "direction": direction,
        "nullifier": nullifier,
    });
    let public_inputs_json =
        String::from_utf8(norito::json::to_vec(&hint_payload).expect("serialize hints to JSON"))
            .expect("hints JSON is utf8");
    let instruction = InstructionBox::from(CastZkBallot {
        election_id: "ref-zk".to_owned(),
        proof_b64: "BBA=".to_owned(),
        public_inputs_json,
    });
    let payload_bytes = norito::to_bytes(&instruction).expect("encode zk ballot");
    let payload_hex = hex::encode(&payload_bytes);
    let fingerprint = CryptoHash::new(&payload_bytes).to_string();
    let config_payload = norito::json!({
        "referenda": [{
            "id": "ref-zk",
            "referendum": {
                "id": "ref-zk",
                "mode": "Zk",
                "status": "Open"
            },
            "ballot_zk_request": {
                "authority": owner_str,
                "network_id": MOCK_NETWORK_ID,
                "election_id": "ref-zk",
                "backend": "halo2/ipa",
                "envelope_b64": "BBA=",
                "owner": owner_str,
                "amount": amount,
                "duration_blocks": duration_blocks,
                "direction": direction,
                "nullifier": nullifier
            },
            "ballot_zk_response": {
                "ok": true,
                "accepted": true,
                "reason": "",
                "tx_instructions": [{
                    "wire_id": "CastZkBallot",
                    "payload_hex": payload_hex,
                }]
            }
        }]
    });
    configure_governance(mock.base_url(), &config_payload)
        .expect("configure governance responses in mock");
    let temp_dir = TempDir::new("gov_vote_zk_summary").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, mock.base_url()).expect("write config");
    let summary = command()
        .arg("--config")
        .arg(&config_path)
        .arg("--output-format")
        .arg("text")
        .args([
            "app",
            "gov",
            "vote",
            "--referendum-id",
            "ref-zk",
            "--mode",
            "zk",
            "--backend",
            "halo2/ipa",
            "--envelope-b64",
            "BBA=",
            "--owner",
            &owner_str,
            "--amount",
            amount,
            "--duration-blocks",
            &duration_blocks_str,
            "--direction",
            direction,
            "--nullifier",
            &nullifier,
        ])
        .output()
        .expect("failed to execute iroha app gov vote --output-format text");
    assert!(
        summary.status.success(),
        "expected gov vote zk summary to succeed, stderr: {}",
        String::from_utf8_lossy(&summary.stderr)
    );
    let summary_text = String::from_utf8_lossy(&summary.stdout);
    let expected_summary = format!(
        "vote zk: election_id=ref-zk ok=true accepted=true instrs=1 fingerprint={fingerprint} owner={owner_str} amount={amount} duration_blocks={duration_blocks} direction={direction} nullifier={nullifier}"
    );
    assert_eq!(summary_text.trim_end(), expected_summary);
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "gov",
            "vote",
            "--referendum-id",
            "ref-zk",
            "--mode",
            "zk",
            "--backend",
            "halo2/ipa",
            "--envelope-b64",
            "BBA=",
            "--owner",
            &owner_str,
            "--amount",
            amount,
            "--duration-blocks",
            &duration_blocks_str,
            "--direction",
            direction,
            "--nullifier",
            &nullifier,
        ])
        .output()
        .expect("failed to execute iroha app gov vote");
    assert!(
        output.status.success(),
        "expected gov vote zk to succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: norito::json::Value =
        norito::json::from_slice(&output.stdout).expect("vote zk output JSON");
    assert_eq!(
        value.get("ok").and_then(norito::json::Value::as_bool),
        Some(true)
    );
    let instructions = value
        .get("tx_instructions")
        .and_then(norito::json::Value::as_array)
        .expect("instructions array");
    assert_eq!(
        instructions.len(),
        1,
        "expected single instruction skeleton"
    );
    let entry = instructions[0]
        .as_object()
        .expect("instruction should be an object");
    assert_eq!(
        entry.get("wire_id").and_then(norito::json::Value::as_str),
        Some("CastZkBallot")
    );
    assert_eq!(
        entry
            .get("payload_fingerprint_hex")
            .and_then(norito::json::Value::as_str),
        Some(fingerprint.as_str())
    );
    assert_eq!(
        entry.get("owner").and_then(norito::json::Value::as_str),
        Some(owner_str.as_str())
    );
    assert_eq!(
        entry
            .get("duration_blocks")
            .and_then(norito::json::Value::as_str),
        Some(duration_blocks_str.as_str())
    );
    assert_eq!(
        entry.get("direction").and_then(norito::json::Value::as_str),
        Some(direction)
    );
    assert_eq!(
        entry.get("nullifier").and_then(norito::json::Value::as_str),
        Some(nullifier.as_str())
    );
}
#[test]
fn gov_rejects_retired_governance_commands() {
    for command_name in ["finalize", "enact", "council"] {
        let output = command()
            .args(["app", "gov", command_name])
            .output()
            .expect("run CLI with a retired governance command");
        assert!(!output.status.success(), "{command_name} must be absent");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unrecognized subcommand") && stderr.contains(command_name),
            "unexpected diagnostic for {command_name}: {stderr}"
        );
    }
}
#[test]
fn gov_queries_reject_retired_id_alias() {
    for (label, query) in [
        ("referendum get", ["app", "gov", "referendum", "get"]),
        ("tally get", ["app", "gov", "tally", "get"]),
    ] {
        let output = command()
            .args(query)
            .args(["--id", "ref-plain"])
            .output()
            .expect("run governance query with retired --id alias");
        assert!(!output.status.success(), "{label} must reject --id");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unexpected argument") && stderr.contains("--id"),
            "unexpected {label} diagnostic: {stderr}"
        );
    }
}
#[test]
#[allow(clippy::too_many_lines)]
fn gov_audit_deploy_reports_results_against_mock() {
    use iroha_crypto::Hash as CryptoHash;
    use torii_mock_support::{
        SpawnError, TempDir, ToriiMockProcess, configure_governance, write_client_config,
    };
    let mock = match ToriiMockProcess::spawn() {
        Ok(proc) => proc,
        Err(SpawnError::PythonUnavailable | SpawnError::PermissionDenied) => {
            eprintln!(
                "skipping gov_audit_deploy_reports_results_against_mock: mock server unavailable"
            );
            return;
        }
        Err(err) => panic!("failed to start Torii mock: {err}"),
    };
    let contract_address = "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";
    let (code_bytes, manifest) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(include_str!("../../src/contracts/fixtures/minimal_view.ko"))
        .expect("compile the audited public contract and its matching manifest");
    let code_hash = manifest.code_hash.expect("compiled artifact hash");
    let abi_hash = manifest.abi_hash.expect("compiled ABI hash");
    assert_ne!(code_hash, CryptoHash::new(&code_bytes));
    let public_entrypoints = manifest
        .entrypoints
        .as_ref()
        .expect("compiled entrypoint interface")
        .iter()
        .map(|entrypoint| entrypoint.name.clone())
        .collect::<Vec<_>>();
    assert_eq!(public_entrypoints, ["inspect"]);
    let code_hash_hex = hex::encode(code_hash.as_ref());
    let parsed_contract_address = contract_address
        .parse::<iroha_data_model::smart_contract::ContractAddress>()
        .expect("canonical contract address");
    let artifact_id = iroha_data_model::smart_contract::ContractArtifactId::for_address(
        &parsed_contract_address,
        code_hash,
    )
    .expect("contract address artifact identity");
    let artifact_key = format!("{}/{code_hash_hex}", artifact_id.dataspace_id.as_u64());
    let network_id = MOCK_NETWORK_ID
        .parse::<iroha_data_model::NetworkId>()
        .expect("mock network identity");
    let abi_hash_hex = hex::encode(abi_hash.as_ref());
    let mut code_arr = [0u8; 32];
    code_arr.copy_from_slice(code_hash.as_ref());
    let mut abi_arr = [0u8; 32];
    abi_arr.copy_from_slice(abi_hash.as_ref());
    let proposal_hex = proposal_id_hex(contract_address, &code_arr, &abi_arr);
    let manifest_body = norito::json!({
        "network_id": network_id,
        "artifact_id": artifact_id,
        "manifest": manifest,
        "code_hash": null,
        "abi_hash": null,
        "code_bytes": null
    });
    let code_bytes_body = norito::json!({
        "network_id": network_id,
        "artifact_id": artifact_id,
        "code_b64": (BASE64.encode(&code_bytes))
    });
    let proposal_body = {
        let mut deploy = json::Map::new();
        deploy.insert(
            "contract_address".to_string(),
            json::Value::String(contract_address.to_string()),
        );
        deploy.insert(
            "code_hash_hex".to_string(),
            json::Value::String(format!("0x{code_hash_hex}")),
        );
        deploy.insert(
            "abi_hash_hex".to_string(),
            json::Value::String(format!("0x{abi_hash_hex}")),
        );
        let mut kind = json::Map::new();
        kind.insert("DeployContract".to_string(), json::Value::Object(deploy));
        let mut proposal = json::Map::new();
        proposal.insert("status".to_string(), json::Value::String("Enacted".into()));
        proposal.insert("kind".to_string(), json::Value::Object(kind));
        let mut root = json::Map::new();
        root.insert("found".to_string(), json::Value::Bool(true));
        root.insert("proposal".to_string(), json::Value::Object(proposal));
        json::Value::Object(root)
    };
    let mut gov_contracts = json::Map::new();
    gov_contracts.insert(
        contract_address.to_string(),
        norito::json!({
            "found": true,
            "contract_address": contract_address,
            "contract_subject_account": (bob_account_literal()),
            "dataspace": "universal",
            "active": true,
            "lifecycle": {
                "version": 1,
                "origin": "parliament",
                "origin_account": (alice_account_literal()),
                "origin_proposal_content_id_hex": proposal_hex,
                "origin_governance_attempt_id_hex": ("33".repeat(32)),
                "owner": "parliament",
                "pending_owner": null,
                "parliament_delegated": false,
                "active_code_hash_hex": code_hash_hex,
                "retained_code_hash_hex": code_hash_hex,
                "revision": 1,
                "emergency_hold": null
            },
            "emergency_hold_active": false,
            "code_hash_hex": code_hash_hex,
            "abi_hash_hex": abi_hash_hex,
            "public_entrypoints": public_entrypoints
        }),
    );
    let mut manifests = json::Map::new();
    manifests.insert(artifact_key.clone(), manifest_body);
    let mut code_bytes_map = json::Map::new();
    code_bytes_map.insert(artifact_key.clone(), code_bytes_body);
    let mut proposals = json::Map::new();
    proposals.insert(proposal_hex.clone(), proposal_body);
    let mut root = json::Map::new();
    root.insert("referenda".to_string(), norito::json!([]));
    root.insert(
        "gov_contracts".to_string(),
        json::Value::Object(gov_contracts),
    );
    root.insert("manifests".to_string(), json::Value::Object(manifests));
    root.insert(
        "code_bytes".to_string(),
        json::Value::Object(code_bytes_map),
    );
    root.insert("proposals".to_string(), json::Value::Object(proposals));
    let config_payload = json::Value::Object(root);
    let temp_dir = TempDir::new("gov_audit_deploy").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, mock.base_url()).expect("write config");
    configure_governance(mock.base_url(), &config_payload).expect("configure governance");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "gov",
            "deploy",
            "audit",
            "--contract-address",
            contract_address,
        ])
        .output()
        .expect("invoke iroha app gov deploy audit");
    assert!(
        output.status.success(),
        "expected deploy audit to succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: norito::json::Value =
        norito::json::from_slice(&output.stdout).expect("parse deploy audit JSON");
    assert_eq!(
        value
            .get("contract_address")
            .and_then(norito::json::Value::as_str),
        Some(contract_address)
    );
    assert_eq!(
        value.get("found").and_then(norito::json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        value
            .get("issue_count")
            .and_then(norito::json::Value::as_u64),
        Some(0),
        "unexpected deploy audit report: {value:?}"
    );
    assert_eq!(
        value
            .get("has_issues")
            .and_then(norito::json::Value::as_bool),
        Some(false)
    );
    let issues = value
        .get("issues")
        .and_then(norito::json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(issues.is_empty(), "expected no issues, found: {issues:?}");
    let manifest = value
        .get("manifest")
        .and_then(norito::json::Value::as_object)
        .expect("manifest section");
    assert_eq!(
        manifest
            .get("code_hash_matches")
            .and_then(norito::json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        manifest
            .get("abi_hash")
            .and_then(norito::json::Value::as_str),
        Some(abi_hash_hex.as_str())
    );
    let proposal = value
        .get("proposal")
        .and_then(norito::json::Value::as_object)
        .expect("proposal section");
    assert_eq!(
        proposal.get("status").and_then(norito::json::Value::as_str),
        Some("Enacted")
    );
    assert_eq!(
        proposal
            .get("code_hash_matches")
            .and_then(norito::json::Value::as_bool),
        Some(true)
    );
    let mut tampered_code = code_bytes;
    tampered_code[0] ^= 1;
    let mut tampered_config = config_payload;
    tampered_config
        .get_mut("code_bytes")
        .and_then(Value::as_object_mut)
        .and_then(|entries| entries.get_mut(&artifact_key))
        .and_then(Value::as_object_mut)
        .expect("configured artifact response")
        .insert(
            "code_b64".to_owned(),
            Value::String(BASE64.encode(tampered_code)),
        );
    configure_governance(mock.base_url(), &tampered_config).expect("configure altered artifact");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "gov",
            "deploy",
            "audit",
            "--contract-address",
            contract_address,
        ])
        .output()
        .expect("audit altered artifact bytes");
    assert!(
        output.status.success(),
        "audit must produce an issue report"
    );
    let value: Value = json::from_slice(&output.stdout).expect("altered artifact audit JSON");
    assert_eq!(value.get("has_issues").and_then(Value::as_bool), Some(true));
    assert_eq!(
        value
            .get("code")
            .and_then(|code| code.get("present"))
            .and_then(Value::as_bool),
        Some(false)
    );
    assert!(
        value
            .get("issues")
            .and_then(Value::as_array)
            .expect("audit issues")
            .iter()
            .filter_map(Value::as_str)
            .any(|issue| issue.starts_with("code_bytes_error:")
                && issue.contains("artifact digest does not match the requested hash")),
        "an altered execution header must invalidate the artifact hash"
    );
}
#[test]
fn repo_initiate_emits_instruction_payload() {
    use torii_mock_support::{TempDir, write_client_config};
    let temp_dir = TempDir::new("repo_initiate").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, "http://localhost").expect("write config");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .arg("--emit-instructions")
        .args([
            "app",
            "repo",
            "initiate",
            "--agreement-id",
            "daily_repo",
            "--initiator",
            alice_account_literal(),
            "--counterparty",
            bob_account_literal(),
            "--cash-asset",
            "7EAD8EFYUx1aVKZPUU1fyKvr8dF1",
            "--cash-quantity",
            "1000",
            "--collateral-asset",
            "4fEiy2n5VMFVfi6BzDJge519zAzg",
            "--collateral-quantity",
            "1050",
            "--rate-bps",
            "250",
            "--maturity-timestamp-ms",
            "1704000000000",
            "--haircut-bps",
            "1500",
            "--margin-frequency-secs",
            "86400",
        ])
        .output()
        .expect("failed to execute iroha repo initiate");
    assert!(
        output.status.success(),
        "repo initiate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("repo initiate stdout: {stdout}");
    let instructions = parse_instruction_stdout(&stdout);
    assert_eq!(instructions.len(), 1, "expected a single instruction");
    let repo = repo_instruction(&instructions[0]);
    match repo {
        RepoInstructionBox::Initiate(isi) => {
            let expected_initiator = parse_account_literal(alice_account_literal());
            let expected_counterparty = parse_account_literal(bob_account_literal());
            assert_eq!(isi.agreement_id().to_string(), "daily_repo");
            assert_eq!(isi.initiator(), &expected_initiator);
            assert_eq!(isi.counterparty(), &expected_counterparty);
        }
        other => panic!("unexpected instruction variant: {other:?}"),
    }
}
#[test]
#[allow(clippy::too_many_lines)]
fn da_submit_no_submit_emits_request_artifacts() {
    use torii_mock_support::{TempDir, write_client_config};
    let temp_dir = TempDir::new("da_submit_artifacts").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, "http://localhost").expect("write config");
    let payload_bytes = b"demo-da-payload";
    let payload_path = temp_dir.path().join("payload.bin");
    fs::write(&payload_path, payload_bytes).expect("write payload");
    let metadata_path = temp_dir.path().join("metadata.json");
    fs::write(
        &metadata_path,
        br#"{ "purpose": "test", "owner": "alice" }"#,
    )
    .expect("write metadata");
    let artifact_dir = temp_dir.path().join("da_artifacts");
    let blob_override = "ab".repeat(32);
    let mut cmd = command();
    cmd.arg("--config")
        .arg(&config_path)
        .arg("app")
        .arg("da")
        .arg("submit")
        .arg("--payload")
        .arg(&payload_path)
        .arg("--lane-id")
        .arg("42")
        .arg("--epoch")
        .arg("7")
        .arg("--sequence")
        .arg("17")
        .arg("--blob-class")
        .arg("governance")
        .arg("--blob-codec")
        .arg("text/plain")
        .arg("--chunk-size")
        .arg("1024")
        .arg("--data-shards")
        .arg("8")
        .arg("--parity-shards")
        .arg("4")
        .arg("--chunk-alignment")
        .arg("8")
        .arg("--fec-scheme")
        .arg("rs12_10")
        .arg("--hot-retention-secs")
        .arg("3600")
        .arg("--cold-retention-secs")
        .arg("7200")
        .arg("--required-replicas")
        .arg("1")
        .arg("--storage-class")
        .arg("hot")
        .arg("--governance-tag")
        .arg("da.test")
        .arg("--metadata-json")
        .arg(&metadata_path)
        .arg("--client-blob-id")
        .arg(&blob_override)
        .arg("--artifact-dir")
        .arg(&artifact_dir)
        .arg("--no-submit");
    let output = cmd.output().expect("failed to execute iroha app da submit");
    assert!(
        output.status.success(),
        "iroha app da submit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request_path = artifact_dir.join("da_request.norito");
    assert!(request_path.exists(), "expected {request_path:?} to exist");
    let request_json_path = artifact_dir.join("da_request.json");
    let request_json =
        fs::read_to_string(&request_json_path).expect("read da_request.json contents");
    let request_value: Value =
        norito::json::from_str(&request_json).expect("parse da_request.json");
    assert_eq!(
        request_value.get("lane_id").and_then(Value::as_u64),
        Some(42)
    );
    assert_eq!(request_value.get("epoch").and_then(Value::as_u64), Some(7));
    assert_eq!(
        request_value.get("sequence").and_then(Value::as_u64),
        Some(17)
    );
    let blob_class = request_value
        .get("blob_class")
        .and_then(Value::as_object)
        .expect("blob_class object");
    assert_eq!(
        blob_class.get("class").and_then(Value::as_str),
        Some("GovernanceArtifact")
    );
    let payload_base64 = request_value
        .get("payload")
        .and_then(Value::as_str)
        .expect("payload base64");
    assert_eq!(payload_base64, BASE64.encode(payload_bytes));
    let client_blob_id_outer = request_value
        .get("client_blob_id")
        .and_then(Value::as_array)
        .expect("client_blob_id tuple");
    assert_eq!(client_blob_id_outer.len(), 1);
    let client_blob_id = client_blob_id_outer[0]
        .as_array()
        .expect("client_blob_id bytes");
    assert_eq!(client_blob_id.len(), 32);
    assert_eq!(client_blob_id[0].as_u64(), Some(0xab));
    assert_eq!(client_blob_id[31].as_u64(), Some(0xab));
    let retention = request_value
        .get("retention_policy")
        .and_then(Value::as_object)
        .expect("retention policy");
    assert_eq!(
        retention.get("required_replicas").and_then(Value::as_u64),
        Some(1)
    );
    let storage_class = retention
        .get("storage_class")
        .and_then(Value::as_object)
        .expect("storage class");
    assert_eq!(
        storage_class.get("type").and_then(Value::as_str),
        Some("Hot")
    );
    let governance_tag = retention
        .get("governance_tag")
        .and_then(Value::as_array)
        .expect("governance tag tuple");
    assert_eq!(
        governance_tag.first().and_then(Value::as_str),
        Some("da.test")
    );
    assert_eq!(
        retention.get("hot_retention_secs").and_then(Value::as_u64),
        Some(3_600)
    );
    let metadata_items = request_value
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|meta| meta.get("items"))
        .and_then(Value::as_array)
        .expect("metadata items");
    assert_eq!(metadata_items.len(), 2);
    let expected_purpose = BASE64.encode(b"test");
    let expected_owner = BASE64.encode(b"alice");
    let purpose_entry = metadata_items
        .iter()
        .find(|entry| entry.get("key").and_then(Value::as_str) == Some("purpose"))
        .expect("purpose metadata entry");
    assert_eq!(
        purpose_entry.get("value").and_then(Value::as_str),
        Some(expected_purpose.as_str())
    );
    let owner_entry = metadata_items
        .iter()
        .find(|entry| entry.get("key").and_then(Value::as_str) == Some("owner"))
        .expect("owner metadata entry");
    assert_eq!(
        owner_entry.get("value").and_then(Value::as_str),
        Some(expected_owner.as_str())
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn iroha_da_submit_records_pdp_commitment_receipt() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use core::convert::TryFrom;
    use iroha_crypto::Signature;
    use iroha_data_model::da::prelude::{
        BlobDigest, DaIngestReceipt, DaRentQuote, DaStripeLayout, StorageTicketId,
    };
    use iroha_model_base::topology::LaneId;
    use norito::{
        DeserializePayload,
        json::{Map as JsonMap, Value},
    };
    use sorafs_manifest::{
        BLAKE3_256_MULTIHASH_CODE, ChunkingProfileV1, ProfileId,
        pdp::{PdpCommitmentV1, PdpMerkleTreeV1},
    };
    use torii_mock_support::{TempDir, write_client_config};
    fn fixed_digest(seed: u8) -> BlobDigest {
        let mut bytes = [0u8; 32];
        for (idx, byte) in bytes.iter_mut().enumerate() {
            let offset = u8::try_from(idx).expect("digest length fits in u8");
            *byte = seed.wrapping_add(offset);
        }
        BlobDigest::new(bytes)
    }
    let chunk_profile = ChunkingProfileV1 {
        profile_id: ProfileId(0),
        namespace: "inline".to_string(),
        name: "inline".to_string(),
        semver: "0.0.0".to_string(),
        min_size: 64 * 1024,
        target_size: 64 * 1024,
        max_size: 64 * 1024,
        break_mask: 1,
        multihash_code: BLAKE3_256_MULTIHASH_CODE,
        aliases: vec!["inline.inline@0.0.0".to_string()],
    };
    let pdp_tree = PdpMerkleTreeV1::from_bytes(b"cli pdp commitment fixture")
        .expect("build canonical PDP fixture tree");
    let pdp_commitment = PdpCommitmentV1::from_tree(
        &pdp_tree,
        *fixed_digest(0x90).as_bytes(),
        chunk_profile,
        24,
        1_701_800_000,
    )
    .expect("build canonical PDP commitment fixture");
    let mut receipt = DaIngestReceipt {
        client_blob_id: fixed_digest(0xA0),
        lane_id: LaneId::new(42),
        epoch: 7,
        blob_hash: fixed_digest(0xA1),
        chunk_root: fixed_digest(0xA2),
        manifest_hash: fixed_digest(0xA3),
        storage_ticket: StorageTicketId::new(*fixed_digest(0xA4).as_bytes()),
        pdp_commitment: None,
        stripe_layout: DaStripeLayout {
            total_stripes: 1,
            shards_per_stripe: 1,
            row_parity_stripes: 0,
        },
        queued_at_unix: 1_701_800_123,
        rent_quote: DaRentQuote::default(),
        operator_signature: Signature::try_from_bytes(&[0x11; 64])
            .expect("checked CLI DA receipt operator signature fixture"),
    };
    let pdp_bytes = norito::to_bytes(&pdp_commitment).expect("encode commitment");
    let pdp_header = BASE64.encode(&pdp_bytes);
    receipt.pdp_commitment = Some(pdp_bytes.clone());
    let receipt_body = norito::to_bytes(&receipt).expect("encode receipt");
    let temp_dir = TempDir::new("cli_da_submit_pdp").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, "http://localhost").expect("write config");
    let metadata_path = temp_dir.path().join("metadata.json");
    let metadata_contents = norito::json!({
        "purpose": "test",
        "owner": "alice"
    });
    let metadata_json = norito::json::to_string(&metadata_contents).expect("serialize metadata");
    fs::write(&metadata_path, metadata_json).expect("write metadata");
    let payload_path = temp_dir.path().join("payload.bin");
    fs::write(&payload_path, b"payload-bytes").expect("write payload");
    let artifact_dir = temp_dir.path().join("artifacts");
    let blob_override = "ab".repeat(32);
    let fixture_path = temp_dir.path().join("receipt_fixture.json");
    let mut fixture_headers = JsonMap::new();
    fixture_headers.insert(
        "sora-pdp-commitment".to_string(),
        Value::from(pdp_header.clone()),
    );
    let mut fixture_map = JsonMap::new();
    fixture_map.insert(
        "receipt_base64".to_string(),
        Value::from(BASE64.encode(&receipt_body)),
    );
    fixture_map.insert("headers".to_string(), Value::Object(fixture_headers));
    let fixture = Value::Object(fixture_map);
    let fixture_json = norito::json::to_string(&fixture).expect("serialize receipt fixture");
    fs::write(&fixture_path, fixture_json).expect("write fixture");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "da",
            "submit",
            "--payload",
            payload_path.to_str().expect("payload path"),
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir"),
            "--lane-id",
            "42",
            "--epoch",
            "7",
            "--sequence",
            "17",
            "--client-blob-id",
            &blob_override,
            "--metadata-json",
            metadata_path.to_str().expect("metadata path"),
        ])
        .arg("--receipt-fixture")
        .arg(fixture_path.to_str().expect("fixture path"))
        .output()
        .expect("invoke iroha da submit");
    assert!(
        output.status.success(),
        "expected da submit to succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt_json_path = artifact_dir.join("da_receipt.json");
    let receipt_json =
        fs::read_to_string(&receipt_json_path).expect("read da_receipt.json contents");
    let value: Value = norito::json::from_str(&receipt_json).expect("parse receipt JSON");
    let pdp_json = value
        .get("pdp_commitment")
        .and_then(Value::as_str)
        .expect("pdp_commitment field");
    assert_eq!(pdp_json, BASE64.encode(&pdp_bytes));
    let receipt_norito_path = artifact_dir.join("da_receipt.norito");
    let receipt_bytes = fs::read(&receipt_norito_path).expect("read da_receipt.norito contents");
    let archived = norito::from_bytes::<DaIngestReceipt>(&receipt_bytes).expect("decode receipt");
    let decoded = DaIngestReceipt::deserialize(archived);
    assert_eq!(
        decoded.pdp_commitment.as_deref(),
        Some(pdp_bytes.as_slice())
    );
    let headers_path = artifact_dir.join("da_response_headers.json");
    let headers_json = fs::read_to_string(&headers_path).expect("read header json");
    let headers_value: Value = norito::json::from_str(&headers_json).expect("parse header json");
    let stored_header = headers_value
        .get("sora-pdp-commitment")
        .and_then(Value::as_str)
        .expect("sora-pdp-commitment header");
    assert_eq!(stored_header, pdp_header);
}
#[test]
fn da_rent_quote_outputs_summary_and_json() {
    const GIB: u64 = 12;
    const MONTHS: u32 = 3;
    const BASE: &str = "9";
    const RESERVE: &str = "1.8";
    const PROVIDER: &str = "7.2";
    const PDP: &str = "0.45";
    const POTR: &str = "0.225";
    const EGRESS_CREDIT: &str = "0.0015";
    let summary_output = command()
        .args([
            "--output-format",
            "text",
            "app",
            "da",
            "rent-quote",
            "--gib",
            &GIB.to_string(),
            "--months",
            &MONTHS.to_string(),
        ])
        .output()
        .expect("failed to execute iroha da rent-quote --output-format text");
    assert!(
        summary_output.status.success(),
        "rent-quote failed: {}",
        String::from_utf8_lossy(&summary_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&summary_output.stdout);
    let mut lines = stdout.lines();
    let summary_line = lines.next().expect("rent-quote should emit a summary line");
    assert!(
        summary_line.contains("rent_quote base=9 XOR"),
        "unexpected summary line: {summary_line}"
    );
    assert!(
        summary_line.contains("reserve=1.8 XOR"),
        "unexpected summary line: {summary_line}"
    );
    assert!(
        summary_line.contains("egress_credit_per_gib=0.0015 XOR/GiB"),
        "unexpected summary line: {summary_line}"
    );
    assert!(
        lines.any(|line| line.starts_with("policy_source: ")),
        "rent-quote summary should include policy source: {stdout}"
    );
    let json_output = command()
        .args([
            "app",
            "da",
            "rent-quote",
            "--gib",
            &GIB.to_string(),
            "--months",
            &MONTHS.to_string(),
        ])
        .output()
        .expect("failed to execute iroha da rent-quote");
    assert!(
        json_output.status.success(),
        "rent-quote failed: {}",
        String::from_utf8_lossy(&json_output.stderr)
    );
    let value: Value =
        norito::json::from_slice(&json_output.stdout).expect("rent-quote JSON output");
    assert_eq!(
        value.get("policy_source").and_then(Value::as_str),
        Some("embedded default policy")
    );
    assert_eq!(value.get("gib").and_then(Value::as_u64), Some(GIB));
    assert_eq!(
        value.get("months").and_then(Value::as_u64),
        Some(u64::from(MONTHS))
    );
    let quote = value
        .get("quote")
        .and_then(Value::as_object)
        .expect("quote object");
    let read_quantity = |map: &Map, key: &str| -> XorQuantity {
        let entry = map
            .get(key)
            .unwrap_or_else(|| panic!("missing `{key}` field"));
        xor_quantity_from_value(entry)
    };
    let expected = |raw: &str| raw.parse::<XorQuantity>().expect("canonical quantity");
    assert_eq!(read_quantity(quote, "base_rent"), expected(BASE));
    assert_eq!(read_quantity(quote, "protocol_reserve"), expected(RESERVE));
    assert_eq!(read_quantity(quote, "provider_reward"), expected(PROVIDER));
    assert_eq!(read_quantity(quote, "pdp_bonus"), expected(PDP));
    assert_eq!(read_quantity(quote, "potr_bonus"), expected(POTR));
    assert_eq!(
        read_quantity(quote, "egress_credit_per_gib"),
        expected(EGRESS_CREDIT)
    );
    let projection = value
        .get("ledger_projection")
        .and_then(Value::as_object)
        .expect("ledger projection object");
    assert_eq!(read_quantity(projection, "rent_due"), expected(BASE));
    assert_eq!(
        read_quantity(projection, "protocol_reserve_due"),
        expected(RESERVE)
    );
    assert_eq!(
        read_quantity(projection, "provider_reward_due"),
        expected(PROVIDER)
    );
    assert_eq!(read_quantity(projection, "pdp_bonus_pool"), expected(PDP));
    assert_eq!(read_quantity(projection, "potr_bonus_pool"), expected(POTR));
    assert_eq!(
        read_quantity(projection, "egress_credit_per_gib"),
        expected(EGRESS_CREDIT)
    );
}
#[test]
fn da_rent_ledger_emits_transfer_plan() {
    use torii_mock_support::TempDir;
    const GIB: u64 = 12;
    const MONTHS: u32 = 3;
    const BASE: &str = "9";
    const RESERVE: &str = "1.8";
    const PROVIDER: &str = "7.2";
    const PDP: &str = "0.45";
    const POTR: &str = "0.225";
    let temp_dir = TempDir::new("da_rent_ledger_plan").expect("temp dir");
    let quote_path = temp_dir.path().join("rent_quote.json");
    let quote_path_str = quote_path
        .to_str()
        .expect("quote path must be valid UTF-8")
        .to_string();
    let quote_output = command()
        .args([
            "app",
            "da",
            "rent-quote",
            "--gib",
            &GIB.to_string(),
            "--months",
            &MONTHS.to_string(),
            "--quote-out",
            &quote_path_str,
        ])
        .output()
        .expect("failed to execute iroha da rent-quote --quote-out");
    assert!(
        quote_output.status.success(),
        "rent-quote failed: {}",
        String::from_utf8_lossy(&quote_output.stderr)
    );
    let payer_account = parse_account_literal(alice_account_literal());
    let treasury_account = parse_account_literal(bob_account_literal());
    let protocol_account = account_id("protocol-da-ledger");
    let provider_account = account_id("provider-da-ledger");
    let pdp_account = account_id("pdp-da-ledger");
    let potr_account = account_id("potr-da-ledger");
    let payer_arg = account_literal(&payer_account);
    let treasury_arg = account_literal(&treasury_account);
    let protocol_arg = account_literal(&protocol_account);
    let provider_arg = account_literal(&provider_account);
    let pdp_arg = account_literal(&pdp_account);
    let potr_arg = account_literal(&potr_account);
    let asset_definition_arg = xor_asset_id().to_string();
    let ledger_output = command()
        .args([
            "app",
            "da",
            "rent-ledger",
            "--quote",
            &quote_path_str,
            "--payer-account",
            &payer_arg,
            "--treasury-account",
            &treasury_arg,
            "--protocol-reserve-account",
            &protocol_arg,
            "--provider-account",
            &provider_arg,
            "--pdp-bonus-account",
            &pdp_arg,
            "--potr-bonus-account",
            &potr_arg,
            "--asset-definition",
            &asset_definition_arg,
        ])
        .output()
        .expect("failed to execute iroha da rent-ledger");
    assert!(
        ledger_output.status.success(),
        "rent-ledger failed: {}",
        String::from_utf8_lossy(&ledger_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&ledger_output.stdout);
    let value: Value = norito::json::from_str(stdout.trim()).expect("rent-ledger output JSON");
    assert_eq!(
        value.get("quote_path").and_then(Value::as_str),
        Some(quote_path_str.as_str())
    );
    assert_eq!(
        value
            .get("rent_due")
            .map(xor_quantity_from_value)
            .expect("rent_due field"),
        BASE.parse::<XorQuantity>().expect("canonical quantity")
    );
    assert_eq!(
        value
            .get("protocol_reserve_due")
            .map(xor_quantity_from_value)
            .expect("protocol_reserve_due field"),
        RESERVE.parse::<XorQuantity>().expect("canonical quantity")
    );
    assert_eq!(
        value
            .get("provider_reward_due")
            .map(xor_quantity_from_value)
            .expect("provider_reward_due field"),
        PROVIDER.parse::<XorQuantity>().expect("canonical quantity")
    );
    assert_eq!(
        value
            .get("pdp_bonus_pool")
            .map(xor_quantity_from_value)
            .expect("pdp_bonus_pool field"),
        PDP.parse::<XorQuantity>().expect("canonical quantity")
    );
    assert_eq!(
        value
            .get("potr_bonus_pool")
            .map(xor_quantity_from_value)
            .expect("potr_bonus_pool field"),
        POTR.parse::<XorQuantity>().expect("canonical quantity")
    );
    for retired in [
        "rent_due_micro_xor",
        "protocol_reserve_due_micro_xor",
        "provider_reward_due_micro_xor",
        "pdp_bonus_pool_micro_xor",
        "potr_bonus_pool_micro_xor",
    ] {
        assert!(
            value.get(retired).is_none(),
            "retired implicit-unit alias `{retired}` must not be emitted"
        );
    }
    let instructions_value = value
        .get("instructions")
        .and_then(Value::as_array)
        .expect("instructions array");
    let instruction_bytes =
        norito::json::to_vec(instructions_value).expect("serialize instructions array");
    let instructions: Vec<InstructionBox> =
        norito::json::from_slice(&instruction_bytes).expect("decode rent ledger instructions");
    assert_eq!(
        instructions.len(),
        5,
        "expected rent ledger to emit five transfer instructions"
    );
    let payer_asset = AssetId::new(xor_asset_id(), payer_account.clone());
    let treasury_asset = AssetId::new(xor_asset_id(), treasury_account.clone());
    let (rent_source, rent_amount, rent_destination) = transfer_parts(&instructions[0]);
    assert_eq!(rent_source, &payer_asset);
    assert_eq!(rent_destination, &treasury_account);
    assert_quantity_xor(rent_amount, BASE);
    let (reserve_source, reserve_amount, reserve_destination) = transfer_parts(&instructions[1]);
    assert_eq!(reserve_source, &treasury_asset);
    assert_eq!(reserve_destination, &protocol_account);
    assert_quantity_xor(reserve_amount, RESERVE);
    let (provider_source, provider_amount, provider_destination) = transfer_parts(&instructions[2]);
    assert_eq!(provider_source, &treasury_asset);
    assert_eq!(provider_destination, &provider_account);
    assert_quantity_xor(provider_amount, PROVIDER);
    let (pdp_source, pdp_amount, pdp_destination) = transfer_parts(&instructions[3]);
    assert_eq!(pdp_source, &treasury_asset);
    assert_eq!(pdp_destination, &pdp_account);
    assert_quantity_xor(pdp_amount, PDP);
    let (potr_source, potr_amount, potr_destination) = transfer_parts(&instructions[4]);
    assert_eq!(potr_source, &treasury_asset);
    assert_eq!(potr_destination, &potr_account);
    assert_quantity_xor(potr_amount, POTR);
}
#[test]
fn repo_unwind_emits_instruction_payload() {
    use torii_mock_support::{TempDir, write_client_config};
    let temp_dir = TempDir::new("repo_unwind").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, "http://localhost").expect("write config");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .arg("--emit-instructions")
        .args(["app", "repo", "unwind", "--agreement-id", "daily_repo"])
        .output()
        .expect("failed to execute iroha repo unwind");
    assert!(
        output.status.success(),
        "repo unwind failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let instructions = parse_instruction_stdout(&stdout);
    assert_eq!(instructions.len(), 1, "expected a single instruction");
    let repo = repo_instruction(&instructions[0]);
    match repo {
        RepoInstructionBox::Reverse(isi) => {
            assert_eq!(isi.agreement_id().to_string(), "daily_repo");
        }
        other => panic!("unexpected instruction variant: {other:?}"),
    }
}
#[test]
fn settlement_dvp_emits_instruction_payload() {
    use torii_mock_support::{TempDir, write_client_config};
    let temp_dir = TempDir::new("settlement_dvp").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, "http://localhost").expect("write config");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .arg("--emit-instructions")
        .args([
            "app",
            "settlement",
            "dvp",
            "--settlement-id",
            "trade_dvp",
            "--delivery-asset",
            "4fEiy2n5VMFVfi6BzDJge519zAzg",
            "--delivery-quantity",
            "10",
            "--delivery-from",
            alice_account_literal(),
            "--delivery-to",
            bob_account_literal(),
            "--payment-asset",
            "7EAD8EFYUx1aVKZPUU1fyKvr8dF1",
            "--payment-quantity",
            "1000",
            "--payment-from",
            bob_account_literal(),
            "--payment-to",
            alice_account_literal(),
            "--order",
            "payment-then-delivery",
            "--atomicity",
            "all-or-nothing",
        ])
        .output()
        .expect("failed to execute iroha settlement dvp");
    assert!(
        output.status.success(),
        "settlement dvp failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let instructions = parse_instruction_stdout(&stdout);
    assert_eq!(instructions.len(), 1, "expected a single instruction");
    let settlement = settlement_instruction(&instructions[0]);
    match settlement {
        SettlementInstructionBox::Dvp(isi) => {
            let expected_delivery_from = parse_account_literal(alice_account_literal());
            let expected_payment_from = parse_account_literal(bob_account_literal());
            assert_eq!(isi.settlement_id().to_string(), "trade_dvp");
            assert_eq!(isi.delivery_leg().from(), &expected_delivery_from);
            assert_eq!(isi.payment_leg().from(), &expected_payment_from);
        }
        other => panic!("unexpected instruction variant: {other:?}"),
    }
}
#[test]
fn settlement_pvp_emits_instruction_payload() {
    use torii_mock_support::{TempDir, write_client_config};
    let temp_dir = TempDir::new("settlement_pvp").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, "http://localhost").expect("write config");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .arg("--emit-instructions")
        .args([
            "app",
            "settlement",
            "pvp",
            "--settlement-id",
            "trade_pvp",
            "--primary-asset",
            "7EAD8EFYUx1aVKZPUU1fyKvr8dF1",
            "--primary-quantity",
            "500",
            "--primary-from",
            alice_account_literal(),
            "--primary-to",
            bob_account_literal(),
            "--counter-asset",
            "5tPkFK6s2zUcd1qUHyTmY7fDVa2n",
            "--counter-quantity",
            "460",
            "--counter-from",
            bob_account_literal(),
            "--counter-to",
            alice_account_literal(),
        ])
        .output()
        .expect("failed to execute iroha settlement pvp");
    assert!(
        output.status.success(),
        "settlement pvp failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let instructions = parse_instruction_stdout(&stdout);
    assert_eq!(instructions.len(), 1, "expected a single instruction");
    let settlement = settlement_instruction(&instructions[0]);
    match settlement {
        SettlementInstructionBox::Pvp(isi) => {
            let expected_primary_from = parse_account_literal(alice_account_literal());
            let expected_counter_from = parse_account_literal(bob_account_literal());
            assert_eq!(isi.settlement_id().to_string(), "trade_pvp");
            assert_eq!(isi.primary_leg().from(), &expected_primary_from);
            assert_eq!(isi.counter_leg().from(), &expected_counter_from);
        }
        other => panic!("unexpected instruction variant: {other:?}"),
    }
}
#[test]
fn settlement_accepts_commit_atomicity() {
    use torii_mock_support::{TempDir, write_client_config};
    let temp_dir = TempDir::new("settlement_atomicity").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    let iso_path = temp_dir.path().join("dvp_preview.xml");
    write_client_config(&config_path, "http://localhost").expect("write config");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .arg("--emit-instructions")
        .args([
            "app",
            "settlement",
            "dvp",
            "--settlement-id",
            "trade_dvp",
            "--delivery-asset",
            "4fEiy2n5VMFVfi6BzDJge519zAzg",
            "--delivery-quantity",
            "10",
            "--delivery-from",
            alice_account_literal(),
            "--delivery-to",
            bob_account_literal(),
            "--payment-asset",
            "7EAD8EFYUx1aVKZPUU1fyKvr8dF1",
            "--payment-quantity",
            "1000",
            "--payment-from",
            bob_account_literal(),
            "--payment-to",
            alice_account_literal(),
            "--delivery-instrument-id",
            "US0378331005",
            "--atomicity",
            "commit-first-leg",
            "--iso-xml-out",
            iso_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("failed to execute iroha settlement dvp with atomicity flag");
    assert!(
        output.status.success(),
        "expected commit-first-leg atomicity to succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let instructions = parse_instruction_stdout(&stdout);
    assert_eq!(instructions.len(), 1, "expected a single instruction");
    let settlement = settlement_instruction(&instructions[0]);
    let plan = match settlement {
        SettlementInstructionBox::Dvp(isi) => *isi.plan(),
        other => panic!("unexpected instruction variant: {other:?}"),
    };
    assert_eq!(
        plan.atomicity(),
        SettlementAtomicity::CommitFirstLeg,
        "unexpected atomicity payload: {:?}",
        plan.atomicity()
    );
    let iso_xml = fs::read_to_string(&iso_path).expect("read iso preview");
    assert!(
        iso_xml.contains("COMMIT_FIRST_LEG"),
        "ISO preview should reflect atomicity"
    );
}
#[test]
fn query_help_documents_stdin_flow() {
    expect_subcommand_help(
        &["ledger", "query", "--help"],
        "Query using JSON input from stdin",
    );
}
#[test]
fn role_help_mentions_register() {
    expect_subcommand_help(
        &["ledger", "role", "--help"],
        "Register a role and grant it to the registrant",
    );
}
#[test]
fn zk_help_mentions_attachments() {
    expect_subcommand_help(
        &["app", "zk", "--help"],
        "Manage ZK attachments in the app API",
    );
}
#[test]
fn crypto_sm2_import_accepts_pem_files() {
    use torii_mock_support::{TempDir, write_client_config};
    let key =
        Sm2PrivateKey::new("pem-distid", [0x11; 32]).expect("deterministic SM2 key generation");
    let private_pem = key.to_pkcs8_pem().expect("encode SM2 private key");
    let public_pem = key
        .public_key()
        .to_public_key_pem()
        .expect("encode SM2 public key");
    let temp_dir = TempDir::new("crypto_sm2_import_pem").expect("create temp dir");
    let priv_path = temp_dir.path().join("private.pem");
    let pub_path = temp_dir.path().join("public.pem");
    fs::write(&priv_path, private_pem.as_bytes()).expect("write private PEM");
    fs::write(&pub_path, public_pem.as_bytes()).expect("write public PEM");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, "http://localhost").expect("write config");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "tools",
            "crypto",
            "sm2",
            "import",
            "--distid",
            "pem-distid",
            "--private-key-pem-file",
            priv_path.to_str().expect("utf-8 path"),
            "--public-key-pem-file",
            pub_path.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("invoke iroha crypto sm2 import --private-key-pem-file");
    assert!(
        output.status.success(),
        "crypto sm2 import failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: json::Value = json::from_str(stdout.trim()).expect("parse SM2 import JSON output");
    assert_eq!(
        value.get("distid").and_then(|v| v.as_str()),
        Some("pem-distid")
    );
    let output_public_pem = value
        .get("public_key_pem")
        .and_then(|v| v.as_str())
        .expect("public_key_pem field");
    assert_eq!(output_public_pem.trim_end(), public_pem.trim_end());
    let output_private_pem = value
        .get("private_key_pem")
        .and_then(|v| v.as_str())
        .expect("private_key_pem field");
    assert_eq!(output_private_pem.trim_end(), private_pem.trim_end());
}
#[test]
#[allow(clippy::too_many_lines)]
fn incentives_daemon_processes_metrics_spool() {
    let temp_dir = torii_mock_support::TempDir::new("incentives_daemon")
        .expect("temp dir for incentives daemon");
    let reward_config_path = write_reward_config_file(&temp_dir);
    let state_path = state_path(&temp_dir, "daemon_state.json");
    let metrics_dir = temp_dir.path().join("metrics");
    fs::create_dir_all(&metrics_dir).expect("create metrics dir");
    let instruction_dir = temp_dir.path().join("instructions");
    fs::create_dir_all(&instruction_dir).expect("create instruction dir");
    let transfer_dir = temp_dir.path().join("transfers");
    fs::create_dir_all(&transfer_dir).expect("create transfer dir");
    let archive_dir = temp_dir.path().join("archive");
    fs::create_dir_all(&archive_dir).expect("create archive dir");
    let bonds_dir = temp_dir.path().join("bonds");
    fs::create_dir_all(&bonds_dir).expect("create bonds dir");
    let bond_entry = sample_bond_entry();
    let bond_path = bonds_dir.join("relay-bond.to");
    let bond_bytes = to_bytes(&bond_entry).expect("encode bond entry");
    fs::write(&bond_path, bond_bytes).expect("write bond entry");
    let relay_hex = hex::encode(bond_entry.relay_id);
    let beneficiary_account = account_literal_for("relay1");
    let config_path = write_daemon_config(&temp_dir, &relay_hex, &beneficiary_account, &bond_path);
    let init_output = command()
        .args([
            "app",
            "sorafs",
            "incentives",
            "service",
            "init",
            "--state",
            state_path.to_str().unwrap(),
            "--config",
            reward_config_path.to_str().unwrap(),
            "--treasury-account",
            alice_account_literal(),
        ])
        .output()
        .expect("run incentives init");
    assert!(
        init_output.status.success(),
        "incentives init failed: {}",
        String::from_utf8_lossy(&init_output.stderr)
    );
    let mut metrics_a = sample_metrics();
    metrics_a.epoch = 42;
    metrics_a.verified_bandwidth_bytes = 5_000;
    write_metrics_snapshot(&metrics_dir, &metrics_a, "a");
    let mut metrics_b = metrics_a.clone();
    metrics_b.epoch = 43;
    metrics_b.verified_bandwidth_bytes = 7_500;
    write_metrics_snapshot(&metrics_dir, &metrics_b, "b");
    let daemon_output = command()
        .args([
            "app",
            "sorafs",
            "incentives",
            "service",
            "daemon",
            "--state",
            state_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
            "--metrics-dir",
            metrics_dir.to_str().unwrap(),
            "--instruction-out-dir",
            instruction_dir.to_str().unwrap(),
            "--transfer-out-dir",
            transfer_dir.to_str().unwrap(),
            "--archive-dir",
            archive_dir.to_str().unwrap(),
            "--once",
            "--pretty",
        ])
        .output()
        .expect("run incentives daemon");
    assert!(
        daemon_output.status.success(),
        "incentives daemon failed: {}",
        String::from_utf8_lossy(&daemon_output.stderr)
    );
    let summary: Value =
        norito::json::from_slice(&daemon_output.stdout).expect("daemon summary json");
    assert_eq!(
        summary["processed"]
            .as_array()
            .expect("processed array")
            .len(),
        2,
        "expected two processed payouts"
    );
    for entry in summary["processed"].as_array().expect("processed array") {
        assert_eq!(
            entry
                .get("budget_approval_id")
                .and_then(|value| value.as_str()),
            Some(SAMPLE_BUDGET_APPROVAL_ID),
            "budget approval id should be present on each processed payout"
        );
    }
    assert!(
        summary["errors"]
            .as_array()
            .expect("errors array")
            .is_empty(),
        "daemon reported errors: {summary:?}"
    );
    let state_json = read_state(&state_path);
    assert_eq!(
        state_json["payouts"]
            .as_array()
            .expect("payouts array")
            .len(),
        2,
        "state should record two payouts"
    );
    let mut instruction_files: Vec<PathBuf> = fs::read_dir(&instruction_dir)
        .expect("read instruction dir")
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    instruction_files.sort();
    assert_eq!(instruction_files.len(), 2, "expected two instruction files");
    let transfer_files: Vec<_> = fs::read_dir(&transfer_dir)
        .expect("read transfer dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect transfer dir");
    assert_eq!(transfer_files.len(), 2, "expected two transfer files");
    let archived_files: Vec<_> = fs::read_dir(&archive_dir)
        .expect("read archive dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect archive dir");
    assert_eq!(archived_files.len(), 2, "expected archived metrics files");
    let instructions = instruction_files
        .iter()
        .map(|path| {
            let bytes = fs::read(path).expect("read instruction file");
            norito::decode_from_bytes::<RelayRewardInstructionV1>(&bytes)
                .expect("decode reward instruction")
        })
        .collect::<Vec<_>>();
    let treasury_account = parse_account_literal(alice_account_literal());
    let transfers = instructions
        .iter()
        .map(|instruction| LedgerTransferRecord {
            relay_id: instruction.relay_id,
            epoch: instruction.epoch,
            kind: TransferKind::Payout,
            dispute_id: None,
            amount: instruction.payout_amount.clone(),
            source_asset: AssetId::new(
                instruction.payout_asset_id.clone(),
                treasury_account.clone(),
            ),
            destination: instruction.beneficiary.clone(),
        })
        .collect();
    let export = TestLedgerExport {
        version: 1,
        transfers,
    };
    let export_bytes = encode_ledger_export(&export);
    let ledger_export_path = temp_dir.path().join("ledger_export.to");
    fs::write(&ledger_export_path, export_bytes).expect("write ledger export");
    let reconcile_output = command()
        .args([
            "app",
            "sorafs",
            "incentives",
            "service",
            "reconcile",
            "--state",
            state_path.to_str().unwrap(),
            "--ledger-export",
            ledger_export_path.to_str().unwrap(),
            "--pretty",
        ])
        .output()
        .expect("run incentives reconcile");
    assert!(
        reconcile_output.status.success(),
        "reconcile failed: {}",
        String::from_utf8_lossy(&reconcile_output.stderr)
    );
    let reconcile_summary: Value =
        norito::json::from_slice(&reconcile_output.stdout).expect("reconcile summary json");
    assert!(
        reconcile_summary["clean"].as_bool().unwrap_or(false),
        "expected clean reconciliation, summary: {reconcile_summary:?}"
    );
    assert_eq!(
        reconcile_summary["total_expected_transfers"]
            .as_u64()
            .unwrap_or_default(),
        2
    );
    assert!(
        reconcile_summary["missing_transfers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
#[test]
fn tx_status_command_against_torii_mock() {
    use torii_mock_support::{
        SpawnError, TempDir, ToriiMockProcess, configure_pipeline, write_client_config,
    };
    let mock = match ToriiMockProcess::spawn() {
        Ok(proc) => proc,
        Err(SpawnError::PythonUnavailable | SpawnError::PermissionDenied) => {
            eprintln!("skipping tx_status_command_against_torii_mock: mock server unavailable");
            return;
        }
        Err(err) => panic!("failed to start Torii mock: {err}"),
    };
    let temp_dir = TempDir::new("tx_status").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, mock.base_url()).expect("write config");
    let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    configure_pipeline(
        mock.base_url(),
        &norito::json!({
            "hash": hash,
            "repeat_last": true,
            "statuses": [
                {
                    "kind": "Committed",
                    "block_height": 42,
                    "scope": "local",
                    "resolved_from": "state"
                }
            ]
        }),
    )
    .expect("configure pipeline");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .args(["tx", "status", "--hash", hash, "--scope", "local"])
        .output()
        .expect("failed to run iroha tx status");
    assert!(
        output.status.success(),
        "expected tx status to succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: json::Value = json::from_slice(&output.stdout).expect("tx status JSON");
    assert_eq!(payload["hash"].as_str(), Some(hash));
    assert_eq!(payload["status"]["kind"].as_str(), Some("Committed"));
    assert_eq!(payload["status"]["block_height"].as_u64(), Some(42));
    assert_eq!(payload["scope"].as_str(), Some("local"));
    assert_eq!(payload["resolved_from"].as_str(), Some("state"));
    let missing_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    for scope in [None, Some("global"), Some("local")] {
        let mut invocation = command();
        invocation
            .arg("--config")
            .arg(&config_path)
            .args(["tx", "status", "--hash", missing_hash]);
        if let Some(scope) = scope {
            invocation.args(["--scope", scope]);
        }
        let missing = invocation
            .output()
            .expect("failed to run iroha tx status for missing hash");
        assert!(
            !missing.status.success(),
            "expected missing tx status to fail for scope {scope:?}, stdout: {}",
            String::from_utf8_lossy(&missing.stdout)
        );
        assert!(
            String::from_utf8_lossy(&missing.stderr).contains("Transaction status not found"),
            "missing tx status stderr mismatch for scope {scope:?}: {}",
            String::from_utf8_lossy(&missing.stderr)
        );
    }
}
#[test]
fn account_get_command_against_torii_mock() {
    use torii_mock_support::{
        SpawnError, TempDir, ToriiMockProcess, configure_accounts, write_client_config,
    };
    let mock = match ToriiMockProcess::spawn() {
        Ok(proc) => proc,
        Err(SpawnError::PythonUnavailable | SpawnError::PermissionDenied) => {
            eprintln!("skipping account_get_command_against_torii_mock: mock server unavailable");
            return;
        }
        Err(err) => panic!("failed to start Torii mock: {err}"),
    };
    let temp_dir = TempDir::new("account_get").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, mock.base_url()).expect("write config");
    let account_id = alice_account_literal();
    configure_accounts(
        mock.base_url(),
        &norito::json!({
            "accounts": [
                {
                    "account_id": account_id,
                    "label": null,
                    "uaid": null,
                    "opaque_ids": []
                }
            ]
        }),
    )
    .expect("configure accounts");
    let output = command()
        .arg("--config")
        .arg(&config_path)
        .args(["account", "get", "--id", account_id])
        .output()
        .expect("failed to run iroha account get");
    assert!(
        output.status.success(),
        "expected account get to succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: json::Value = json::from_slice(&output.stdout).expect("account get JSON");
    assert_eq!(
        payload["account_id"].as_str(),
        Some(account_id),
        "canonical account id mismatch"
    );
    assert!(
        payload.get("linked_domains").is_none(),
        "account get should not expose linked_domains"
    );
    let missing = command()
        .arg("--config")
        .arg(&config_path)
        .args(["account", "get", "--id", bob_account_literal()])
        .output()
        .expect("failed to run iroha account get for missing account");
    assert!(
        !missing.status.success(),
        "expected missing account get to fail, stdout: {}",
        String::from_utf8_lossy(&missing.stdout)
    );
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("Failed to get account"),
        "missing account stderr mismatch: {}",
        String::from_utf8_lossy(&missing.stderr)
    );
}
// Coverage: The `zk_attachments_flow_against_torii_mock` test below exercises the
// upload/list/get/delete CLI paths against the lightweight Torii mock.
#[test]
#[allow(clippy::too_many_lines)]
fn zk_attachments_flow_against_torii_mock() {
    use torii_mock_support::{SpawnError, TempDir, ToriiMockProcess, write_client_config};
    let mock = match ToriiMockProcess::spawn() {
        Ok(proc) => proc,
        Err(SpawnError::PythonUnavailable | SpawnError::PermissionDenied) => {
            eprintln!("skipping zk_attachments_flow_against_torii_mock: mock server unavailable");
            return;
        }
        Err(err) => panic!("failed to start Torii mock: {err}"),
    };
    let temp_dir = TempDir::new("zk_attachment_flow").expect("temp dir");
    let config_path = temp_dir.path().join("client.toml");
    write_client_config(&config_path, mock.base_url()).expect("write config");
    let payload_path = temp_dir.path().join("payload.json");
    fs::write(&payload_path, b"{\"hello\":\"world\"}").expect("write payload");
    let upload = command()
        .arg("--config")
        .arg(&config_path)
        .args(["app", "zk", "attachments", "upload", "--file"])
        .arg(&payload_path)
        .args(["--content-type", "application/json"])
        .output()
        .expect("failed to run iroha zk attachments upload");
    assert!(
        upload.status.success(),
        "expected upload to succeed, stderr: {}",
        String::from_utf8_lossy(&upload.stderr)
    );
    let upload_meta: json::Value =
        json::from_slice(&upload.stdout).expect("upload returned JSON metadata");
    let attachment_id = upload_meta
        .get("id")
        .and_then(json::Value::as_str)
        .map(str::to_owned)
        .expect("attachment id present");
    assert_eq!(
        upload_meta
            .get("content_type")
            .and_then(json::Value::as_str),
        Some("application/json")
    );
    let list = command()
        .arg("--config")
        .arg(&config_path)
        .args(["app", "zk", "attachments", "list"])
        .output()
        .expect("failed to run iroha zk attachments list");
    assert!(
        list.status.success(),
        "expected list to succeed, stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_json: json::Value = json::from_slice(&list.stdout).expect("list JSON");
    let mut listed_ids = list_json
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|item| {
            item.get("id")
                .and_then(json::Value::as_str)
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    assert!(
        listed_ids.contains(&attachment_id),
        "attachment id not found in list"
    );
    let download_path = temp_dir.path().join("download.bin");
    let get = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "zk",
            "attachments",
            "get",
            "--id",
            attachment_id.as_str(),
            "--out",
        ])
        .arg(&download_path)
        .output()
        .expect("failed to run iroha zk attachments get");
    assert!(
        get.status.success(),
        "expected get to succeed, stderr: {}",
        String::from_utf8_lossy(&get.stderr)
    );
    let downloaded = fs::read(&download_path).expect("downloaded file readable");
    assert_eq!(downloaded, b"{\"hello\":\"world\"}");
    let delete = command()
        .arg("--config")
        .arg(&config_path)
        .args([
            "app",
            "zk",
            "attachments",
            "delete",
            "--id",
            attachment_id.as_str(),
        ])
        .output()
        .expect("failed to run iroha zk attachments delete");
    assert!(
        delete.status.success(),
        "expected delete to succeed, stderr: {}",
        String::from_utf8_lossy(&delete.stderr)
    );
    let list_after = command()
        .arg("--config")
        .arg(&config_path)
        .args(["app", "zk", "attachments", "list"])
        .output()
        .expect("failed to run iroha zk attachments list after delete");
    assert!(
        list_after.status.success(),
        "expected list after delete to succeed, stderr: {}",
        String::from_utf8_lossy(&list_after.stderr)
    );
    let after_json: json::Value = json::from_slice(&list_after.stdout).expect("list JSON");
    listed_ids = after_json
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|item| {
            item.get("id")
                .and_then(json::Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    assert!(
        !listed_ids.contains(&attachment_id),
        "attachment id still present after deletion"
    );
}
#[test]
fn address_convert_outputs_i105_by_default() {
    let key_pair = fixture_key_pair(0xA1);
    let account = AccountId::new(key_pair.public_key().clone());
    let expected_i105 = encode_account_id_to_i105(&account, 753).expect("i105 string");
    let output = command()
        .args(["tools", "address", "convert", &expected_i105])
        .output()
        .expect("run address convert");
    assert!(
        output.status.success(),
        "cli exited with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let rendered = if stdout.trim().is_empty() {
        stderr
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or_default()
            .trim()
            .to_owned()
    } else {
        stdout.trim().to_owned()
    };
    assert_eq!(rendered, expected_i105);
}
#[test]
fn address_convert_json_summary_contains_i105_and_canonical_hex() {
    let key_pair = fixture_key_pair(0xB2);
    let account = AccountId::new(key_pair.public_key().clone());
    let i105 = encode_account_id_to_i105(&account, 753).expect("i105 string");
    let canonical = encode_account_id_to_canonical_hex(&account).expect("canonical");
    let output = command()
        .args([
            "tools",
            "address",
            "convert",
            &i105,
            "--expect-prefix",
            "753",
            "--format",
            "json",
        ])
        .output()
        .expect("run address convert json");
    assert!(
        output.status.success(),
        "cli exited with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = norito::json::from_slice(&output.stdout).expect("parse summary");
    assert_eq!(
        summary
            .get("detected_format")
            .and_then(|value| value.get("kind"))
            .and_then(Value::as_str),
        Some("i105")
    );
    assert_eq!(
        summary
            .get("detected_format")
            .and_then(|value| value.get("network_prefix"))
            .and_then(Value::as_u64),
        None
    );
    assert_eq!(
        summary
            .get("i105")
            .and_then(|value| value.get("value"))
            .and_then(Value::as_str),
        Some(i105.as_str())
    );
    assert_eq!(
        summary
            .get("i105")
            .and_then(|value| value.get("network_prefix"))
            .and_then(Value::as_u64),
        Some(753)
    );
    assert_eq!(
        summary.get("canonical_hex").and_then(Value::as_str),
        Some(canonical.as_str())
    );
    assert!(
        summary.get("input_domain").is_none_or(Value::is_null),
        "input_domain should be null when no domain literal was provided"
    );
}
#[test]
fn address_convert_rejects_domain_suffix() {
    let domain: iroha_model_base::domain::DomainId =
        iroha_model_base::domain::DomainId::try_new("sora", "universal").expect("domain");
    let key_pair = fixture_key_pair(0xAB);
    let account = AccountId::new(key_pair.public_key().clone());
    let i105 = encode_account_id_to_i105(&account, 753).expect("i105");
    let literal = format!("{i105}@{domain}");
    let output = command()
        .current_dir(workspace_root())
        .args([
            "--config",
            "defaults/client.toml",
            "tools",
            "address",
            "convert",
            &literal,
            "--format",
            "i105",
        ])
        .output()
        .expect("run address convert");
    assert!(
        !output.status.success(),
        "convert should reject domain suffix: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must not include '@domain'") || stderr.contains("parse error"),
        "unexpected stderr: {stderr}"
    );
}
#[test]
fn address_convert_json_rejects_domain_suffix() {
    let key_pair = fixture_key_pair(0xC4);
    let account = AccountId::new(key_pair.public_key().clone());
    let i105 = encode_account_id_to_i105(&account, 753).expect("i105");
    let literal = format!("{i105}@universal");
    let output = command()
        .current_dir(workspace_root())
        .args([
            "--config",
            "defaults/client.toml",
            "tools",
            "address",
            "convert",
            &literal,
            "--network-prefix",
            "753",
            "--format",
            "json",
        ])
        .output()
        .expect("run address convert json");
    assert!(
        !output.status.success(),
        "convert json should reject domain suffix: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must not include '@domain'")
            || stderr.contains("address audit encountered 1 parse error(s)"),
        "unexpected stderr: {stderr}"
    );
}
#[test]
fn address_convert_json_summary_is_domainless() {
    let key_pair = fixture_key_pair(0xC4);
    let account = AccountId::new(key_pair.public_key().clone());
    let i105 = encode_account_id_to_i105(&account, 753).expect("i105");
    let output = command()
        .current_dir(workspace_root())
        .args([
            "--config",
            "defaults/client.toml",
            "tools",
            "address",
            "convert",
            &i105,
            "--network-prefix",
            "753",
            "--format",
            "json",
        ])
        .output()
        .expect("run address convert json");
    assert!(
        output.status.success(),
        "convert exited with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        norito::json::from_slice::<Value>(&output.stdout)
            .expect("summary json")
            .get("input_domain"),
        None
    );
}
#[test]
fn address_audit_reports_parsed_and_errors() {
    use torii_mock_support::TempDir;
    let first_account = AccountId::new(fixture_key_pair(0xC3).public_key().clone());
    let second_account = AccountId::new(fixture_key_pair(0x44).public_key().clone());
    let first_i105 = encode_account_id_to_i105(&first_account, 753).expect("i105");
    let second_i105 = encode_account_id_to_i105(&second_account, 753).expect("i105");
    let temp_dir = TempDir::new("address_audit_report").expect("temp dir");
    let input_path = temp_dir.path().join("addresses.txt");
    let contents = format!("# sample addresses\n{first_i105}\n{second_i105}\ninvalid-address\n");
    fs::write(&input_path, contents).expect("write addresses");
    let output = command()
        .current_dir(workspace_root())
        .args([
            "--config",
            "defaults/client.toml",
            "--output-format",
            "text",
            "tools",
            "address",
            "audit",
            "--input",
            input_path.to_str().expect("utf8 path"),
            "--network-prefix",
            "753",
            "--allow-errors",
        ])
        .output()
        .expect("run address audit");
    assert!(
        output.status.success(),
        "audit exited with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = norito::json::from_slice(&output.stdout).expect("report json");
    let stats = report.get("stats").expect("stats field");
    assert_address_audit_stats(stats);
    let entries = report
        .get("entries")
        .and_then(Value::as_array)
        .expect("entries");
    assert_eq!(entries.len(), 3);
    assert_parsed_address_entry(entries, &first_i105, &first_account);
    assert_parsed_address_entry(entries, &second_i105, &second_account);
    assert_error_entry(entries);
}
#[test]
fn address_audit_rejects_domain_suffix() {
    use torii_mock_support::TempDir;
    let account = account_id_for_domain("wonderland", 0xE5);
    let i105 = encode_account_id_to_i105(&account, 753).expect("i105");
    let literal = format!("{i105}@banka");
    let temp_dir = TempDir::new("address_audit_domain").expect("temp dir");
    let path = temp_dir.path().join("addresses.txt");
    fs::write(&path, format!("{literal}\n")).expect("write addresses");
    let output = command()
        .current_dir(workspace_root())
        .args([
            "--config",
            "defaults/client.toml",
            "tools",
            "address",
            "audit",
            "--input",
            path.to_str().expect("utf8 path"),
            "--network-prefix",
            "753",
        ])
        .output()
        .expect("run address audit");
    assert!(
        !output.status.success(),
        "audit should reject domain suffix: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must not include '@domain'") || stderr.contains("parse error"),
        "unexpected stderr: {stderr}"
    );
}
include!("cli_smoke/address_audit_csv_test.rs");

fn assert_address_audit_stats(stats_value: &Value) {
    let stats = stats_value
        .as_object()
        .expect("stats should be a JSON object");
    assert_eq!(
        stats
            .get("total")
            .and_then(Value::as_u64)
            .expect("total count"),
        3
    );
    assert_eq!(
        stats
            .get("parsed")
            .and_then(Value::as_u64)
            .expect("parsed count"),
        2
    );
    assert_eq!(
        stats
            .get("errors")
            .and_then(Value::as_u64)
            .expect("error count"),
        1
    );
}
fn assert_parsed_address_entry(entries: &[Value], expected_input: &str, account: &AccountId) {
    let parsed_entry = entry_by_input(entries, expected_input);
    assert_eq!(
        parsed_entry
            .get("status")
            .and_then(Value::as_str)
            .expect("status"),
        "parsed"
    );
    let summary = parsed_entry.get("summary").expect("parsed address summary");
    assert_eq!(summary.as_object().expect("summary object").len(), 3);
    assert_eq!(summary.get("domain"), None);
    assert_eq!(
        summary
            .pointer("/detected_format/kind")
            .and_then(Value::as_str),
        Some("i105")
    );
    assert_eq!(
        summary.pointer("/i105/value").and_then(Value::as_str),
        Some(expected_input)
    );
    assert_eq!(
        summary
            .pointer("/i105/network_prefix")
            .and_then(Value::as_u64),
        Some(753)
    );
    let canonical = encode_account_id_to_canonical_hex(account).expect("canonical account bytes");
    assert_eq!(
        summary.get("canonical_hex").and_then(Value::as_str),
        Some(canonical.as_str())
    );
}
fn assert_error_entry(entries: &[Value]) {
    let entry = entry_by_status(entries, "error");
    assert_eq!(
        entry
            .get("error")
            .and_then(|value| value.get("code"))
            .and_then(Value::as_str)
            .expect("error code"),
        "ERR_UNSUPPORTED_ADDRESS_FORMAT"
    );
}
fn entry_by_input<'a>(entries: &'a [Value], expected_input: &str) -> &'a Value {
    entries
        .iter()
        .find(|entry| {
            entry
                .get("input")
                .and_then(Value::as_str)
                .is_some_and(|value| value == expected_input)
        })
        .unwrap_or_else(|| panic!("missing entry for {expected_input}"))
}
fn entry_by_status<'a>(entries: &'a [Value], status: &str) -> &'a Value {
    entries
        .iter()
        .find(|entry| entry.get("status").and_then(Value::as_str) == Some(status))
        .unwrap_or_else(|| panic!("missing entry with status {status}"))
}
#[test]
fn space_directory_manifest_audit_bundle_cli() {
    use torii_mock_support::TempDir;
    let workspace = workspace_root();
    let manifest_fixture = workspace
        .join("fixtures")
        .join("space_directory")
        .join("capability")
        .join("cbdc_wholesale.manifest.json");
    let profile_fixture = workspace
        .join("fixtures")
        .join("space_directory")
        .join("profile")
        .join("cbdc_lane_profile.json");
    let manifest_fixture_str = manifest_fixture
        .to_str()
        .expect("manifest path utf-8")
        .to_owned();
    let profile_fixture_str = profile_fixture
        .to_str()
        .expect("profile path utf-8")
        .to_owned();
    let manifest_json: Value =
        json::from_slice(&fs::read(&manifest_fixture).expect("read manifest fixture"))
            .expect("parse manifest fixture");
    let expected_uaid = manifest_json
        .get("uaid")
        .and_then(Value::as_str)
        .expect("fixture uaid")
        .to_owned();
    let expected_dataspace = manifest_json
        .get("dataspace")
        .and_then(Value::as_u64)
        .expect("fixture dataspace");
    let temp_dir = TempDir::new("space_directory_audit_bundle").expect("temp dir");
    let bundle_dir = temp_dir.path().join("bundle");
    let bundle_dir_str = bundle_dir.to_str().expect("bundle path utf-8").to_owned();
    let status = command()
        .args([
            "app",
            "space-directory",
            "manifest",
            "audit-bundle",
            "--manifest-json",
            &manifest_fixture_str,
            "--profile",
            &profile_fixture_str,
            "--out-dir",
            &bundle_dir_str,
            "--notes",
            "cli-smoke",
        ])
        .status()
        .expect("run audit bundle CLI");
    assert!(status.success(), "audit bundle command failed");
    let bundle_path = bundle_dir.join("audit_bundle.json");
    assert!(bundle_path.exists(), "missing audit bundle output");
    let manifest_to_path = bundle_dir.join("manifest.to");
    let manifest_to_bytes = fs::read(&manifest_to_path).expect("read manifest Norito payload");
    let expected_hash = iroha_crypto::Hash::new(&manifest_to_bytes);
    let expected_hash_hex = hex::encode(expected_hash.as_ref());
    let bundle_json: Value =
        json::from_slice(&fs::read(&bundle_path).expect("read bundle")).expect("parse bundle json");
    assert_eq!(
        bundle_json.get("uaid").and_then(Value::as_str),
        Some(expected_uaid.as_str()),
        "bundle UAID mismatch"
    );
    assert_eq!(
        bundle_json.get("dataspace_id").and_then(Value::as_u64),
        Some(expected_dataspace),
        "bundle dataspace mismatch"
    );
    assert_eq!(
        bundle_json.get("manifest_hash").and_then(Value::as_str),
        Some(expected_hash_hex.as_str()),
        "bundle hash mismatch"
    );
    assert_eq!(
        bundle_json.get("notes").and_then(Value::as_str),
        Some("cli-smoke"),
        "notes field missing"
    );
    assert_eq!(
        bundle_json
            .get("artifacts")
            .and_then(|value| value.get("manifest_json"))
            .and_then(Value::as_str),
        Some("manifest.json"),
        "artifact manifest reference mismatch"
    );
}
mod torii_mock_support {
    use norito::json;
    use std::{
        env, fmt, fs,
        io::{self, BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::mpsc,
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use url::Url;
    const MOCK_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
    #[derive(Debug)]
    pub enum SpawnError {
        PythonUnavailable,
        PermissionDenied,
        Io(io::Error),
        Setup(String),
    }
    impl fmt::Display for SpawnError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                SpawnError::PythonUnavailable => write!(f, "python interpreter not found"),
                SpawnError::PermissionDenied => {
                    write!(
                        f,
                        "mock server cannot bind to localhost in this environment"
                    )
                }
                SpawnError::Io(err) => write!(f, "{err}"),
                SpawnError::Setup(msg) => write!(f, "{msg}"),
            }
        }
    }
    impl From<io::Error> for SpawnError {
        fn from(err: io::Error) -> Self {
            SpawnError::Io(err)
        }
    }
    pub struct ToriiMockProcess {
        child: std::process::Child,
        base_url: String,
        stdout_thread: Option<std::thread::JoinHandle<()>>,
    }
    impl ToriiMockProcess {
        pub fn spawn() -> Result<Self, SpawnError> {
            match TcpListener::bind(("127.0.0.1", 0)) {
                Ok(listener) => drop(listener),
                Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                    return Err(SpawnError::PermissionDenied);
                }
                Err(_) => {}
            }
            let workspace_dir = workspace_root();
            let script_path = workspace_dir.join("python/iroha_torii_client/mock.py");
            let module = "iroha_torii_client.mock";
            let mut last_error: Option<io::Error> = None;
            for candidate in ["python3", "python"] {
                let mut cmd = Command::new(candidate);
                if script_path.is_file() {
                    cmd.arg(&script_path);
                } else {
                    cmd.arg("-m").arg(module);
                }
                cmd.arg("--stdio")
                    .env("PYTHONUNBUFFERED", "1")
                    .env("PYTHONPATH", python_path_env(&workspace_dir))
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit());
                let mut child = match cmd.spawn() {
                    Ok(child) => child,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        continue;
                    }
                    Err(err) => return Err(SpawnError::Io(err)),
                };
                let stdout = child
                    .stdout
                    .take()
                    .ok_or_else(|| SpawnError::Setup("missing stdout pipe".into()))?;
                let (line_tx, line_rx) = mpsc::channel();
                let startup_thread = thread::spawn(move || {
                    let mut reader = BufReader::new(stdout);
                    let mut line = String::new();
                    let result = reader.read_line(&mut line).map(|read| (read, line, reader));
                    let _ = line_tx.send(result);
                });
                match line_rx.recv_timeout(MOCK_STARTUP_TIMEOUT) {
                    Ok(Ok((0, _, _))) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = startup_thread.join();
                        last_error = Some(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "torii mock exited early",
                        ));
                    }
                    Ok(Ok((_, line, reader))) => {
                        let _ = startup_thread.join();
                        let base_url = match parse_base_url(line.trim()) {
                            Ok(base_url) => base_url,
                            Err(err) => {
                                let _ = child.kill();
                                let _ = child.wait();
                                return Err(err);
                            }
                        };
                        let stdout_thread = thread::spawn(move || {
                            let mut reader = reader;
                            let mut sink = io::sink();
                            let _ = io::copy(&mut reader, &mut sink);
                        });
                        return Ok(Self {
                            child,
                            base_url,
                            stdout_thread: Some(stdout_thread),
                        });
                    }
                    Ok(Err(err)) => {
                        let _ = startup_thread.join();
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(SpawnError::Io(err));
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = startup_thread.join();
                        return Err(SpawnError::Setup(format!(
                            "torii mock did not announce base_url within {MOCK_STARTUP_TIMEOUT:?}"
                        )));
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = startup_thread.join();
                        return Err(SpawnError::Setup(
                            "torii mock startup reader stopped before base_url".into(),
                        ));
                    }
                }
            }
            if let Some(err) = last_error {
                return Err(SpawnError::Io(err));
            }
            Err(SpawnError::PythonUnavailable)
        }
        pub fn base_url(&self) -> &str {
            &self.base_url
        }
    }
    impl Drop for ToriiMockProcess {
        fn drop(&mut self) {
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
            if let Some(handle) = self.stdout_thread.take() {
                let _ = handle.join();
            }
        }
    }
    pub struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        pub fn new(prefix: &str) -> io::Result<Self> {
            let mut path = std::env::temp_dir();
            let unique = format!(
                "{prefix}_{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            );
            path.push(unique);
            fs::create_dir(&path)?;
            Ok(Self { path })
        }
        pub fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
    pub fn write_client_config(path: &Path, base_url: &str) -> io::Result<()> {
        let torii_url = format!("{}/", base_url.trim_end_matches('/'));
        let contents = format!(
            "chain = \"00000000-0000-0000-0000-000000000000\"\n\
network_id = \"{network_id}\"\n\
torii_url = \"{torii_url}\"\n\
\n\
[basic_auth]\n\
web_login = \"mad_hatter\"\n\
password = \"ilovetea\"\n\
\n\
[account]\n\
chain_discriminant = 753\n\
public_key = \"ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03\"\n\
private_key = \"{private_key}\"\n",
            private_key = super::ALICE_PRIVATE_KEY,
            network_id = super::MOCK_NETWORK_ID,
        );
        fs::write(path, contents)
    }
    fn post_mock_config(base_url: &str, endpoint: &str, config: &json::Value) -> io::Result<()> {
        let base =
            Url::parse(base_url).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let target = base
            .join(endpoint)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let host = target
            .host_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing host"))?;
        let port = target.port_or_known_default().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing port for mock server")
        })?;
        let path = target.path().to_string();
        let body =
            json::to_vec(config).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let mut stream = TcpStream::connect((host, port))?;
        stream.set_read_timeout(Some(MOCK_STARTUP_TIMEOUT))?;
        stream.set_write_timeout(Some(MOCK_STARTUP_TIMEOUT))?;
        write!(
            stream,
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            path,
            host,
            port,
            body.len()
        )?;
        stream.write_all(&body)?;
        stream.flush()?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        if !(response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200")) {
            return Err(io::Error::other(format!("mock config failed: {response}")));
        }
        Ok(())
    }
    pub fn configure_governance(base_url: &str, config: &json::Value) -> io::Result<()> {
        post_mock_config(base_url, "__mock__/gov/config", config)
    }
    pub fn configure_pipeline(base_url: &str, config: &json::Value) -> io::Result<()> {
        post_mock_config(base_url, "__mock__/pipeline/config", config)
    }
    pub fn configure_accounts(base_url: &str, config: &json::Value) -> io::Result<()> {
        post_mock_config(base_url, "__mock__/accounts/config", config)
    }
    pub fn configure_sumeragi(base_url: &str, config: &json::Value) -> io::Result<()> {
        post_mock_config(base_url, "__mock__/sumeragi/config", config)
    }
    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .expect("workspace root")
    }
    fn python_path_env(root: &Path) -> String {
        let dir_str = root.join("python").to_string_lossy().into_owned();
        match env::var("PYTHONPATH") {
            Ok(existing) if !existing.is_empty() => format!("{dir_str}:{existing}"),
            _ => dir_str,
        }
    }
    fn parse_base_url(line: &str) -> Result<String, SpawnError> {
        let value: json::Value = json::from_str(line).map_err(|err| {
            SpawnError::Setup(format!("mock server announced invalid JSON: {err}"))
        })?;
        value
            .get("base_url")
            .and_then(json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| SpawnError::Setup("mock server did not report base_url".into()))
    }
}
