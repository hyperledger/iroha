//! Installed-runtime checks with no supplied configuration or build tools on PATH.

use iroha::{client::Client, data_model::account::address::ChainDiscriminantGuard};
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    smart_contract::{ContractAddress, ContractArtifactId},
};
use iroha_deploy::managed::{ManagedDeploymentExecution, ManagedParentReport, ManagedStore};
use norito::json::{self, Value};
use std::{
    error::Error,
    fs::{self, File},
    io::Read as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(super) mod cold_start_smoke;
mod context_smoke;
mod publication_smoke;

const LOCAL_CLEANUP: [&str; 3] = ["localnet", "down", "local"];
const COMMAND_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_OUTPUT: u64 = 1024 * 1024;
const SOURCE: &str = "seiyaku BundleSmoke { view fn quote(int cups) authorize(anyone) -> int { return cups * 10; } }";
const PACKAGE_SOURCE: &str = "seiyaku BundlePackage { view fn quote(int cups) authorize(anyone) -> int { return cups * 30; } }";
const PACKAGE_MANIFEST: &str = r#"manifest-version = 1

[package]
namespace = "smoke"
name = "bundle-package"
version = "0.1.0"
edition = "1"
abi-version = 1

[[contract]]
name = "bundle-package"
path = "contract.ko"
"#;

const BYTECODE_SOURCE: &str = "seiyaku BundleBytecodeFixture { view fn quote(int cups) authorize(anyone) -> int { return cups * 20; } }";

/// Compile fixture input offline with the canonical compiler, outside every measured command.
/// This compiler belongs to the test controller; installed products still need only the bundle.
pub(super) fn prepare_distinct_bytecode() -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(BYTECODE_SOURCE)
        .map_err(|_| "canonical bytecode fixture compilation failed")?
        .0)
}

pub(super) fn require_distinct_artifacts(deployments: &[&Value]) -> Result<(), Box<dyn Error>> {
    let mut hashes = std::collections::BTreeSet::new();
    for deployment in deployments {
        let value = deployment
            .get("receipt")
            .and_then(|receipt| receipt.get("code_hash"))
            .cloned()
            .ok_or("missing artifact code hash")?;
        let hash: iroha_crypto::Hash = json::from_value(value)?;
        if !hashes.insert(hash) {
            return Err("deployment input cases must upload distinct artifacts".into());
        }
    }
    Ok(())
}

pub(super) fn run(kagami: &Path) -> Result<(), Box<dyn Error>> {
    let bytecode = prepare_distinct_bytecode()?;
    let mut harness = Harness::new(kagami)?;
    let result = harness.exercise(&bytecode);
    // Cleanup is itself a required observation. On uncertainty retain custody and logs instead
    // of deleting a directory which an owned worker or validator could still be using.
    let stopped = harness
        .command(&LOCAL_CLEANUP)
        .and_then(|value| require_zero_owned_resources(&value));
    match (result, stopped) {
        (Ok(()), Ok(())) => Ok(()),
        (result, stopped) => {
            let root = harness.root.keep();
            Err(format!("installed developer smoke failed; retained diagnostics at {}: flow={result:?}; cleanup={stopped:?}", root.display()).into())
        }
    }
}

pub(super) struct Harness {
    root: tempfile::TempDir,
    kagami: PathBuf,
    pub(super) workspace: PathBuf,
    state: PathBuf,
    empty_path: PathBuf,
    sequence: usize,
}

impl Harness {
    pub(super) fn new(kagami: &Path) -> Result<Self, Box<dyn Error>> {
        let root = tempfile::Builder::new()
            .prefix("iroha-bundle-smoke-")
            .tempdir()?;
        let workspace = root.path().join("workspace");
        let empty_path = root.path().join("empty-path");
        fs::create_dir(&workspace)?;
        fs::create_dir(&empty_path)?;
        fs::write(workspace.join("hello.ko"), SOURCE)?;
        Ok(Self {
            kagami: kagami.canonicalize()?,
            state: root.path().join("state"),
            root,
            workspace,
            empty_path,
            sequence: 0,
        })
    }

    pub(super) fn command(&mut self, args: &[&str]) -> Result<Value, Box<dyn Error>> {
        let observation = self.observe_command(args);
        eprintln!(
            "[developer-smoke] kagami {}: {:.2}s",
            args.join(" "),
            Duration::from_nanos(observation.elapsed_ns).as_secs_f64()
        );
        observation.value.ok_or_else(|| {
            format!(
                "installed CLI command did not complete: {}",
                observation.outcome.as_str()
            )
            .into()
        })
    }

    /// Observe the installed CLI directly; latency samples retain only a closed failure code.
    pub(super) fn observe_command(&mut self, args: &[&str]) -> super::latency::CommandObservation {
        use super::latency::{CommandObservation, Outcome};
        let started = Instant::now();
        let result = self
            .command_document(args, started + COMMAND_TIMEOUT, false)
            .and_then(|document| {
                if document.exit_code == Some(0) {
                    Ok(document.value)
                } else {
                    Err(Outcome::CommandFailed)
                }
            });
        CommandObservation {
            elapsed_ns: u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
            outcome: result
                .as_ref()
                .map_or_else(|error| *error, |_| Outcome::Succeeded),
            value: result.ok(),
        }
    }

    /// List installed public presets through the same bounded child and output owner.
    /// This command creates no managed state and accepts no --state option.
    pub(super) fn network_names(&mut self) -> Result<Value, Box<dyn Error>> {
        let document = self
            .command_document_with_store(
                &["dataspace", "networks"],
                Instant::now() + COMMAND_TIMEOUT,
                false,
                false,
            )
            .map_err(|error| format!("installed network listing failed: {}", error.as_str()))?;
        Ok(document.value)
    }

    // Publication needs the canonical error document as well as its process status. Every command
    // still uses this one child/timeout/log owner; ordinary smoke and latency reject nonzero exits.
    fn command_document(
        &mut self,
        args: &[&str],
        deadline: Instant,
        include_failure: bool,
    ) -> Result<CommandDocument, super::latency::Outcome> {
        self.command_document_with_store(args, deadline, include_failure, true)
    }

    fn command_document_with_store(
        &mut self,
        args: &[&str],
        deadline: Instant,
        include_failure: bool,
        include_state: bool,
    ) -> Result<CommandDocument, super::latency::Outcome> {
        use super::latency::Outcome;
        let started = Instant::now();
        let deadline = deadline.min(started + COMMAND_TIMEOUT);
        if started >= deadline {
            return Err(Outcome::TimedOut);
        }
        self.sequence += 1;
        let stdout = self.root.path().join(format!("{}.stdout", self.sequence));
        let stderr = self.root.path().join(format!("{}.stderr", self.sequence));
        let mut child = self
            .command_builder(args, include_state)
            .stdout(File::create(&stdout).map_err(|_| Outcome::ControllerIo)?)
            .stderr(File::create(&stderr).map_err(|_| Outcome::ControllerIo)?)
            .spawn()
            .map_err(|_| Outcome::SpawnFailed)?;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|_| Outcome::ControllerIo)? {
                break status;
            }
            if Instant::now() >= deadline {
                // Only this unreaped command child is terminated. The managed worker and its
                // validators are stopped separately through the authenticated localnet owner.
                child.kill().map_err(|_| Outcome::ControllerIo)?;
                child.wait().map_err(|_| Outcome::ControllerIo)?;
                return Err(Outcome::TimedOut);
            }
            thread::sleep(Duration::from_millis(50));
        };
        if !status.success() && !include_failure {
            return Err(Outcome::CommandFailed);
        }
        let mut bytes = Vec::new();
        File::open(stdout)
            .map_err(|_| Outcome::ControllerIo)?
            .take(MAX_OUTPUT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Outcome::ControllerIo)?;
        let value = parse_command_output(&bytes)?;
        Ok(CommandDocument {
            exit_code: status.code(),
            value,
        })
    }

    fn command_builder(&self, args: &[&str], include_state: bool) -> Command {
        let mut command = Command::new(&self.kagami);
        command.args(args);
        if include_state {
            command.arg("--state").arg(&self.state);
        }
        command
            .arg("--json")
            .current_dir(&self.workspace)
            .env("PATH", &self.empty_path)
            .stdin(Stdio::null());
        command
    }

    pub(super) fn retain(self) {
        let retained = self.root.keep();
        eprintln!(
            "retained private developer diagnostics at {}",
            retained.display()
        );
    }

    pub(super) fn stop(&mut self) -> bool {
        self.command(&LOCAL_CLEANUP)
            .and_then(|value| require_zero_owned_resources(&value))
            .is_ok()
    }

    fn exercise(&mut self, prepared_bytecode: &[u8]) -> Result<(), Box<dyn Error>> {
        // Public input mistakes must fail before a managed store or worker can exist. These
        // use the same installed executable, bounded command owner and empty PATH as deploy.
        let invalid_artifact = self.workspace.join("invalid.to");
        let invalid_package = self.workspace.join("invalid-package");
        let invalid_manifest = invalid_package.join("Musubi.toml");
        fs::write(&invalid_artifact, b"not an IVM artifact")?;
        fs::create_dir(&invalid_package)?;
        fs::write(&invalid_manifest, b"[broken")?;
        for (input, expected_error) in [
            ("invalid.to", "invalid contract artifact"),
            ("invalid-package/Musubi.toml", "invalid or duplicate TOML"),
            ("invalid-package", "invalid or duplicate TOML"),
        ] {
            match fs::symlink_metadata(&self.state) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err("invalid-input smoke requires an absent managed store".into()),
            }
            let observation = self.observe_command(&["contract", "deploy", input]);
            if !matches!(observation.outcome, super::latency::Outcome::CommandFailed) {
                return Err(format!(
                    "invalid {input} was not rejected by the installed CLI: {}",
                    observation.outcome.as_str()
                )
                .into());
            }
            // A crash, argument error or unrelated runtime failure is not input admission.
            // Read only the already closed bounded diagnostic owned by this command.
            let mut diagnostic = String::new();
            File::open(self.root.path().join(format!("{}.stderr", self.sequence)))?
                .take(MAX_OUTPUT + 1)
                .read_to_string(&mut diagnostic)?;
            if diagnostic.len() as u64 > MAX_OUTPUT || !diagnostic.contains(expected_error) {
                return Err(format!("invalid {input} did not report its local input error").into());
            }
            match fs::symlink_metadata(&self.state) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(format!("invalid {input} created managed state").into()),
            }
        }
        fs::remove_file(invalid_artifact)?;
        fs::remove_file(invalid_manifest)?;
        fs::remove_dir(invalid_package)?;
        // The first valid call must both provision the network and deploy from raw source.
        let first = self.command(&["contract", "deploy", "hello.ko"])?;
        require_deployment(&first)?;
        let initial = self.command(&["localnet", "status"])?;
        require_phase(&initial, "ready", 4)?;
        self.execute_on_every_peer(&first, "30")?;
        let repeated_up = self.command(&["localnet", "up"])?;
        require_same_context(&initial, &repeated_up)?;
        require_phase(&repeated_up, "ready", 4)?;
        let repeated_deploy = self.command(&["contract", "deploy", "hello.ko"])?;
        require_same_deployment(&first, &repeated_deploy)?;
        let files = fs::read_dir(&self.workspace)?.collect::<Result<Vec<_>, _>>()?;
        if files.len() != 1 || files[0].file_name() != "hello.ko" {
            return Err("config-free deployment wrote additional files into the project".into());
        }
        // Deploy the independently hash-checked, distinct setup artifact through the bytecode
        // entry point. No compiler or external build tool is used by the installed workflow.
        fs::write(self.workspace.join("hello.to"), prepared_bytecode)?;
        // The embedded artifact name selects its alias, as on the source/package paths.
        // Explicit-alias installed coverage remains in the separate ready-latency fixture.
        let bytecode_args = ["contract", "deploy", "hello.to"];
        let bytecode = self.command(&bytecode_args)?;
        require_deployment(&bytecode)?;
        self.execute_on_every_peer(&bytecode, "60")?;
        let package = self.workspace.join("package");
        fs::create_dir(&package)?;
        fs::write(package.join("Musubi.toml"), PACKAGE_MANIFEST)?;
        fs::write(package.join("contract.ko"), PACKAGE_SOURCE)?;
        let packaged = self.command(&["contract", "deploy", "package"])?;
        require_deployment(&packaged)?;
        self.execute_on_every_peer(&packaged, "90")?;
        let repeated_bytecode = self.command(&bytecode_args)?;
        require_same_deployment(&bytecode, &repeated_bytecode)?;
        let repeated_package = self.command(&["contract", "deploy", "package"])?;
        require_same_deployment(&packaged, &repeated_package)?;
        let stopped = self.command(&["localnet", "down"])?;
        require_phase(&stopped, "stopped", 0)?;
        let restarted = self.command(&["localnet", "up"])?;
        require_phase(&restarted, "ready", 4)?;
        require_same_context(&initial, &restarted)?;
        let retained_deploy = self.command(&["contract", "deploy", "hello.ko"])?;
        require_same_deployment(&first, &retained_deploy)?;
        let retained_bytecode = self.command(&bytecode_args)?;
        require_same_deployment(&bytecode, &retained_bytecode)?;
        let retained_package = self.command(&["contract", "deploy", "package"])?;
        require_same_deployment(&packaged, &retained_package)?;
        require_distinct_artifacts(&[&first, &bytecode, &packaged])?;
        for (deployment, expected) in [
            (&retained_deploy, "30"),
            (&retained_bytecode, "60"),
            (&retained_package, "90"),
        ] {
            self.execute_on_every_peer(deployment, expected)?;
        }
        publication_smoke::run(self)?;
        context_smoke::run(self, &initial, &first)
    }

    pub(super) fn execute_on_every_peer(
        &self,
        deployment: &Value,
        expected_result: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.execute_on_every_peer_in_context(deployment, expected_result, None, None)
    }

    fn execute_on_every_peer_in_context(
        &self,
        deployment: &Value,
        expected_result: &str,
        requested_context: Option<&str>,
        operation_deadline: Option<Instant>,
    ) -> Result<(), Box<dyn Error>> {
        let store = ManagedStore::open(&self.state)?;
        let context = store.context(requested_context)?;
        let prepared = store.prepared(&context.name)?;
        if prepared.peers.len() != 4 {
            return Err(
                "installed execution smoke requires exactly four retained validators".into(),
            );
        }
        let config = context.load_client_config()?;
        let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
        let artifact = receipt_artifact(deployment, &context.network_id, context.dataspace_id)?;
        let address: ContractAddress = json::from_value(
            deployment
                .get("receipt")
                .and_then(|receipt| receipt.get("contract_address"))
                .cloned()
                .ok_or("deployment has no contract address")?,
        )?;
        let authority = config.account.clone();
        // IVM integers use canonical decimal strings in JSON, including small values.
        let payload = norito::json!({"cups": "3"});
        for (index, peer) in prepared.peers.iter().enumerate() {
            let mut selected = config.clone();
            selected.torii_api_url = peer.torii_url.parse()?;
            let per_peer_deadline = Instant::now() + Duration::from_secs(10);
            let deadline = operation_deadline.map_or(per_peer_deadline, |original| {
                original.min(per_peer_deadline)
            });
            if Instant::now() >= deadline {
                return Err("installed execution observation deadline elapsed".into());
            }
            let client = Client::builder(selected)
                .build()?
                .with_request_deadline(deadline);
            let mut first_error = None;
            let response = loop {
                match client.post_contract_view_json(
                    &authority,
                    Some(&address),
                    None,
                    "quote",
                    Some(&payload),
                    1_500_000,
                ) {
                    Ok(response) => break response,
                    Err(error) if Instant::now() < deadline => {
                        first_error.get_or_insert_with(|| format!("{error:#}"));
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(error) => {
                        return Err(format!(
                            "live contract view failed on peer {index}: {error:#}; first failure: {}",
                            first_error.as_deref().unwrap_or("same request")
                        )
                        .into());
                    }
                }
            };
            require_view(&response, &address, &artifact, expected_result)?;
            if client.get_contract_code_bytes(&artifact)?.is_empty() {
                return Err("deployed artifact readback is empty".into());
            }
        }
        Ok(())
    }
}

// These are presentation observations, never native finality or a publication capability.
struct CommandDocument {
    exit_code: Option<i32>,
    value: Value,
}
fn parse_command_output(bytes: &[u8]) -> Result<Value, super::latency::Outcome> {
    if bytes.len() as u64 > MAX_OUTPUT {
        return Err(super::latency::Outcome::OutputRejected);
    }
    json::from_slice(bytes).map_err(|_| super::latency::Outcome::OutputRejected)
}

fn receipt_artifact(
    deployment: &Value,
    network: &str,
    dataspace: u64,
) -> Result<ContractArtifactId, Box<dyn Error>> {
    require_deployment(deployment)?;
    let execution: ManagedDeploymentExecution = json::from_value(
        deployment
            .get("execution")
            .cloned()
            .ok_or("deployment omits its original execution scope")?,
    )?;
    let parent: Option<ManagedParentReport> = json::from_value(
        deployment
            .get("parent")
            .cloned()
            .ok_or("deployment omits its separate parent observation")?,
    )?;
    let valid_scope = match execution.root_scope {
        SumeragiRootScope::Global => dataspace == 0 && parent.is_none(),
        SumeragiRootScope::Dataspace {
            parent_network_id,
            dataspace_id,
        } => {
            dataspace_id.as_u64() == dataspace
                && parent.as_ref().is_some_and(|parent| {
                    parent.parent_network_id == parent_network_id
                        && parent.child_network_id == execution.network_id
                })
        }
    };
    if execution.network_id.to_string() != network || !valid_scope {
        return Err("deployment execution or parent observation belongs to another root".into());
    }
    let receipt = deployment
        .get("receipt")
        .ok_or("missing deployment receipt")?;
    if receipt.get("network_id").and_then(Value::as_str) != Some(network)
        || receipt.get("dataspace_id").and_then(Value::as_u64) != Some(dataspace)
        || receipt
            .get("stored_artifact_matches")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(
            "deployment receipt differs from the selected network or artifact scope".into(),
        );
    }
    Ok(ContractArtifactId::new(
        iroha_model_base::topology::DataSpaceId::new(dataspace),
        json::from_value(
            receipt
                .get("code_hash")
                .cloned()
                .ok_or("missing artifact hash")?,
        )?,
    ))
}

fn require_view(
    response: &Value,
    address: &ContractAddress,
    artifact: &ContractArtifactId,
    expected_result: &str,
) -> Result<(), Box<dyn Error>> {
    if address.dataspace_id()? != artifact.dataspace_id
        || response.get("ok").and_then(Value::as_bool) != Some(true)
        || response.get("contract_address") != Some(&json::to_value(address)?)
        || response.get("code_hash_hex").and_then(Value::as_str)
            != Some(hex::encode(artifact.code_hash.as_ref()).as_str())
        || response.get("entrypoint").and_then(Value::as_str) != Some("quote")
        || response.get("result").and_then(Value::as_str) != Some(expected_result)
    {
        return Err(
            "live view did not execute the exact deployed contract with the expected result".into(),
        );
    }
    Ok(())
}

pub(super) fn require_phase(value: &Value, phase: &str, peers: u64) -> Result<(), Box<dyn Error>> {
    if value.get("phase").and_then(Value::as_str) != Some(phase)
        || value.get("running_peers").and_then(Value::as_u64) != Some(peers)
    {
        return Err(format!("expected {phase} with {peers} validators").into());
    }
    Ok(())
}

fn require_zero_owned_resources(value: &Value) -> Result<(), Box<dyn Error>> {
    // A failed startup remains Failed after authenticated down; its zero-owned-peer result is
    // safe cleanup, not a conversion of that failed attempt into success.
    if !matches!(
        value.get("phase").and_then(Value::as_str),
        Some("stopped" | "failed")
    ) || value.get("running_peers").and_then(Value::as_u64) != Some(0)
    {
        return Err("cleanup did not authenticate zero owned validators".into());
    }
    Ok(())
}

fn require_same_context(before: &Value, after: &Value) -> Result<(), Box<dyn Error>> {
    let Some(expected) = before.get("context").filter(|context| context.is_object()) else {
        return Err("missing initial managed context".into());
    };
    if after.get("context") != Some(expected) {
        return Err("idempotent start or restart changed retained client identity".into());
    }
    Ok(())
}

pub(super) fn require_deployment(value: &Value) -> Result<(), Box<dyn Error>> {
    let commit = value
        .get("receipt")
        .and_then(|receipt| receipt.get("commit"));
    if value.get("status").and_then(Value::as_str) != Some("applied")
        || !commit.is_some_and(|commit| {
            commit.get("terminal_kind").and_then(Value::as_str) == Some("Applied")
                && commit.get("resolved_from").and_then(Value::as_str) == Some("state")
                && commit
                    .get("block_height")
                    .and_then(Value::as_u64)
                    .is_some_and(|height| height > 1)
        })
        || value
            .get("journal")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err("deployment lacks Applied evidence or exact recovery journal".into());
    }
    Ok(())
}

fn require_same_deployment(before: &Value, after: &Value) -> Result<(), Box<dyn Error>> {
    require_deployment(before)?;
    require_deployment(after)?;
    if before.get("receipt") != after.get("receipt")
        || before.get("journal") != after.get("journal")
    {
        return Err("unchanged deployment created a new receipt, transaction or journal".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_listing_uses_bounded_child_without_managed_state_or_path_lookup() {
        let root = tempfile::tempdir().unwrap();
        let mut harness = Harness {
            kagami: root.path().join("absent-kagami"),
            workspace: root.path().join("workspace"),
            state: root.path().join("state"),
            empty_path: root.path().join("empty-path"),
            sequence: 0,
            root,
        };
        let command = harness.command_builder(&["dataspace", "networks"], false);
        assert_eq!(command.get_program(), harness.kagami.as_os_str());
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["dataspace", "networks", "--json"]
        );
        assert_eq!(command.get_current_dir(), Some(harness.workspace.as_path()));
        assert!(
            command.get_envs().any(
                |(name, value)| name == "PATH" && value == Some(harness.empty_path.as_os_str())
            )
        );
        let ordinary = harness.command_builder(&["localnet", "status"], true);
        assert_eq!(
            ordinary.get_args().collect::<Vec<_>>(),
            [
                std::ffi::OsStr::new("localnet"),
                std::ffi::OsStr::new("status"),
                std::ffi::OsStr::new("--state"),
                harness.state.as_os_str(),
                std::ffi::OsStr::new("--json"),
            ]
        );
        assert!(matches!(
            harness.command_document_with_store(
                &["dataspace", "networks"],
                Instant::now() - Duration::from_millis(1),
                false,
                false,
            ),
            Err(super::super::latency::Outcome::TimedOut)
        ));
        assert_eq!(harness.sequence, 0);
        assert_eq!(fs::read_dir(harness.root.path()).unwrap().count(), 0);
        assert!(!harness.state.exists());
    }

    #[test]
    fn live_execution_evidence_rejects_other_network_scope_artifact_or_return_value() {
        use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
        use iroha_data_model::{NetworkId, account::AccountId};
        use iroha_model_base::topology::DataSpaceId;

        let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"installed smoke network",
        )));
        let account = AccountId::new(
            KeyPair::from_seed(vec![1; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let scope = DataSpaceId::new(u64::MAX);
        let parent_network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"installed smoke parent"),
        ));
        let address = ContractAddress::derive(&network, &account, 1, scope).unwrap();
        let artifact = ContractArtifactId::new(scope, Hash::new(b"installed smoke artifact"));
        let execution = ManagedDeploymentExecution {
            network_id: network,
            root_scope: SumeragiRootScope::Dataspace {
                parent_network_id: parent_network,
                dataspace_id: scope,
            },
        };
        let parent = ManagedParentReport {
            parent_network_id: parent_network,
            child_network_id: network,
            observation: iroha_deploy::managed::ManagedParentObservation::NotConfigured,
        };
        let deployment = norito::json!({
            "status": "applied",
            "journal": "retained",
            "execution": execution,
            "parent": parent,
            "receipt": {
                "commit": {"terminal_kind": "Applied", "resolved_from": "state", "block_height": 5},
                "network_id": network,
                "dataspace_id": scope,
                "code_hash": (artifact.code_hash),
                "stored_artifact_matches": true,
            },
        });
        assert_eq!(
            receipt_artifact(&deployment, &network.to_string(), u64::MAX).unwrap(),
            artifact
        );
        assert!(receipt_artifact(&deployment, "other network", u64::MAX).is_err());
        assert!(receipt_artifact(&deployment, &network.to_string(), 0).is_err());
        let mut wrong_execution = deployment.clone();
        wrong_execution.as_object_mut().unwrap().insert(
            "execution".into(),
            json::to_value(&ManagedDeploymentExecution {
                network_id: parent_network,
                ..execution
            })
            .unwrap(),
        );
        assert!(receipt_artifact(&wrong_execution, &network.to_string(), u64::MAX).is_err());
        let mut wrong_parent = deployment.clone();
        wrong_parent.as_object_mut().unwrap().insert(
            "parent".into(),
            json::to_value(&ManagedParentReport {
                child_network_id: parent_network,
                ..parent
            })
            .unwrap(),
        );
        assert!(receipt_artifact(&wrong_parent, &network.to_string(), u64::MAX).is_err());
        let mut missing_execution = deployment.clone();
        missing_execution
            .as_object_mut()
            .unwrap()
            .remove("execution");
        assert!(receipt_artifact(&missing_execution, &network.to_string(), u64::MAX).is_err());
        let mut global = deployment.clone();
        let fields = global.as_object_mut().unwrap();
        fields.insert(
            "execution".into(),
            json::to_value(&ManagedDeploymentExecution {
                network_id: network,
                root_scope: SumeragiRootScope::Global,
            })
            .unwrap(),
        );
        fields.insert("parent".into(), Value::Null);
        fields
            .get_mut("receipt")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("dataspace_id".into(), 0_u64.into());
        assert_eq!(
            receipt_artifact(&global, &network.to_string(), 0).unwrap(),
            ContractArtifactId::new(DataSpaceId::UNIVERSAL, artifact.code_hash)
        );
        global
            .as_object_mut()
            .unwrap()
            .insert("parent".into(), deployment.get("parent").unwrap().clone());
        assert!(receipt_artifact(&global, &network.to_string(), 0).is_err());
        let response = norito::json!({
            "ok": true,
            "contract_address": address,
            "code_hash_hex": (hex::encode(artifact.code_hash.as_ref())),
            "entrypoint": "quote",
            "result": "30",
        });
        require_view(&response, &address, &artifact, "30").unwrap();
        let mut wrong_result = response.clone();
        wrong_result
            .as_object_mut()
            .unwrap()
            .insert("result".into(), "31".into());
        assert!(require_view(&wrong_result, &address, &artifact, "30").is_err());
        let mut numeric_result = response.clone();
        numeric_result
            .as_object_mut()
            .unwrap()
            .insert("result".into(), 30.into());
        assert!(require_view(&numeric_result, &address, &artifact, "30").is_err());
        let mut wrong_artifact = artifact;
        wrong_artifact.code_hash = Hash::new(b"another artifact");
        assert!(require_view(&response, &address, &wrong_artifact, "30").is_err());
        let other_address = ContractAddress::derive(&network, &account, 2, scope).unwrap();
        assert!(require_view(&response, &other_address, &artifact, "30").is_err());
        let mut wrong_scope = artifact;
        wrong_scope.dataspace_id = DataSpaceId::new(0);
        assert!(require_view(&response, &address, &wrong_scope, "30").is_err());
    }

    /// Exercise an already-built matching runtime without invoking Cargo from the bundle.
    #[test]
    #[ignore = "requires IROHA_DEVEX_BUNDLE_BIN pointing to matching native runtime binaries"]
    fn installed_runtime_without_configuration() {
        let directory = std::env::var_os("IROHA_DEVEX_BUNDLE_BIN")
            .map(PathBuf::from)
            .expect("set IROHA_DEVEX_BUNDLE_BIN to the canonical installed runtime directory (Contents/MacOS on macOS, bin elsewhere)");
        let kagami = directory.join(if cfg!(windows) {
            "kagami.exe"
        } else {
            "kagami"
        });
        run(&kagami)
            .expect("installed developer workflow must retain Applied evidence across restart");
    }

    #[test]
    fn readiness_requires_every_validator_and_exact_phase() {
        let ready = norito::json!({"phase": "ready", "running_peers": 4});
        require_phase(&ready, "ready", 4).unwrap();
        assert!(require_phase(&ready, "stopped", 0).is_err());
        assert!(
            require_phase(
                &norito::json!({"phase": "ready", "running_peers": 3}),
                "ready",
                4
            )
            .is_err()
        );
        assert!(require_phase(&Value::Null, "ready", 4).is_err());
    }

    #[test]
    fn repeat_checks_reject_missing_evidence_and_changed_receipts_or_identities() {
        let context = norito::json!({"context": {"network_id": "retained", "account_id": "owner"}});
        require_same_context(&context, &context).unwrap();
        assert!(
            require_same_context(
                &context,
                &norito::json!({"context": {"network_id": "changed"}})
            )
            .is_err()
        );
        assert!(require_same_context(&Value::Null, &Value::Null).is_err());
        let receipt = norito::json!({"status": "applied", "receipt": {"commit": {"terminal_kind": "Applied", "resolved_from": "state", "block_height": 5}}, "journal": "retained"});
        require_same_deployment(&receipt, &receipt).unwrap();
        let changed = norito::json!({"status": "applied", "receipt": {"commit": {"terminal_kind": "Applied", "resolved_from": "state", "block_height": 6}}, "journal": "retained"});
        assert!(require_same_deployment(&receipt, &changed).is_err());
        assert!(require_same_deployment(&Value::Null, &Value::Null).is_err());
        assert!(
            require_deployment(
                &norito::json!({"status": "pending", "receipt": {}, "journal": "retained"})
            )
            .is_err()
        );
    }

    #[test]
    fn cleanup_accepts_only_authenticated_stopped_or_failed_zero() {
        for phase in ["stopped", "failed"] {
            require_zero_owned_resources(&norito::json!({"phase": phase, "running_peers": 0}))
                .unwrap();
            assert!(
                require_zero_owned_resources(&norito::json!({"phase": phase, "running_peers": 1}))
                    .is_err()
            );
        }
        for phase in ["starting", "ready", "unknown"] {
            assert!(
                require_zero_owned_resources(&norito::json!({"phase": phase, "running_peers": 0}))
                    .is_err()
            );
        }
        assert!(require_zero_owned_resources(&Value::Null).is_err());
        assert!(require_zero_owned_resources(&norito::json!({"phase": "failed"})).is_err());
    }

    #[test]
    fn deployment_requires_native_applied_state_evidence() {
        let applied = norito::json!({"status": "applied", "receipt": {"commit": {"terminal_kind": "Applied", "resolved_from": "state", "block_height": 5}}, "journal": "retained"});
        require_deployment(&applied).unwrap();
        for (field, value) in [
            ("terminal_kind", Value::from("Committed")),
            ("resolved_from", Value::from("cache")),
            ("block_height", Value::from(1_u64)),
        ] {
            let mut changed = applied.clone();
            changed
                .as_object_mut()
                .unwrap()
                .get_mut("receipt")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .get_mut("commit")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(field.into(), value);
            assert!(require_deployment(&changed).is_err());
        }
        let mut no_commit = applied.clone();
        no_commit
            .as_object_mut()
            .unwrap()
            .get_mut("receipt")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("commit");
        assert!(require_deployment(&no_commit).is_err());
    }
}
#[test]
fn distinct_inputs_require_distinct_typed_artifact_hashes() {
    let deployments: Vec<_> = [b"source".as_slice(), b"bytecode", b"package"]
        .into_iter()
        .map(|bytes| norito::json!({"receipt": {"code_hash": (iroha_crypto::Hash::new(bytes))}}))
        .collect();
    require_distinct_artifacts(&deployments.iter().collect::<Vec<_>>()).unwrap();
    assert!(require_distinct_artifacts(&[&deployments[0], &deployments[0]]).is_err());
    assert!(require_distinct_artifacts(&[&Value::Null]).is_err());
}

#[test]
fn fixture_behaviors_compile_to_three_distinct_complete_artifacts() {
    let compiled: Vec<_> = [SOURCE, BYTECODE_SOURCE, PACKAGE_SOURCE]
        .into_iter()
        .map(|source| {
            let (bytes, manifest) = kotodama_lang::compiler::Compiler::new()
                .compile_source_with_manifest(source)
                .unwrap();
            let quote = manifest
                .entrypoints
                .as_ref()
                .unwrap()
                .iter()
                .find(|entrypoint| entrypoint.name == "quote")
                .unwrap();
            assert_eq!(
                quote.kind,
                iroha_data_model::smart_contract::manifest::EntryPointKind::View
            );
            assert_eq!(
                quote.authorization,
                iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone
            );
            bytes
        })
        .collect();
    let hashes: std::collections::BTreeSet<_> = compiled
        .iter()
        .map(|bytes| ivm::contract_code_hash(bytes))
        .collect();
    assert_eq!(hashes.len(), 3);
    assert_eq!(prepare_distinct_bytecode().unwrap(), compiled[1]);
}
