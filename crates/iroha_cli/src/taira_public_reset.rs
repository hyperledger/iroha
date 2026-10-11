//! Fail-closed public Taira reset/deploy admission and execution state machine.

use eyre::{Context as _, Result, eyre};
use iroha::{
    client::AccountOnboardingPlanRequestV1,
    data_model::{
        account::{AccountId, address::ChainDiscriminantGuard},
        asset::AssetDefinitionId,
        nexus::FeeSponsorProgramId,
        soracloud::SoraInrouPlacementTargetV1,
    },
};
use iroha_crypto::{
    Algorithm, Hash, PublicKey, ed25519_parse_signature, verify_signature_for_admission,
};
use iroha_model_base::peer::PeerId;
use iroha_primitives::numeric::Quantity;
use norito::json::{self, JsonDeserialize, JsonSerialize, Map, Value};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Seek as _, Write},
    path::{Component, Path, PathBuf},
    str::FromStr as _,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

const INVENTORY_SCHEMA_V1: &str = "iroha.taira.public-reset.executor-inventory.v1";
const AUTHORIZATION_SCHEMA_V1: &str = "iroha.taira.public-reset.authorization.v1";
const TRUSTED_KEY_SCHEMA_V1: &str = "iroha.taira.public-reset.trusted-key.v1";
const SOURCE_MANIFEST_SCHEMA_V1: &str = "iroha.taira.public-reset.signed-source-closure.v1";
const JOURNAL_SCHEMA_V1: &str = "iroha.taira.public-reset.journal.v1";
const REPORT_SCHEMA_V1: &str = "iroha.taira.public-reset.report.v1";
const AUTHORIZATION_DOMAIN_V1: &[u8] = b"iroha:taira:public-reset:authorization:v1\0";
const CHAIN_ID: &str = "fc56984b-2be7-431d-840e-21514d1883f0";
const CHAIN_DISCRIMINANT: u16 = 369;
const BUILD_TARGET: &str = "aarch64-unknown-linux-gnu";
const BUILD_PROFILE: &str = "release";
const SOURCE_BRANCH: &str = "optimizations";
const PUBLIC_ROOT: &str = "https://taira.sora.org";
const SSH: &str = "/usr/bin/ssh";
const GIT: &str = "/usr/bin/git";
const MAX_JSON_BYTES: u64 = 8 * 1024 * 1024;
const MAX_AUTHORIZATION_LIFETIME_MS: u64 = 15 * 60 * 1_000;
const EXECUTION_SAFETY_MARGIN_MS: u64 = 5 * 60 * 1_000;
const MAX_EXECUTION_LIFETIME_MS: u64 = 12 * 60 * 60 * 1_000;
const MAX_CLOCK_SKEW_MS: u64 = 30_000;
const VALIDATOR_SLUGS: [&str; 4] = [
    "taira-validator-1",
    "taira-validator-2",
    "taira-validator-3",
    "taira-validator-4",
];
const VALIDATOR_ARTIFACT_ROLES: [&str; 8] = [
    "iroha3d",
    "iroha_cli",
    "kagami",
    "sorafs_node",
    "config",
    "genesis",
    "genesis_hash",
    "validator_unit",
];
// Rollback admits the prior validator runtime independently of candidate build tools.
const OCCUPIED_VALIDATOR_ARTIFACT_ROLES: [&str; 5] = [
    "iroha3d",
    "config",
    "genesis",
    "genesis_hash",
    "validator_unit",
];
const EDGE_ARTIFACT_ROLES: [&str; 2] = ["iroha_cli", "edge_config"];
const MAX_SOURCE_FILES: usize = 100_000;
const MAX_SOURCE_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_GIT_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_INROU_STAGE_BYTES: u64 = 12 * 1024 * 1024 * 1024;
const INROU_CANARY_SERVICE_VERSION_PREFIX_V1: &str = "artifact-";
const JOURNAL_ROOT: &str = "/private/runtime/taira-public-reset/journal-v1";
const RECOVERY_INTENT_SCHEMA_V1: &str = "iroha.taira.public-reset.recovery-intent.v1";

#[path = "taira_public_reset_config.rs"]
mod config;
#[path = "taira_public_reset_history.rs"]
mod history;
#[path = "taira_public_reset_host.rs"]
mod host;
#[path = "taira_public_reset_host_pair.rs"]
mod host_pair;
#[path = "taira_public_reset_native_edge_prepare.rs"]
mod native_edge_prepare;
#[path = "taira_public_reset_native_edge_protocol.rs"]
mod native_edge_protocol;
#[path = "taira_public_reset_validator_config.rs"]
mod validator_config;
#[cfg(target_os = "linux")]
pub(crate) use host::config_retirement::verify_installed_retirement;
pub(crate) use host::config_retirement::{RetireValidatorConfig, validate_retirement_records};
pub(crate) use host::maintenance::StoppedOwnerMaintenance;
#[path = "taira_public_reset_deployment_profile.rs"]
mod deployment_profile;
#[path = "taira_public_reset_inputs.rs"]
mod inputs;
#[path = "taira_public_reset_public_inputs.rs"]
mod public_inputs;
#[path = "taira_public_reset_runtime_clients.rs"]
mod runtime_clients;
#[path = "taira_public_reset_staging_canary.rs"]
mod staging_canary;
#[path = "taira_public_reset_validator_units.rs"]
mod validator_units;

#[cfg(test)]
pub(crate) fn deployment_genesis_fixture()
-> (iroha_data_model::block::SignedBlock, iroha_crypto::KeyPair) {
    public_inputs::deployment_genesis_fixture()
}

/// Executed genesis with its exact native manifest and verifier-key binding.
#[cfg(test)]
pub(crate) fn deployment_validated_genesis_fixture() -> iroha_genesis::ValidatedGenesisBundle {
    public_inputs::deployment_validated_genesis_fixture()
}

/// Executed signed genesis with four explicit active lane-validator account bindings.
#[cfg(test)]
pub(crate) fn deployment_lane_genesis_fixture()
-> (iroha_data_model::block::SignedBlock, iroha_crypto::KeyPair) {
    public_inputs::deployment_lane_genesis_fixture()
}

#[path = "taira_public_reset_source.rs"]
mod source;

/// Strict compiled public-reset command.
#[derive(clap::Args, Debug)]
pub(crate) struct PublicReset {
    /// Select source export, signed admission, or reset execution.
    #[command(subcommand)]
    command: PublicResetCommand,
}

#[derive(clap::Subcommand, Debug)]
enum PublicResetCommand {
    /// Initialize the fixed native Mac custodian from independently pinned executable and public key.
    InitializeNativeEdgeCustody(host::InitializeNativeEdgeCustody),
    /// Capture the pinned native Python image and supported version without changing services.
    CaptureNativePython(host::CaptureNativePython),
    /// Authorize explicit native custody of retained opaque incident journals.
    AuthorizeNativeEdgeOwner(host::AuthorizeNativeEdgeOwner),
    /// Derive complete public owner-adoption inputs from pinned native capture and incident files.
    PrepareNativeEdgeOwner(host::PrepareNativeEdgeOwner),
    /// Adopt the unchanged native public include under a fresh authenticated owner.
    AdoptNativeEdgeOwner(host::AdoptNativeEdgeOwner),
    /// Capture the native Mac edge and authorize its same-source Darwin candidate.
    PrepareNativeEdge(native_edge_prepare::PrepareNativeEdge),
    /// Reversibly advance the fixed dispatcher after a sealed occupied deployment.
    DispatcherTransition(host::dispatcher_transition::DispatcherTransition),
    /// Capture the stopped installed runtime into a private typed transition input.
    CaptureDispatcherCurrentRuntime(
        host::dispatcher_transition::prepare::capture::CaptureDispatcherCurrentRuntime,
    ),
    /// Derive a pinned reversible dispatcher plan from qualified transfer and current runtime evidence.
    PrepareDispatcherTransition(host::dispatcher_transition::prepare::PrepareDispatcherTransition),
    /// Derive one fresh typed topology intent from an applied transition and new public inputs.
    PrepareTopologyIntent(host::dispatcher_transition::prepare::topology::PrepareTopologyIntent),
    /// Export the exact clean local source manifest without contacting hosts or loading keys.
    SourceManifest(PublicResetSourceManifest),
    /// Materialize a retained validator config from an inherited descriptor without printing secrets.
    ConfigRebase(config::ConfigRebase),
    /// Amend validator HTTP request budgets through an inherited descriptor and emit public provenance.
    ToriiRateConfigAmend(config::ToriiRateConfigAmend),
    /// Materialize a fresh validator config for its exact public-reset runtime paths.
    MaterializeValidatorConfig(validator_config::MaterializeValidatorConfig),
    /// Rebind a retained client config to an explicitly checked new genesis identity.
    ClientConfigRebase(config::ClientConfigRebase),
    /// Generate a dedicated runtime operator credential without exposing private key bytes.
    OperatorKeygen(config::OperatorKeygen),
    /// Derive and validate the complete public genesis and canary bundle without private keys.
    PreparePublicInputs(public_inputs::PreparePublicInputs),
    /// Prepare exact private client configs and public validator/faucet identities from native inputs.
    PrepareRuntimeClients(runtime_clients::PrepareRuntimeClients),
    /// Run or read-only recover the ordered canary on one independent private candidate.
    StageCanary(staging_canary::StageCanary),
    /// Derive the signed-network-bound beacon request and exact renderer seat paths.
    PrepareBeaconInputs(inputs::PrepareBeaconInputs),
    /// Render four public validator units from the embedded signed custody renderer.
    PrepareValidatorUnits(validator_units::PrepareValidatorUnits),
    /// Export a public deployment target profile from assembled inventory and native inputs.
    ExportDeploymentProfile(deployment_profile::ExportDeploymentProfile),
    /// Assemble exact release inputs locally from an explicit inventory draft.
    Assemble(inputs::Assemble),
    /// Sign retained release inputs using an independently trusted owner key.
    Authorize(inputs::Authorize),
    /// Verify signed inputs and read-only readiness of all four validators and the edge host.
    Preflight(PublicResetPreflight),
    /// Execute the admitted reset with pinned SSH and runtime signing inputs.
    Apply(PublicResetApply),
    /// Abandon an unresolved pre-edge testnet canary, preserve its evidence, and roll back.
    Abandon(PublicResetAbandon),
    /// Internal fixed-protocol host dispatcher. Requests are read only from stdin.
    #[command(name = "host-dispatch", hide = true)]
    HostDispatch(host::PublicResetHost),
}

#[derive(clap::Args, Debug)]
struct PublicResetSourceManifest {
    /// Absolute path to the clean optimizations checkout with a direct .git directory.
    #[arg(long, value_name = "DIR")]
    source_root: PathBuf,
}

#[derive(clap::Args, Debug)]
struct PublicResetPreflight {
    /// Exact V1 executor inventory.
    #[arg(long, value_name = "PATH")]
    inventory: PathBuf,
    /// Exact V1 authorization envelope.
    #[arg(long, value_name = "PATH")]
    authorization: PathBuf,
    /// Separately trusted exact V1 authorization public-key file.
    #[arg(long, value_name = "PATH")]
    trusted_public_key: PathBuf,
    /// Runtime-only owner-private OpenSSH identity.
    #[arg(long, value_name = "PATH")]
    ssh_identity: PathBuf,
    /// Runtime-only owner-private pinned OpenSSH known-hosts file.
    #[arg(long, value_name = "PATH")]
    known_hosts: PathBuf,
}

#[derive(clap::Args, Debug)]
struct PublicResetAbandon {
    /// Original signed reset inputs and pinned SSH custody.
    #[command(flatten)]
    inputs: PublicResetPreflight,
    /// Exact SHA-256 of the original recovery-pending journal, including its newline.
    #[arg(long, value_name = "SHA256")]
    expected_journal_sha256: String,
    /// Explicitly discard the unproven testnet without asserting a transaction outcome.
    #[arg(long, required = true)]
    abandon_pending_mutations: bool,
}

#[derive(clap::Args, Debug)]
struct PublicResetApply {
    /// Exact V1 executor inventory.
    #[arg(long, value_name = "PATH")]
    inventory: PathBuf,
    /// Exact V1 authorization envelope.
    #[arg(long, value_name = "PATH")]
    authorization: PathBuf,
    /// Separately trusted exact V1 authorization public-key file.
    #[arg(long, value_name = "PATH")]
    trusted_public_key: PathBuf,
    /// Runtime-only owner-private OpenSSH identity.
    #[arg(long, value_name = "PATH")]
    ssh_identity: PathBuf,
    /// Runtime-only owner-private pinned OpenSSH known-hosts file.
    #[arg(long, value_name = "PATH")]
    known_hosts: PathBuf,
    /// Dedicated owner-private operator key for convergence and restart verification.
    #[arg(long, value_name = "PATH")]
    validator_operator_key: Option<PathBuf>,
    /// Owner-private signing config for forward work or read-only mutation recovery.
    #[arg(long, value_name = "PATH")]
    runtime_client_config: Option<PathBuf>,
    /// Four ordered validator read configs for forward work, Canary or RestartProof recovery;
    /// other recovery steps ignore these paths.
    #[arg(long, value_name = "PATH", num_args = 4)]
    validator_client_config: Vec<PathBuf>,
    /// Owner-private account-onboarding token required only for forward work.
    #[arg(long, value_name = "PATH")]
    onboarding_token: Option<PathBuf>,
    /// Exact deploy-mode Inrou stage directory required only for forward work.
    #[arg(long, value_name = "DIR")]
    inrou_stage_dir: Option<PathBuf>,
}

impl PublicResetApply {
    fn recovery_validator_operator_key(
        &self,
        step: executor_model::ExecutionStep,
    ) -> Result<Option<PathBuf>> {
        if matches!(
            step,
            executor_model::ExecutionStep::Canary | executor_model::ExecutionStep::RestartProof
        ) {
            Ok(Some(self.validator_operator_key.clone().ok_or_else(
                || eyre!("Canary/RestartProof recovery requires --validator-operator-key"),
            )?))
        } else {
            Ok(None)
        }
    }
    fn recovery_client_config(&self) -> Result<PathBuf> {
        self.runtime_client_config
            .clone()
            .ok_or_else(|| eyre!("read-only recovery requires --runtime-client-config"))
    }

    fn recovery_validator_client_configs(
        &self,
        step: executor_model::ExecutionStep,
    ) -> Result<Vec<PathBuf>> {
        match step {
            executor_model::ExecutionStep::RestartProof | executor_model::ExecutionStep::Canary => {
                if self.validator_client_config.len() != 4 {
                    return Err(eyre!(
                        "Canary/RestartProof recovery requires exactly four --validator-client-config values"
                    ));
                }
                Ok(self.validator_client_config.clone())
            }
            executor_model::ExecutionStep::EdgeVerify => Ok(Vec::new()),
            _ => Err(eyre!("journal does not identify a recoverable V1 step")),
        }
    }

    fn fee_args(inventory: &InventoryV1) -> Result<Vec<std::ffi::OsString>> {
        use std::ffi::OsString;
        validate_fee_intent(&inventory.fee_intent)?;
        match inventory.fee_intent.payer.as_str() {
            "authority" => Ok(vec!["--fee-payer".into(), "authority".into()]),
            "sponsor" => {
                let program = inventory
                    .fee_intent
                    .sponsor_program
                    .as_deref()
                    .ok_or_else(|| eyre!("signed sponsor fee intent omits its program"))?;
                let revision = inventory
                    .fee_intent
                    .sponsor_program_revision
                    .filter(|value| *value > 0)
                    .ok_or_else(|| eyre!("signed sponsor fee intent omits its nonzero revision"))?;
                Ok(vec![
                    OsString::from("--fee-payer"),
                    OsString::from("sponsor"),
                    OsString::from("--fee-program"),
                    OsString::from(program),
                    OsString::from("--fee-program-revision"),
                    OsString::from(revision.to_string()),
                ])
            }
            _ => Err(eyre!("signed fee intent has an unsupported payer")),
        }
    }

    fn runtime_inputs(&self, admitted: &AdmittedReset) -> Result<host::RuntimeCanaryInputs> {
        let client_config = self
            .runtime_client_config
            .clone()
            .ok_or_else(|| eyre!("forward execution requires --runtime-client-config"))?;
        if self.validator_client_config.len() != 4 {
            return Err(eyre!(
                "forward execution requires exactly four --validator-client-config values"
            ));
        }
        let onboarding_token = self
            .onboarding_token
            .clone()
            .ok_or_else(|| eyre!("forward execution requires --onboarding-token"))?;
        admitted
            .inventory
            .qualification_scope
            .validate_stage_argument(self.inrou_stage_dir.as_deref())?;
        let inrou_stage_dir = self.inrou_stage_dir.clone();

        Ok(host::RuntimeCanaryInputs {
            client_config,
            validator_client_configs: self.validator_client_config.clone(),
            validator_operator_key: self
                .validator_operator_key
                .clone()
                .ok_or_else(|| eyre!("forward execution requires --validator-operator-key"))?,
            onboarding_token,
            inrou_stage_dir,
            fee_args: Self::fee_args(&admitted.inventory)?,
        })
    }
}

impl PublicReset {
    /// Run before client configuration or any ledger signing identity is loaded.
    pub(super) fn run_without_client_config<W: Write>(&self, mut output: W) -> Result<()> {
        let report = match &self.command {
            PublicResetCommand::InitializeNativeEdgeCustody(args) => {
                return host::initialize_native_edge_custody(args, &mut output);
            }
            PublicResetCommand::CaptureNativePython(args) => {
                return host::capture_native_python(args, &mut output);
            }
            PublicResetCommand::PrepareNativeEdgeOwner(args) => {
                return host::prepare_native_edge_owner(args, &mut output);
            }
            PublicResetCommand::AuthorizeNativeEdgeOwner(args) => {
                return host::authorize_native_edge_owner(args, &mut output);
            }
            PublicResetCommand::AdoptNativeEdgeOwner(args) => {
                return host::adopt_native_edge_owner(args, &mut output);
            }
            PublicResetCommand::PrepareNativeEdge(args) => {
                return native_edge_prepare::prepare(args, &mut output);
            }
            PublicResetCommand::DispatcherTransition(args) => return args.run(&mut output),
            PublicResetCommand::CaptureDispatcherCurrentRuntime(args) => {
                return args.run(&mut output);
            }
            PublicResetCommand::PrepareDispatcherTransition(args) => return args.run(&mut output),
            PublicResetCommand::PrepareTopologyIntent(args) => return args.run(&mut output),
            PublicResetCommand::SourceManifest(args) => {
                source::export_manifest(&args.source_root, &mut output)?;
                return Ok(());
            }
            PublicResetCommand::ConfigRebase(args) => {
                config::config_rebase(args)?;
                return Ok(());
            }
            PublicResetCommand::ToriiRateConfigAmend(args) => {
                return config::torii_rate_config_amend(args, &mut output);
            }
            PublicResetCommand::MaterializeValidatorConfig(args) => {
                validator_config::materialize(args)?;
                return Ok(());
            }
            PublicResetCommand::ClientConfigRebase(args) => {
                config::client_config_rebase(args)?;
                return Ok(());
            }
            PublicResetCommand::OperatorKeygen(args) => {
                config::operator_keygen(args, &mut output)?;
                return Ok(());
            }
            PublicResetCommand::PreparePublicInputs(args) => {
                public_inputs::prepare(args, &mut output)?;
                return Ok(());
            }
            PublicResetCommand::StageCanary(args) => return args.run(&mut output),
            PublicResetCommand::PrepareRuntimeClients(args) => {
                runtime_clients::prepare(args, &mut output)?;
                return Ok(());
            }
            PublicResetCommand::PrepareBeaconInputs(args) => {
                inputs::prepare_beacon_inputs(args)?;
                return Ok(());
            }
            PublicResetCommand::PrepareValidatorUnits(args) => {
                validator_units::prepare(args, &mut output)?;
                return Ok(());
            }
            PublicResetCommand::ExportDeploymentProfile(args) => {
                deployment_profile::export(args, &mut output)?;
                return Ok(());
            }
            PublicResetCommand::Assemble(args) => {
                inputs::assemble(args)?;
                return Ok(());
            }
            PublicResetCommand::Authorize(args) => {
                inputs::authorize(args)?;
                return Ok(());
            }
            PublicResetCommand::Preflight(args) => {
                let (admitted, _chain_guard) = admit(
                    &args.inventory,
                    &args.authorization,
                    &args.trusted_public_key,
                    &args.ssh_identity,
                    &args.known_hosts,
                )?;
                host::preflight_hosts(&admitted)?;
                report(
                    &admitted,
                    "preflight",
                    "ok",
                    "signed inputs and read-only preflight of four validators and the edge host verified",
                )
            }
            PublicResetCommand::Apply(args) => {
                let journal_dir = Path::new(JOURNAL_ROOT);
                let (mut admitted, _chain_guard) = admit_signed_inputs(
                    &args.inventory,
                    &args.authorization,
                    &args.trusted_public_key,
                    &args.ssh_identity,
                    &args.known_hosts,
                )?;
                if !admitted.inventory.qualification_scope.includes_inrou()
                    && args.inrou_stage_dir.is_some()
                {
                    return Err(eyre!(
                        "core_testnet forbids --inrou-stage-dir, including recovery"
                    ));
                }
                match executor_model::DurableJournal::classify(journal_dir, &admitted)? {
                    executor_model::JournalOpen::Fresh(seed) => {
                        let now_ms = now_unix_ms()?;
                        verify_fresh_authorization(&admitted, now_ms)?;
                        admit_forward_closure(&mut admitted)?;
                        let runtime = args.runtime_inputs(&admitted)?;
                        let mut journal =
                            executor_model::DurableJournal::initialize(seed, &admitted)?;
                        let mut transport = match host::OpenSshTransport::new(
                            &admitted,
                            journal_dir,
                            args.ssh_identity.clone(),
                            args.known_hosts.clone(),
                            runtime,
                        ) {
                            Ok(transport) => transport,
                            Err(error) => {
                                return handle_forward_preparation_failure(
                                    &admitted,
                                    &mut journal,
                                    journal_dir,
                                    error,
                                );
                            }
                        };
                        executor_model::execute_plan(
                            &admitted.inventory,
                            &mut transport,
                            &mut journal,
                        )?;
                    }
                    executor_model::JournalOpen::Resumable(mut journal) => {
                        let disposition = journal.resume_disposition();
                        match disposition {
                            executor_model::ResumeDisposition::Rollback => {
                                let mut transport =
                                    host::RollbackSshTransport::new(&admitted, journal_dir)?;
                                executor_model::execute_plan(
                                    &admitted.inventory,
                                    &mut transport,
                                    &mut journal,
                                )?;
                            }
                            executor_model::ResumeDisposition::Sealing
                            | executor_model::ResumeDisposition::CleanupPending => {
                                let mut transport =
                                    host::SealCleanupSshTransport::new(&admitted, journal_dir)?;
                                executor_model::execute_plan(
                                    &admitted.inventory,
                                    &mut transport,
                                    &mut journal,
                                )?;
                            }
                            executor_model::ResumeDisposition::RecoveryPending => {
                                // An exact durable ambiguity may outlive the forward
                                // lease, but it is allowed to perform only read-only
                                // reconciliation of the already prepared mutations.
                                let runtime_client_config = args.recovery_client_config()?;
                                let recovery_step = journal.pending_recovery_step()?;
                                let validator_client_configs =
                                    args.recovery_validator_client_configs(recovery_step)?;
                                let mut transport = host::RecoverySshTransport::new(
                                    &admitted,
                                    journal_dir,
                                    runtime_client_config,
                                    validator_client_configs,
                                    args.recovery_validator_operator_key(recovery_step)?,
                                )?;
                                executor_model::execute_plan(
                                    &admitted.inventory,
                                    &mut transport,
                                    &mut journal,
                                )?;
                            }
                            executor_model::ResumeDisposition::Forward => {
                                let now_ms = now_unix_ms()?;
                                let forward_authorization =
                                    verify_forward_authorization(&admitted, now_ms);
                                if let Err(error) = forward_authorization {
                                    if journal.has_touched_hosts() {
                                        executor_model::begin_rollback_after_preparation_failure(
                                            &mut journal,
                                            &error,
                                        )?;
                                        let mut transport = host::RollbackSshTransport::new(
                                            &admitted,
                                            journal_dir,
                                        )?;
                                        return executor_model::resume_rollback_after_preparation_failure(
                                            &admitted.inventory,
                                            &mut transport,
                                            &mut journal,
                                            error,
                                        );
                                    }
                                    journal.abort_before_mutation()?;
                                    return Err(error.wrap_err(
                                        "expired untouched public reset was durably aborted",
                                    ));
                                }
                                if let Err(error) = admit_forward_closure(&mut admitted) {
                                    return handle_forward_preparation_failure(
                                        &admitted,
                                        &mut journal,
                                        journal_dir,
                                        error,
                                    );
                                }
                                let runtime = match args.runtime_inputs(&admitted) {
                                    Ok(runtime) => runtime,
                                    Err(error) => {
                                        return handle_forward_preparation_failure(
                                            &admitted,
                                            &mut journal,
                                            journal_dir,
                                            error,
                                        );
                                    }
                                };
                                let mut transport = match host::OpenSshTransport::new(
                                    &admitted,
                                    journal_dir,
                                    args.ssh_identity.clone(),
                                    args.known_hosts.clone(),
                                    runtime,
                                ) {
                                    Ok(transport) => transport,
                                    Err(error) => {
                                        return handle_forward_preparation_failure(
                                            &admitted,
                                            &mut journal,
                                            journal_dir,
                                            error,
                                        );
                                    }
                                };
                                executor_model::execute_plan(
                                    &admitted.inventory,
                                    &mut transport,
                                    &mut journal,
                                )?;
                            }
                        }
                    }
                }
                report(
                    &admitted,
                    "apply",
                    "ok",
                    "public reset completed with immutable receipts",
                )
            }
            PublicResetCommand::Abandon(args) => {
                if !args.abandon_pending_mutations {
                    return Err(eyre!("abandonment requires --abandon-pending-mutations"));
                }
                let inputs = &args.inputs;
                let (admitted, _chain_guard) = admit_signed_inputs_for_controller(
                    &inputs.inventory,
                    &inputs.authorization,
                    &inputs.trusted_public_key,
                    &inputs.ssh_identity,
                    &inputs.known_hosts,
                    ControllerAdmission::AbandonOriginalTarget,
                )?;
                let journal_dir = Path::new(JOURNAL_ROOT);
                let executor_model::JournalOpen::Resumable(mut journal) =
                    executor_model::DurableJournal::classify(journal_dir, &admitted)?
                else {
                    return Err(eyre!("abandonment requires an existing unresolved journal"));
                };
                let mut transport = host::RollbackSshTransport::new(&admitted, journal_dir)?;
                let receipt = executor_model::abandon_pending_attempt(
                    &admitted.inventory,
                    &mut transport,
                    &mut journal,
                    &args.expected_journal_sha256,
                )?;
                let mut result = report(
                    &admitted,
                    "abandon",
                    "rolled_back",
                    "unresolved testnet evidence preserved; all four validators rolled back",
                );
                if let Value::Object(fields) = &mut result {
                    fields.insert(
                        "abandonment_receipt".into(),
                        Value::String(receipt.display().to_string()),
                    );
                }
                result
            }
            PublicResetCommand::HostDispatch(args) => {
                args.run(std::io::stdin().lock(), &mut output)?;
                return Ok(());
            }
        };
        let rendered = json::to_json_pretty(&report)
            .wrap_err("failed to render public-reset Norito JSON report")?;
        writeln!(output, "{rendered}").wrap_err("failed to write public-reset report")
    }
}

fn handle_forward_preparation_failure(
    admitted: &AdmittedReset,
    journal: &mut executor_model::DurableJournal,
    journal_dir: &Path,
    error: eyre::Report,
) -> Result<()> {
    if journal.has_touched_hosts() {
        executor_model::begin_rollback_after_preparation_failure(journal, &error)?;
        let mut transport = match host::RollbackSshTransport::new(admitted, journal_dir) {
            Ok(transport) => transport,
            Err(transport_error) => {
                return Err(error.wrap_err(format!(
                    "forward input preparation failed and rollback transport remains unavailable: {transport_error}"
                )));
            }
        };
        executor_model::resume_rollback_after_preparation_failure(
            &admitted.inventory,
            &mut transport,
            journal,
            error,
        )
    } else {
        Err(error.wrap_err(
            "forward input preparation failed before any durably recorded live-host mutation",
        ))
    }
}

#[cfg(test)]
fn sample_inventory_fixture() -> InventoryV1 {
    executor_model::tests::sample_inventory()
}

/// Create a disposable fixture with the same ancestor custody as operator inputs.
#[cfg(test)]
pub(crate) fn private_custody_test_dir(prefix: &str) -> tempfile::TempDir {
    // A private leaf below a shared temporary directory does not satisfy the
    // public-reset custody policy. Keep fixtures beneath the owned workspace.
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    fs::create_dir_all(&target).expect("workspace target directory");
    let target = target.canonicalize().expect("canonical workspace target");
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(target)
        .expect("private workspace fixture");
    #[cfg(unix)]
    {
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private workspace fixture permissions");
        validate_owner_private_dir(directory.path(), "test fixture")
            .expect("fixture ancestors must meet operator custody policy");
    }
    directory
}

/// Exact qualification selected by the signed inventory; omitted scopes never default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QualificationScopeV1 {
    CoreTestnet,
    FullInrou,
}

impl QualificationScopeV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CoreTestnet => "core_testnet",
            Self::FullInrou => "full_inrou",
        }
    }

    const fn includes_inrou(self) -> bool {
        matches!(self, Self::FullInrou)
    }

    fn validate_stage_argument(self, stage: Option<&Path>) -> Result<()> {
        match (self, stage) {
            (Self::CoreTestnet, None) | (Self::FullInrou, Some(_)) => Ok(()),
            (Self::CoreTestnet, Some(_)) => Err(eyre!("core_testnet forbids --inrou-stage-dir")),
            (Self::FullInrou, None) => Err(eyre!("full_inrou requires --inrou-stage-dir")),
        }
    }

    /// Canonical inventory slots restarted by this signed qualification plan.
    const fn restart_validator_indices(self) -> &'static [usize] {
        match self {
            Self::CoreTestnet => &[0],
            Self::FullInrou => &[0, 1, 2, 3],
        }
    }

    fn restart_wave(self, phase: &str) -> Option<usize> {
        self.restart_validator_indices()
            .iter()
            .enumerate()
            .find_map(|(index, _)| {
                let wave = index + 1;
                (phase == format!("restart-wave-{wave}")).then_some(wave)
            })
    }

    /// Required beacon funding, DKG phase advancement, installation, and activation only.
    /// The durable `canary` phase identity is retained for bootstrap custody;
    /// optional engineering canaries are not deployment prerequisites.
    const fn canary_kinds(self) -> &'static [&'static str] {
        match self {
            Self::CoreTestnet | Self::FullInrou => &[
                "onboarding",
                "faucet",
                "write_canary",
                "beacon_install",
                "beacon_provider_1",
                "beacon_provider_2",
                "beacon_provider_3",
                "beacon_provider_4",
            ],
        }
    }
}

impl json::FastJsonWrite for QualificationScopeV1 {
    fn write_json(&self, output: &mut String) {
        json::write_json_string(self.as_str(), output);
    }

    fn write_json_to(
        &self,
        output: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_json_string_to(self.as_str(), output)
    }
}

impl JsonDeserialize for QualificationScopeV1 {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        match parser.parse_string()?.as_str() {
            "core_testnet" => Ok(Self::CoreTestnet),
            "full_inrou" => Ok(Self::FullInrou),
            _ => Err(json::Error::Message(
                "unsupported public-reset qualification scope".to_owned(),
            )),
        }
    }
}

type InventoryV1 = InventoryRecordV1<host::beacon::BeaconBootstrapPlanV1>;

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields, no_fast_from_json)]
struct InventoryRecordV1<Beacon> {
    schema: String,
    qualification_scope: QualificationScopeV1,
    deployment_id: String,
    chain_id: String,
    chain_discriminant: u16,
    previous_genesis_hash: String,
    next_genesis_hash: String,
    authorization_nonce: String,
    revision: RevisionV1,
    /// Independently selected physical hosts, native programs and durable custodians.
    hosts: host_pair::ResetHostPairV1,
    validators: Vec<ValidatorV1>,
    validator_clients: Vec<ValidatorClientV1>,
    /// Dedicated public operator identity accepted by every candidate validator.
    operator_public_key: String,
    edge: EdgeV1,
    #[norito(required)]
    inrou_canary: Option<InrouCanaryV1>,
    canary_onboarding_request: AccountOnboardingPlanRequestV1,
    faucet_policy: FaucetPolicyV1,
    fee_intent: FeeIntentV1,
    /// Exact fresh ceremony and final provider units authorized before execution.
    beacon_bootstrap: Beacon,
    cleanup: CleanupV1,
    timeouts: TimeoutsV1,
    artifact_closure_sha256: String,
    runtime_client_config_sha256: String,
    onboarding_token_sha256: String,
    validator_client_configs_sha256: String,
    #[norito(required)]
    inrou_stage_tree_sha256: Option<String>,
}

impl<Beacon> InventoryRecordV1<Beacon> {
    fn validate_inrou_scope(&self) -> Result<()> {
        match (
            self.qualification_scope,
            &self.inrou_canary,
            &self.inrou_stage_tree_sha256,
        ) {
            (QualificationScopeV1::CoreTestnet, None, None) => Ok(()),
            (QualificationScopeV1::FullInrou, Some(canary), Some(hash)) => {
                validate_lower_hex("Inrou stage closure SHA-256", hash, 64)?;
                if hash != &canary.stage_tree_sha256 {
                    return Err(eyre!(
                        "full_inrou stage hash differs from the complete canary closure"
                    ));
                }
                validate_inrou(canary)
            }
            _ => Err(eyre!(
                "core_testnet requires null Inrou fields; full_inrou requires the complete Inrou closure"
            )),
        }
    }

    fn inrou_canary(&self) -> Result<&InrouCanaryV1> {
        if !self.qualification_scope.includes_inrou() {
            return Err(eyre!("this action requires full_inrou qualification"));
        }
        self.inrou_canary
            .as_ref()
            .ok_or_else(|| eyre!("full_inrou canary closure is absent"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct FaucetPolicyV1 {
    authority: String,
    asset_definition_id: String,
    amount: Quantity,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct FeeIntentV1 {
    payer: String,
    #[norito(required)]
    sponsor_program: Option<String>,
    #[norito(required)]
    sponsor_program_revision: Option<u64>,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RevisionV1 {
    branch: String,
    commit: String,
    tree: String,
    cargo_lock_sha256: String,
    source_root: String,
    source_manifest_path: String,
    source_manifest_sha256: String,
    source_closure_sha256: String,
    target: String,
    profile: String,
    build_id: String,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct EndpointV1 {
    hostname: String,
    port: u16,
    user: String,
    known_host_line_sha256: String,
    host_identity_sha256: String,
    upload_guard_sha256: String,
    remote_cli: String,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct SourceManifestV1 {
    schema: String,
    branch: String,
    head_commit_sha1: String,
    head_tree_sha1: String,
    cargo_lock_sha256: String,
    tracked_files: Vec<SourceFileV1>,
    untracked_files: Vec<String>,
    closure_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct SourceFileV1 {
    path: String,
    // Regular permissions (0644/0755), or Git type 0120000/0160000.
    mode: u16,
    // Byte length of regular content, raw symlink text, or gitlink commit hex.
    size: u64,
    // Git blob ID for files/links; indexed commit ID for an empty gitlink.
    git_blob_sha1: String,
    // SHA-256 of the bytes identified by size; all entries remain in the closure.
    sha256: String,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PlatformV1 {
    os: String,
    arch: String,
    kvm_api_version: u32,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct ArtifactV1 {
    role: String,
    local_path: String,
    remote_path: String,
    sha256: String,
    size: u64,
    mode: u16,
    source_commit: String,
    target: String,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct ValidatorAdmittedReleaseV1 {
    /// Source identity of the selected configuration release, independently of its executable.
    commit: String,
    release_root: String,
    /// Exact daemon argv, including the stable configuration selector.
    argv: Vec<String>,
    /// Exact ordered daemon/configuration/genesis/hash/unit runtime closure.
    artifacts: Vec<OccupiedArtifactV1>,
    /// Independently selected predecessor service state; never inferred from a failed probe.
    service_state: PriorValidatorServiceStateV1,
}

/// Signed rollback intent for an occupied validator; neither branch denotes vacancy.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(tag = "state", content = "value")]
#[norito(deny_unknown_fields)]
enum PriorValidatorServiceStateV1 {
    #[norito(rename = "running")]
    Running,
    #[norito(rename = "stopped")]
    Stopped(StoppedValidatorStateV1),
}

/// Identity of the independently selected stopped state directory, not a health assertion.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct StoppedValidatorStateV1 {
    device: u64,
    inode: u64,
}

impl PriorValidatorServiceStateV1 {
    fn validate(&self) -> Result<()> {
        if matches!(self, Self::Stopped(state) if state.inode == 0) {
            return Err(eyre!("stopped predecessor state inode must be nonzero"));
        }
        Ok(())
    }

    fn stopped_state(&self) -> Option<&StoppedValidatorStateV1> {
        match self {
            Self::Running => None,
            Self::Stopped(state) => Some(state),
        }
    }

    fn validate_state_identity(&self, device: u64, inode: u64) -> Result<()> {
        self.validate()?;
        if self
            .stopped_state()
            .is_some_and(|state| state.device != device || state.inode != inode)
        {
            return Err(eyre!(
                "stopped predecessor state differs from its signed directory identity"
            ));
        }
        Ok(())
    }
}

/// An independently admitted prior artifact. These bytes are never supplied by the candidate.
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct OccupiedArtifactV1 {
    role: String,
    path: String,
    sha256: String,
    size: u64,
    mode: u16,
    /// Exact producer revision for this role; executable paths must bind this revision.
    source_commit: String,
}

impl ValidatorAdmittedReleaseV1 {
    fn artifact(&self, role: &str) -> Result<&OccupiedArtifactV1> {
        self.artifacts
            .iter()
            .find(|entry| entry.role == role)
            .ok_or_else(|| eyre!("occupied runtime omits artifact role `{role}`"))
    }
}

/// Signed target occupancy; a vacant target has no prior release to restore.
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(tag = "state", content = "value")]
#[norito(deny_unknown_fields)]
enum ValidatorInitialStateV1 {
    #[norito(rename = "vacant")]
    Vacant,
    #[norito(rename = "admitted_release")]
    AdmittedRelease(ValidatorAdmittedReleaseV1),
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(tag = "state", content = "value")]
#[norito(deny_unknown_fields)]
enum EdgeInitialStateV1 {
    #[norito(rename = "vacant")]
    Vacant,
    #[norito(rename = "admitted_release")]
    AdmittedRelease(EdgeAdmittedReleaseV1),
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct EdgeAdmittedReleaseV1 {
    commit: String,
    release_root: String,
    cli_sha256: String,
    config_sha256: String,
}

impl ValidatorV1 {
    fn is_vacant(&self) -> bool {
        matches!(self.initial_state, ValidatorInitialStateV1::Vacant)
    }

    fn admitted_release(&self) -> Result<&ValidatorAdmittedReleaseV1> {
        match &self.initial_state {
            ValidatorInitialStateV1::AdmittedRelease(release) => Ok(release),
            ValidatorInitialStateV1::Vacant => {
                Err(eyre!("vacant validator has no admitted prior release"))
            }
        }
    }
}

impl EdgeV1 {
    fn is_vacant(&self) -> bool {
        matches!(self.initial_state, EdgeInitialStateV1::Vacant)
    }

    fn admitted_release(&self) -> Result<&EdgeAdmittedReleaseV1> {
        match &self.initial_state {
            EdgeInitialStateV1::AdmittedRelease(release) => Ok(release),
            EdgeInitialStateV1::Vacant => Err(eyre!("vacant edge has no admitted prior release")),
        }
    }
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct ValidatorV1 {
    slug: String,
    node_fingerprint: String,
    build_fingerprint: String,
    config_fingerprint: String,
    endpoint: EndpointV1,
    platform: PlatformV1,
    service_root: String,
    state_root: String,
    reset_guard: String,
    systemd_unit: String,
    systemd_unit_sha256: String,
    artifacts: Vec<ArtifactV1>,
    initial_state: ValidatorInitialStateV1,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct ValidatorClientV1 {
    slug: String,
    torii_origin: String,
    /// Direct local candidate Torii origin, bound to the admitted validator socket.
    probe_origin: String,
    account_id: String,
    peer_id: String,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct EdgeV1 {
    slug: String,
    endpoint: EndpointV1,
    platform: PlatformV1,
    service_root: String,
    state_root: String,
    reset_guard: String,
    nginx_config: String,
    artifacts: Vec<ArtifactV1>,
    native_capability: native_edge_protocol::NativeEdgeCapabilityV1,
    initial_state: EdgeInitialStateV1,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct InrouCanaryV1 {
    public_root: String,
    service_name: String,
    service_version: String,
    replicas: u16,
    route_host: String,
    route_path_prefix: String,
    healthcheck_path: String,
    bundle_hash: String,
    bundle_content_cid: String,
    bundle_manifest_digest_hex: String,
    guest_content_cid: String,
    guest_manifest_digest_hex: String,
    discovery_payload_dir: String,
    discovery_manifest_file: String,
    discovery_document_hash: String,
    discovery_content_cid: String,
    discovery_manifest_digest_hex: String,
    public_discovery_url: String,
    public_discovery_cid_host_url: String,
    deployment_bundle_hash: String,
    container_manifest_hash: String,
    service_manifest_hash: String,
    placement_targets: BTreeSet<SoraInrouPlacementTargetV1>,
    stage_tree_sha256: String,
    stage_bytes: u64,
    receipt_sha256: String,
    container_sha256: String,
    service_sha256: String,
    bundle_payload_sha256: String,
    bundle_manifest_sha256: String,
    guest_manifest_sha256: String,
    discovery_document_sha256: String,
    discovery_manifest_sha256: String,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct CleanupV1 {
    policy: String,
    max_reclaim_bytes_per_host: u64,
    minimum_age_secs: u64,
    retain_successful_releases: u8,
    delete_only_marker_bound_generated_paths: bool,
    preserve_state: bool,
    preserve_secrets: bool,
    preserve_rollback_release: bool,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct TimeoutsV1 {
    stop_secs: u64,
    install_secs: u64,
    reset_secs: u64,
    preseed_secs: u64,
    start_secs: u64,
    convergence_secs: u64,
    canary_secs: u64,
    restart_secs: u64,
    edge_secs: u64,
    cleanup_secs: u64,
    rollback_secs: u64,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct AuthorizationEnvelopeV1 {
    schema: String,
    claims: AuthorizationClaimsV1,
    signature_hex: String,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct AuthorizationClaimsV1 {
    action: String,
    /// Separately signed ongoing intent; independent of the finite reset execution lease.
    qualification_scope: QualificationScopeV1,
    deployment_id: String,
    inventory_sha256: String,
    artifact_closure_sha256: String,
    runtime_client_config_sha256: String,
    onboarding_token_sha256: String,
    validator_client_configs_sha256: String,
    #[norito(required)]
    inrou_stage_tree_sha256: Option<String>,
    faucet_policy: FaucetPolicyV1,
    fee_intent: FeeIntentV1,
    authorization_nonce: String,
    issued_at_unix_ms: u64,
    not_before_unix_ms: u64,
    expires_at_unix_ms: u64,
    execution_expires_at_unix_ms: u64,
}

impl AuthorizationClaimsV1 {
    fn inrou_stage_hash(&self) -> Result<&str> {
        if !self.qualification_scope.includes_inrou() {
            return Err(eyre!("Inrou stage authorization requires full_inrou"));
        }
        self.inrou_stage_tree_sha256
            .as_deref()
            .ok_or_else(|| eyre!("full_inrou stage authorization is absent"))
    }
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct TrustedKeyV1 {
    schema: String,
    algorithm: String,
    public_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(super) struct RecoveryIntentV1 {
    pub(super) schema: String,
    pub(super) step_label: String,
    pub(super) next_mutation: u16,
    pub(super) mutations: Vec<RecoveryMutationV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(super) struct RecoveryMutationV1 {
    pub(super) kind: String,
    pub(super) phase: String,
    pub(super) idempotency_key: String,
    pub(super) receipt_name: String,
    pub(super) state: RecoveryMutationStateV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(tag = "state", content = "value")]
#[norito(deny_unknown_fields)]
pub(super) enum RecoveryMutationStateV1 {
    #[norito(rename = "prepared")]
    Prepared,
    #[norito(rename = "submitted")]
    Submitted,
    #[norito(rename = "applied")]
    Applied,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RecoveryOutcome {
    Applied,
    ReadyToContinue,
    ResumeSubmittedBeaconActivation,
    Pending,
    Rejected(String),
}

struct AdmittedReset {
    inventory: InventoryV1,
    inventory_bytes: Vec<u8>,
    inventory_sha256: String,
    authorization_bytes: Vec<u8>,
    authorization_sha256: String,
    trusted_key_bytes: Vec<u8>,
    authorization: AuthorizationEnvelopeV1,
    trusted_key: TrustedKeyV1,
    pinned_artifacts: Vec<PinnedArtifact>,
    ssh_identity: PinnedInput,
    known_hosts: PinnedInput,
}

struct PinnedInput {
    path: PathBuf,
    file: File,
    snapshot: FileSnapshot,
}

struct PinnedArtifact {
    slug: String,
    role: String,
    artifact: ArtifactV1,
    input: PinnedInput,
}

struct ValidatedArtifactSource {
    sha256: String,
    size: u64,
    mode: u16,
    input: PinnedInput,
}

fn admit(
    inventory_path: &Path,
    authorization_path: &Path,
    trusted_key_path: &Path,
    ssh_identity: &Path,
    known_hosts: &Path,
) -> Result<(AdmittedReset, ChainDiscriminantGuard)> {
    let (mut admitted, chain_guard) = admit_signed_inputs(
        inventory_path,
        authorization_path,
        trusted_key_path,
        ssh_identity,
        known_hosts,
    )?;
    verify_authorization(
        &admitted.inventory,
        &admitted.inventory_sha256,
        &admitted.authorization,
        &admitted.trusted_key,
        now_unix_ms()?,
    )?;
    admit_forward_closure(&mut admitted)?;
    Ok((admitted, chain_guard))
}

fn admit_signed_inputs(
    inventory_path: &Path,
    authorization_path: &Path,
    trusted_key_path: &Path,
    ssh_identity: &Path,
    known_hosts: &Path,
) -> Result<(AdmittedReset, ChainDiscriminantGuard)> {
    admit_signed_inputs_for_controller(
        inventory_path,
        authorization_path,
        trusted_key_path,
        ssh_identity,
        known_hosts,
        ControllerAdmission::CurrentExecutable,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ControllerAdmission {
    CurrentExecutable,
    // The new controller can roll back an original signed target only through its
    // retained dispatcher; the dispatcher still admits its own exact executable.
    AbandonOriginalTarget,
}

fn admit_signed_inputs_for_controller(
    inventory_path: &Path,
    authorization_path: &Path,
    trusted_key_path: &Path,
    ssh_identity: &Path,
    known_hosts: &Path,
    admission: ControllerAdmission,
) -> Result<(AdmittedReset, ChainDiscriminantGuard)> {
    let (inventory, inventory_bytes, chain_guard) = read_inventory(inventory_path, "inventory")?;
    validate_inventory_for_controller(&inventory, admission)?;
    validate_shared_validator_closure(&inventory)?;
    // Reject unsupported placement before opening any deployment credential.
    validate_fixed_executable(Path::new(SSH), "OpenSSH client")?;
    let known_hosts = validate_known_hosts(&inventory, known_hosts)?;
    let ssh_identity = pin_owner_private_file(ssh_identity, "OpenSSH identity")?;

    let (authorization, authorization_bytes) =
        read_private_json::<AuthorizationEnvelopeV1>(authorization_path, "authorization")?;
    let (trusted_key, trusted_key_bytes) =
        read_private_json::<TrustedKeyV1>(trusted_key_path, "trusted key")?;
    let inventory_sha256 = sha256_hex(&inventory_bytes);
    verify_authorization_at_signed_instant(
        &inventory,
        &inventory_sha256,
        &authorization,
        &trusted_key,
    )?;
    let authorization_sha256 = authorization_semantic_sha256(&authorization, &trusted_key)?;
    Ok((
        AdmittedReset {
            inventory,
            inventory_bytes,
            inventory_sha256,
            authorization_bytes,
            authorization_sha256,
            trusted_key_bytes,
            authorization,
            trusted_key,
            pinned_artifacts: Vec::new(),
            ssh_identity,
            known_hosts,
        },
        chain_guard,
    ))
}

fn admit_forward_closure(admitted: &mut AdmittedReset) -> Result<()> {
    validate_fixed_executable(Path::new(GIT), "Git provenance client")?;
    validate_source_closure(&admitted.inventory.revision)?;
    let pinned_artifacts = validate_artifact_files(&admitted.inventory)?;
    validate_shared_validator_closure(&admitted.inventory)?;
    validate_genesis_hash_files(&admitted.inventory, &pinned_artifacts)?;
    validate_pinned_validator_genesis_configs(&admitted.inventory, &pinned_artifacts)?;
    admitted.pinned_artifacts = pinned_artifacts;
    Ok(())
}

fn verify_authorization_at_signed_instant(
    inventory: &InventoryV1,
    inventory_sha256: &str,
    envelope: &AuthorizationEnvelopeV1,
    trusted: &TrustedKeyV1,
) -> Result<()> {
    verify_authorization(
        inventory,
        inventory_sha256,
        envelope,
        trusted,
        envelope.claims.not_before_unix_ms,
    )
}

fn verify_fresh_authorization(admitted: &AdmittedReset, now_ms: u64) -> Result<()> {
    verify_authorization(
        &admitted.inventory,
        &admitted.inventory_sha256,
        &admitted.authorization,
        &admitted.trusted_key,
        now_ms,
    )?;
    if now_ms >= admitted.authorization.claims.expires_at_unix_ms
        || now_ms >= admitted.authorization.claims.execution_expires_at_unix_ms
    {
        return Err(eyre!(
            "signed fresh-admission or forward execution lease expired"
        ));
    }
    Ok(())
}

fn verify_forward_authorization(admitted: &AdmittedReset, now_ms: u64) -> Result<()> {
    verify_execution_authorization(
        &admitted.inventory,
        &admitted.inventory_sha256,
        &admitted.authorization,
        &admitted.trusted_key,
        now_ms,
    )?;
    if now_ms >= admitted.authorization.claims.execution_expires_at_unix_ms {
        return Err(eyre!("signed forward execution lease expired"));
    }
    Ok(())
}

fn authorization_semantic_sha256(
    envelope: &AuthorizationEnvelopeV1,
    trusted: &TrustedKeyV1,
) -> Result<String> {
    let claims = json::to_json(&envelope.claims)
        .wrap_err("failed to encode canonical authorization claims for replay binding")?;
    let mut digest = Sha256::new();
    digest.update(b"iroha:taira:public-reset:authorization-replay:v1\0");
    update_framed(&mut digest, claims.as_bytes());
    update_framed(&mut digest, envelope.signature_hex.as_bytes());
    update_framed(&mut digest, trusted.algorithm.as_bytes());
    update_framed(&mut digest, trusted.public_key.as_bytes());
    Ok(hex::encode(digest.finalize()))
}

fn read_inventory(
    path: &Path,
    label: &str,
) -> Result<(InventoryV1, Vec<u8>, ChainDiscriminantGuard)> {
    let (file, snapshot) = open_pinned_regular(path, label)?;
    if snapshot.len == 0 || snapshot.len > MAX_JSON_BYTES {
        return Err(eyre!("{label} is empty or exceeds the V1 JSON bound"));
    }
    let bytes = read_pinned_bytes(path, label, file, &snapshot, MAX_JSON_BYTES)?;
    let (inventory, guard) = decode_inventory(&bytes, label)?;
    Ok((inventory, bytes, guard))
}

fn read_json<T: JsonDeserialize>(path: &Path, label: &str) -> Result<(T, Vec<u8>)> {
    let (file, snapshot) = open_pinned_regular(path, label)?;
    if snapshot.len > MAX_JSON_BYTES {
        return Err(eyre!("{label} exceeds the {MAX_JSON_BYTES}-byte V1 limit"));
    }
    let bytes = read_pinned_bytes(path, label, file, &snapshot, MAX_JSON_BYTES)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_JSON_BYTES {
        return Err(eyre!("{label} exceeds the {MAX_JSON_BYTES}-byte V1 limit"));
    }
    let parsed = json::from_slice(&bytes)
        .wrap_err_with(|| format!("failed to decode exact Norito JSON {label} V1"))?;
    Ok((parsed, bytes))
}

fn read_private_json<T: JsonDeserialize>(path: &Path, label: &str) -> Result<(T, Vec<u8>)> {
    let (file, snapshot) = open_pinned_regular(path, label)?;
    require_owner_private_snapshot(&snapshot, label)?;
    if snapshot.len > MAX_JSON_BYTES {
        return Err(eyre!("{label} exceeds the {MAX_JSON_BYTES}-byte V1 limit"));
    }
    let bytes = read_pinned_bytes(path, label, file, &snapshot, MAX_JSON_BYTES)?;
    let parsed = json::from_slice(&bytes)
        .wrap_err_with(|| format!("failed to decode exact Norito JSON {label} V1"))?;
    Ok((parsed, bytes))
}

fn verify_authorization(
    inventory: &InventoryV1,
    inventory_sha256: &str,
    envelope: &AuthorizationEnvelopeV1,
    trusted: &TrustedKeyV1,
    now_ms: u64,
) -> Result<()> {
    verify_authorization_window(inventory, inventory_sha256, envelope, trusted, now_ms, true)
}

fn verify_execution_authorization(
    inventory: &InventoryV1,
    inventory_sha256: &str,
    envelope: &AuthorizationEnvelopeV1,
    trusted: &TrustedKeyV1,
    now_ms: u64,
) -> Result<()> {
    verify_authorization_window(
        inventory,
        inventory_sha256,
        envelope,
        trusted,
        now_ms,
        false,
    )
}

fn verify_authorization_window(
    inventory: &InventoryV1,
    inventory_sha256: &str,
    envelope: &AuthorizationEnvelopeV1,
    trusted: &TrustedKeyV1,
    now_ms: u64,
    admission_window: bool,
) -> Result<()> {
    verify_authorization_claims(inventory, inventory_sha256, envelope, trusted)?;
    let claims = &envelope.claims;
    let required_execution_expiry = claims
        .issued_at_unix_ms
        .checked_add(execution_lifetime_ms(inventory)?)
        .ok_or_else(|| eyre!("authorization execution expiry overflow"))?;
    if claims.execution_expires_at_unix_ms != required_execution_expiry {
        return Err(eyre!(
            "authorization execution lease does not exactly cover the bounded execution plan"
        ));
    }
    let active_expiry = if admission_window {
        claims.expires_at_unix_ms
    } else {
        claims.execution_expires_at_unix_ms
    };
    if now_ms.saturating_add(MAX_CLOCK_SKEW_MS) < claims.not_before_unix_ms
        || now_ms > active_expiry.saturating_add(MAX_CLOCK_SKEW_MS)
    {
        return Err(eyre!("authorization is not currently valid"));
    }
    verify_authorization_signature(envelope, trusted)
}

/// Verify signed custody metadata independently of the candidate's execution schema.
fn verify_authorization_claims<Beacon>(
    inventory: &InventoryRecordV1<Beacon>,
    inventory_sha256: &str,
    envelope: &AuthorizationEnvelopeV1,
    trusted: &TrustedKeyV1,
) -> Result<()> {
    if envelope.schema != AUTHORIZATION_SCHEMA_V1 {
        return Err(eyre!(
            "authorization schema must be `{AUTHORIZATION_SCHEMA_V1}`"
        ));
    }
    if trusted.schema != TRUSTED_KEY_SCHEMA_V1 || trusted.algorithm != "ed25519" {
        return Err(eyre!(
            "trusted key must use schema `{TRUSTED_KEY_SCHEMA_V1}` and algorithm `ed25519`"
        ));
    }
    let claims = &envelope.claims;
    if claims.action != "reset_and_deploy"
        || claims.qualification_scope != inventory.qualification_scope
        || claims.deployment_id != inventory.deployment_id
        || claims.inventory_sha256 != inventory_sha256
        || claims.artifact_closure_sha256 != inventory.artifact_closure_sha256
        || claims.runtime_client_config_sha256 != inventory.runtime_client_config_sha256
        || claims.onboarding_token_sha256 != inventory.onboarding_token_sha256
        || claims.validator_client_configs_sha256 != inventory.validator_client_configs_sha256
        || claims.inrou_stage_tree_sha256 != inventory.inrou_stage_tree_sha256
        || claims.faucet_policy != inventory.faucet_policy
        || claims.fee_intent != inventory.fee_intent
        || claims.authorization_nonce != inventory.authorization_nonce
    {
        return Err(eyre!(
            "authorization claims do not exactly bind this reset inventory"
        ));
    }
    validate_lower_hex(
        "authorization inventory SHA-256",
        &claims.inventory_sha256,
        64,
    )?;
    for (label, value) in [
        (
            "runtime client-config SHA-256",
            claims.runtime_client_config_sha256.as_str(),
        ),
        (
            "onboarding-token SHA-256",
            claims.onboarding_token_sha256.as_str(),
        ),
        (
            "validator client-config closure SHA-256",
            claims.validator_client_configs_sha256.as_str(),
        ),
    ] {
        validate_lower_hex(label, value, 64)?;
    }
    inventory.validate_inrou_scope()?;
    if claims.not_before_unix_ms < claims.issued_at_unix_ms
        || claims.expires_at_unix_ms <= claims.not_before_unix_ms
        || claims.expires_at_unix_ms - claims.issued_at_unix_ms > MAX_AUTHORIZATION_LIFETIME_MS
    {
        return Err(eyre!(
            "authorization time window is invalid or exceeds 15 minutes"
        ));
    }
    if claims.execution_expires_at_unix_ms < claims.expires_at_unix_ms
        || claims.execution_expires_at_unix_ms - claims.issued_at_unix_ms
            > MAX_EXECUTION_LIFETIME_MS
    {
        return Err(eyre!(
            "authorization execution lease does not cover admission within its finite bound"
        ));
    }
    Ok(())
}

fn verify_authorization_signature(
    envelope: &AuthorizationEnvelopeV1,
    trusted: &TrustedKeyV1,
) -> Result<()> {
    validate_lower_hex("authorization signature", &envelope.signature_hex, 128)?;
    let signature_bytes = hex::decode(&envelope.signature_hex)
        .wrap_err("authorization signature is not lowercase hexadecimal")?;
    let signature = ed25519_parse_signature(&signature_bytes)
        .wrap_err("authorization signature is not a canonical Ed25519 signature")?;
    let public_key = PublicKey::from_str(&trusted.public_key)
        .wrap_err("trusted authorization public key is invalid")?;
    if public_key
        .try_algorithm()
        .wrap_err("trusted key algorithm is invalid")?
        != Algorithm::Ed25519
    {
        return Err(eyre!("trusted authorization public key must be Ed25519"));
    }
    let message = authorization_message(&envelope.claims)?;
    verify_signature_for_admission(&signature, &public_key, &message)
        .wrap_err("public-reset authorization signature verification failed")
}

fn execution_lifetime_ms(inventory: &InventoryV1) -> Result<u64> {
    execution_lifetime_for_inputs(&inventory.timeouts, &inventory.validators)
}

fn execution_lifetime_for_inputs(timeouts: &TimeoutsV1, validators: &[ValidatorV1]) -> Result<u64> {
    execution_lifetime_for_host_identities(
        timeouts,
        validators
            .iter()
            .map(|validator| validator.endpoint.host_identity_sha256.as_str()),
    )
}

fn execution_lifetime_for_host_identities<'a, I>(
    timeouts: &TimeoutsV1,
    identities: I,
) -> Result<u64>
where
    I: IntoIterator<Item = &'a str>,
{
    let physical_validator_hosts = identities.into_iter().collect::<BTreeSet<_>>().len();
    let physical_validator_hosts = u64::try_from(physical_validator_hosts)
        .map_err(|_| eyre!("physical validator host count does not fit u64"))?;
    let validator_count = u64::try_from(VALIDATOR_SLUGS.len())
        .map_err(|_| eyre!("validator count does not fit u64"))?;
    let validator_artifact_count = u64::try_from(VALIDATOR_ARTIFACT_ROLES.len())
        .map_err(|_| eyre!("validator artifact count does not fit u64"))?;
    // Each validator has one preflight, every canonical artifact upload, one
    // stage verification, and one install. Add the edge preflight and one
    // canonical Inrou stage upload per physical validator host.
    let install_action_count = validator_artifact_count
        .checked_add(3)
        .and_then(|count| count.checked_mul(validator_count))
        .and_then(|count| count.checked_add(1))
        .and_then(|count| count.checked_add(physical_validator_hosts))
        .ok_or_else(|| eyre!("install action count overflow"))?;
    // This conservative maximum covers both explicit qualification scopes. Core
    // omits Inrou execution and additional restart waves without shortening
    // custody leases; unused budget never introduces a wait. Keep each timeout class
    // independently bounded for the closed four-validator/one-edge plan.
    let seconds = timeouts
        .install_secs
        .checked_mul(install_action_count)
        .and_then(|value| value.checked_add(timeouts.stop_secs.checked_mul(4)?))
        // State reset is an atomic rename. Offline ingest and the carrier's
        // before-start verification each traverse every store on that host.
        .and_then(|value| value.checked_add(timeouts.reset_secs.checked_mul(4)?))
        .and_then(|value| {
            value.checked_add(
                timeouts
                    .preseed_secs
                    .checked_mul(physical_validator_hosts.checked_mul(2)?)?,
            )
        })
        .and_then(|value| value.checked_add(timeouts.start_secs.checked_mul(4)?))
        // Three edge-stage actions, cutover, verify, and five seal dispatches.
        .and_then(|value| value.checked_add(timeouts.edge_secs.checked_mul(10)?))
        // Conservative lease capacity retained for bootstrap and convergence.
        // These upper bounds do not schedule diagnostics or impose a wait.
        .and_then(|value| value.checked_add(timeouts.convergence_secs.checked_mul(6)?))
        .and_then(|value| value.checked_add(timeouts.canary_secs.checked_mul(37)?))
        .and_then(|value| value.checked_add(timeouts.restart_secs.checked_mul(4)?))
        .and_then(|value| value.checked_add(timeouts.cleanup_secs.checked_mul(5)?))
        .and_then(|value| value.checked_add(timeouts.rollback_secs.checked_mul(5)?))
        .ok_or_else(|| eyre!("bounded execution timeout sum overflow"))?;
    let lifetime_ms = seconds
        .checked_mul(1_000)
        // A fresh authorization may be admitted at any point in its complete
        // fifteen-minute admission window, so the execution lease must cover
        // that delay in addition to the bounded action ledger.
        .and_then(|value| value.checked_add(MAX_AUTHORIZATION_LIFETIME_MS))
        .and_then(|value| value.checked_add(EXECUTION_SAFETY_MARGIN_MS))
        .ok_or_else(|| eyre!("bounded execution lifetime overflow"))?;
    if lifetime_ms > MAX_EXECUTION_LIFETIME_MS {
        return Err(eyre!(
            "bounded execution plan requires {} seconds (actions: {} seconds, admission: {} seconds, safety: {} seconds), exceeding the {}-second limit by {} seconds",
            lifetime_ms / 1_000,
            seconds,
            MAX_AUTHORIZATION_LIFETIME_MS / 1_000,
            EXECUTION_SAFETY_MARGIN_MS / 1_000,
            MAX_EXECUTION_LIFETIME_MS / 1_000,
            (lifetime_ms - MAX_EXECUTION_LIFETIME_MS) / 1_000,
        ));
    }
    Ok(lifetime_ms)
}

fn authorization_message(claims: &AuthorizationClaimsV1) -> Result<Vec<u8>> {
    let claims_json =
        json::to_json(claims).wrap_err("failed to encode canonical authorization claims")?;
    let mut message = Vec::with_capacity(AUTHORIZATION_DOMAIN_V1.len() + claims_json.len());
    message.extend_from_slice(AUTHORIZATION_DOMAIN_V1);
    message.extend_from_slice(claims_json.as_bytes());
    Ok(message)
}

fn validate_inventory(inventory: &InventoryV1) -> Result<()> {
    validate_inventory_for_controller(inventory, ControllerAdmission::CurrentExecutable)
}

fn validate_inventory_for_controller(
    inventory: &InventoryV1,
    admission: ControllerAdmission,
) -> Result<()> {
    validate_inventory_with_revision(inventory, |revision| {
        validate_revision_for_controller(revision, admission)
    })
}

// The production entry point above always supplies exact compiled-release admission.
// Pure inventory tests exercise the same structure without claiming a release identity.
fn validate_inventory_with_revision(
    inventory: &InventoryV1,
    validate_revision: impl FnOnce(&RevisionV1) -> Result<()>,
) -> Result<()> {
    let _chain_guard = enter_inventory_chain_discriminant(inventory)?;
    validate_inventory_custody_with_revision(inventory, validate_revision)?;
    host::beacon::validate_plan(inventory)?;
    validate_timeout_policy(inventory)
}

/// Common topology and custody checks; this never admits an execution payload.
fn validate_inventory_custody_with_revision<Beacon>(
    inventory: &InventoryRecordV1<Beacon>,
    validate_revision: impl FnOnce(&RevisionV1) -> Result<()>,
) -> Result<()> {
    if inventory.schema != INVENTORY_SCHEMA_V1 {
        return Err(eyre!("inventory schema must be `{INVENTORY_SCHEMA_V1}`"));
    }
    validator_operator_public_key(&inventory.operator_public_key)?;
    let _chain_guard = enter_inventory_chain_discriminant(inventory)?;
    validate_slug("deployment_id", &inventory.deployment_id)?;
    for (label, value) in [
        (
            "runtime client-config SHA-256",
            inventory.runtime_client_config_sha256.as_str(),
        ),
        (
            "onboarding-token SHA-256",
            inventory.onboarding_token_sha256.as_str(),
        ),
        (
            "validator client-config closure SHA-256",
            inventory.validator_client_configs_sha256.as_str(),
        ),
    ] {
        validate_lower_hex(label, value, 64)?;
    }
    inventory.validate_inrou_scope()?;
    for (label, value) in [
        (
            "previous genesis hash",
            inventory.previous_genesis_hash.as_str(),
        ),
        ("next genesis hash", inventory.next_genesis_hash.as_str()),
    ] {
        validate_canonical_iroha_hash(label, value)?;
    }
    if inventory.previous_genesis_hash == inventory.next_genesis_hash {
        return Err(eyre!(
            "public reset must bind distinct previous and next genesis hashes"
        ));
    }
    validate_nonce(&inventory.authorization_nonce)?;
    validate_revision(&inventory.revision)?;
    validate_timeouts(&inventory.timeouts)?;
    validate_canary_onboarding_request(&inventory.canary_onboarding_request)?;
    validate_faucet_policy(&inventory.faucet_policy)?;
    validate_fee_intent(&inventory.fee_intent)?;
    validate_cleanup(&inventory.cleanup)?;
    if inventory.validators.len() != VALIDATOR_SLUGS.len() {
        return Err(eyre!("inventory must contain exactly four validators"));
    }
    if inventory.validator_clients.len() != VALIDATOR_SLUGS.len() {
        return Err(eyre!(
            "inventory must bind exactly four ordered validator client identities"
        ));
    }

    let mut node_fingerprints = BTreeSet::new();
    let mut build_fingerprint = None;
    let mut config_fingerprint = None;
    for (validator, expected_slug) in inventory.validators.iter().zip(VALIDATOR_SLUGS) {
        validate_validator(
            validator,
            expected_slug,
            &inventory.revision,
            inventory.qualification_scope,
        )?;
        if !node_fingerprints.insert(validator.node_fingerprint.clone()) {
            return Err(eyre!("validator node fingerprints must be distinct"));
        }
        match &build_fingerprint {
            None => build_fingerprint = Some(validator.build_fingerprint.clone()),
            Some(expected) if expected == &validator.build_fingerprint => {}
            Some(_) => return Err(eyre!("validators must report one signed build fingerprint")),
        }
        match &config_fingerprint {
            None => config_fingerprint = Some(validator.config_fingerprint.clone()),
            Some(expected) if expected == &validator.config_fingerprint => {}
            Some(_) => {
                return Err(eyre!(
                    "validators must report one signed consensus-config fingerprint"
                ));
            }
        }
    }
    let mut client_accounts = BTreeSet::new();
    let mut client_peers = BTreeSet::new();
    let mut probe_origins = BTreeSet::new();
    let mut public_origins = BTreeSet::new();
    let mut client_placement_targets = BTreeSet::new();
    for (client, expected_slug) in inventory.validator_clients.iter().zip(VALIDATOR_SLUGS) {
        validate_validator_public_origin(&client.torii_origin)?;
        if !public_origins.insert(&client.torii_origin) {
            return Err(eyre!("validator public Torii origins must be distinct"));
        }
        validate_candidate_probe_origin(&client.probe_origin)?;
        if !probe_origins.insert(&client.probe_origin) {
            return Err(eyre!(
                "candidate Torii origins must bind four distinct sockets"
            ));
        }
        if client.slug != expected_slug
            || client.account_id.is_empty()
            || client.peer_id.is_empty()
            || !client_accounts.insert(client.account_id.clone())
            || !client_peers.insert(client.peer_id.clone())
        {
            return Err(eyre!(
                "validator client identities must bind four distinct ordered account/peer pairs and Torii origins"
            ));
        }
        let account = AccountId::parse_encoded(&client.account_id)
            .wrap_err("validator client account identity is not canonical")?;
        if account.to_string() != client.account_id {
            return Err(eyre!(
                "validator client account identity is not canonical I105"
            ));
        }
        let peer = client
            .peer_id
            .parse::<PeerId>()
            .wrap_err("validator client peer identity is not canonical")?;
        if peer.to_string() != client.peer_id {
            return Err(eyre!("validator client peer identity is not canonical"));
        }
        let target = SoraInrouPlacementTargetV1 {
            peer_id: client.peer_id.clone(),
            validator_account_id: account,
        };
        target.validate()?;
        client_placement_targets.insert(target);
    }
    if let Some(canary) = &inventory.inrou_canary
        && canary.placement_targets != client_placement_targets
    {
        return Err(eyre!(
            "Inrou canary placement targets must equal the exact four validator client identities"
        ));
    }
    validate_edge(&inventory.edge, &inventory.revision, &inventory.hosts)?;
    inventory
        .hosts
        .validate_roles(&inventory.validators, &inventory.edge)?;
    validate_lower_hex(
        "artifact closure SHA-256",
        &inventory.artifact_closure_sha256,
        64,
    )?;
    let computed = artifact_closure_sha256(inventory);
    if computed != inventory.artifact_closure_sha256 {
        return Err(eyre!(
            "artifact closure SHA-256 mismatch: inventory `{}`, computed `{computed}`",
            inventory.artifact_closure_sha256
        ));
    }
    Ok(())
}

fn validate_inventory_chain_identity<Beacon>(inventory: &InventoryRecordV1<Beacon>) -> Result<()> {
    if inventory.chain_id != CHAIN_ID || inventory.chain_discriminant != CHAIN_DISCRIMINANT {
        return Err(eyre!(
            "inventory must target the canonical Taira V1 chain identity"
        ));
    }
    Ok(())
}

fn enter_inventory_chain_discriminant<Beacon>(
    inventory: &InventoryRecordV1<Beacon>,
) -> Result<ChainDiscriminantGuard> {
    validate_inventory_chain_identity(inventory)?;
    Ok(ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT))
}

fn decode_inventory(bytes: &[u8], label: &str) -> Result<(InventoryV1, ChainDiscriminantGuard)> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(eyre!("{label} is empty or exceeds the V1 JSON bound"));
    }
    // Nested placement AccountIds must be decoded under this protocol's fixed network,
    // before the untrusted top-level fields can be inspected. Never infer the network
    // from the ambient process or use an unvalidated field to choose the decoder.
    let guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
    let inventory: InventoryV1 = json::from_slice(bytes)
        .map_err(|_| eyre!("{label} is not exact Taira inventory V1 JSON"))?;
    validate_inventory_chain_identity(&inventory)?;
    Ok((inventory, guard))
}

fn canonical_inventory_bytes(inventory: &InventoryV1) -> Result<Vec<u8>> {
    let _guard = enter_inventory_chain_discriminant(inventory)?;
    let mut bytes = json::to_json(inventory)?.into_bytes();
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(eyre!("inventory exceeds the V1 JSON bound"));
    }
    Ok(bytes)
}

fn assembled_inventory_bytes(inventory: &InventoryV1) -> Result<Vec<u8>> {
    let bytes = canonical_inventory_bytes(inventory)?;
    let (decoded, _guard) = decode_inventory(&bytes, "assembled inventory")?;
    if canonical_inventory_bytes(&decoded)? != bytes {
        return Err(eyre!(
            "assembled inventory failed its canonical V1 roundtrip"
        ));
    }
    Ok(bytes)
}

fn validate_revision(revision: &RevisionV1) -> Result<()> {
    validate_revision_for_controller(revision, ControllerAdmission::CurrentExecutable)
}

fn validate_revision_for_controller(
    revision: &RevisionV1,
    admission: ControllerAdmission,
) -> Result<()> {
    validate_revision_source_fields(revision)?;
    let compiled_sha = crate::compiled_build_identity()?.release_source_commit()?;
    validate_lower_hex("compiled CLI Git SHA", compiled_sha, 40)
        .wrap_err("compiled CLI has unknown or dirty source provenance")?;
    validate_revision_build_fields(revision)?;
    if admission == ControllerAdmission::CurrentExecutable && revision.commit != compiled_sha {
        return Err(eyre!(
            "revision commit/build_id must equal the compiled CLI SHA"
        ));
    }
    Ok(())
}

fn validate_revision_source_fields(revision: &RevisionV1) -> Result<()> {
    if revision.branch != SOURCE_BRANCH {
        return Err(eyre!("revision branch must be exact `{SOURCE_BRANCH}`"));
    }
    validate_lower_hex("revision commit", &revision.commit, 40)?;
    validate_lower_hex("revision tree", &revision.tree, 40)?;
    validate_lower_hex("Cargo.lock SHA-256", &revision.cargo_lock_sha256, 64)?;
    validate_lower_hex(
        "source manifest SHA-256",
        &revision.source_manifest_sha256,
        64,
    )?;
    validate_lower_hex(
        "source closure SHA-256",
        &revision.source_closure_sha256,
        64,
    )?;
    validate_absolute_normal_path(Path::new(&revision.source_root), "source root")?;
    validate_absolute_normal_path(
        Path::new(&revision.source_manifest_path),
        "source manifest path",
    )?;
    Ok(())
}

fn validate_revision_build_fields(revision: &RevisionV1) -> Result<()> {
    if revision.target != BUILD_TARGET
        || revision.profile != BUILD_PROFILE
        || revision.build_id != revision.commit
    {
        return Err(eyre!(
            "revision must use target `{BUILD_TARGET}`, evidence profile `{BUILD_PROFILE}`, and identical commit/build_id"
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_inventory_structure(inventory: &InventoryV1) -> Result<()> {
    validate_inventory_with_revision(inventory, |revision| {
        validate_revision_source_fields(revision)?;
        validate_revision_build_fields(revision)
    })
}

#[cfg(test)]
fn test_compiled_release_commit() -> Option<&'static str> {
    use iroha_core::release_identity::BuildIdentityError;
    match crate::compiled_build_identity()
        .expect("valid compiled executable identity")
        .release_source_commit()
    {
        Ok(commit) => Some(commit),
        Err(BuildIdentityError::DevelopmentSource) => None,
        Err(error) => panic!("invalid compiled executable identity: {error}"),
    }
}

#[cfg(test)]
fn assert_compiled_admission_error(error: &eyre::Report, release_message: &str) {
    use iroha_core::release_identity::BuildIdentityError;
    if test_compiled_release_commit().is_some() {
        assert!(error.to_string().contains(release_message), "{error:#}");
    } else {
        assert_eq!(
            error.downcast_ref::<BuildIdentityError>(),
            Some(&BuildIdentityError::DevelopmentSource),
            "development executables must fail release admission before custody: {error:#}",
        );
    }
}

fn validate_source_closure(revision: &RevisionV1) -> Result<()> {
    let manifest_path = Path::new(&revision.source_manifest_path);
    let (manifest, bytes) = read_json::<SourceManifestV1>(manifest_path, "signed source manifest")?;
    if sha256_hex(&bytes) != revision.source_manifest_sha256 {
        return Err(eyre!("signed source manifest SHA-256 mismatch"));
    }
    if manifest.schema != SOURCE_MANIFEST_SCHEMA_V1
        || manifest.branch != SOURCE_BRANCH
        || manifest.branch != revision.branch
        || manifest.head_commit_sha1 != revision.commit
        || manifest.head_tree_sha1 != revision.tree
        || manifest.cargo_lock_sha256 != revision.cargo_lock_sha256
        || manifest.closure_sha256 != revision.source_closure_sha256
        || !manifest.untracked_files.is_empty()
    {
        return Err(eyre!(
            "signed source manifest does not exactly bind the clean optimizations revision"
        ));
    }
    if manifest.tracked_files.is_empty() || manifest.tracked_files.len() > MAX_SOURCE_FILES {
        return Err(eyre!(
            "signed source manifest file count is outside the V1 bound"
        ));
    }
    let source_root = Path::new(&revision.source_root);
    validate_source_root(source_root)?;
    validate_git_provenance(source_root, revision)?;
    let actual = inspect_source_tree(source_root, &manifest.tracked_files)?;
    validate_git_provenance(source_root, revision)?;
    if actual != manifest.tracked_files {
        return Err(eyre!(
            "source root is dirty or differs from the exact signed tracked closure"
        ));
    }
    if source_closure_sha256(&manifest) != manifest.closure_sha256 {
        return Err(eyre!("signed source closure digest mismatch"));
    }
    let cargo_lock = manifest
        .tracked_files
        .iter()
        .find(|entry| entry.path == "Cargo.lock")
        .ok_or_else(|| eyre!("signed source closure omits Cargo.lock"))?;
    if cargo_lock.sha256 != revision.cargo_lock_sha256 || cargo_lock.mode != 0o644 {
        return Err(eyre!("signed source Cargo.lock binding is not canonical"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_source_root(path: &Path) -> Result<()> {
    validate_no_symlink_ancestors(path, "source root")?;
    let metadata = fs::symlink_metadata(path).wrap_err("failed to inspect source root")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.mode() & 0o022 != 0 {
        return Err(eyre!(
            "source root must be one direct non-group-writable directory"
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_source_root(_path: &Path) -> Result<()> {
    Err(eyre!("public Taira reset source admission requires Unix"))
}

fn inspect_source_tree(root: &Path, expected: &[SourceFileV1]) -> Result<Vec<SourceFileV1>> {
    let actual = source::capture_tree(root)?;
    if actual.as_slice() != expected {
        return Err(eyre!("source root differs from its exact tracked manifest"));
    }
    Ok(actual)
}

fn validate_git_provenance(root: &Path, revision: &RevisionV1) -> Result<()> {
    let [branch, head, tree] = source::clean_git_identity(root)?;
    if branch != revision.branch
        || head != revision.commit
        || head != crate::compiled_build_identity()?.release_source_commit()?
        || tree != revision.tree
    {
        return Err(eyre!(
            "source checkout is not the exact clean optimizations HEAD/tree compiled into this CLI"
        ));
    }
    Ok(())
}

fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    let bytes = git_output(root, args)?;
    let value = std::str::from_utf8(&bytes).wrap_err("Git output is not UTF-8")?;
    let value = value
        .strip_suffix('\n')
        .ok_or_else(|| eyre!("Git text output is not newline terminated"))?;
    if value.contains('\n') || value.contains('\r') {
        return Err(eyre!("Git text output contains extra lines"));
    }
    Ok(value.to_owned())
}

fn git_command(root: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(GIT);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .arg("--no-pager")
        .arg("--no-optional-locks")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-C")
        .arg(root);
    command
}

fn git_output(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = git_command(root)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .wrap_err("failed to execute fixed Git provenance command")?;
    if !output.status.success() || output.stdout.len() > MAX_GIT_OUTPUT_BYTES {
        return Err(eyre!(
            "fixed Git provenance command failed or exceeded its output bound"
        ));
    }
    Ok(output.stdout)
}

fn validate_source_relative_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value.as_bytes().contains(&0)
        || path.components().any(|component| {
            matches!(
                component,
                Component::RootDir
                    | Component::Prefix(_)
                    | Component::ParentDir
                    | Component::CurDir
            )
        })
    {
        return Err(eyre!("source closure path is not canonical relative UTF-8"));
    }
    Ok(())
}

fn source_closure_sha256(manifest: &SourceManifestV1) -> String {
    let mut digest = Sha256::new();
    digest.update(b"iroha:taira:public-reset:signed-source-closure:v1\0");
    for value in [
        manifest.branch.as_str(),
        manifest.head_commit_sha1.as_str(),
        manifest.head_tree_sha1.as_str(),
        manifest.cargo_lock_sha256.as_str(),
    ] {
        update_framed(&mut digest, value.as_bytes());
    }
    for entry in &manifest.tracked_files {
        update_framed(&mut digest, entry.path.as_bytes());
        update_framed(&mut digest, &entry.mode.to_be_bytes());
        update_framed(&mut digest, &entry.size.to_be_bytes());
        update_framed(&mut digest, entry.git_blob_sha1.as_bytes());
        update_framed(&mut digest, entry.sha256.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn validate_validator(
    validator: &ValidatorV1,
    slug: &str,
    revision: &RevisionV1,
    scope: QualificationScopeV1,
) -> Result<()> {
    if validator.slug != slug {
        return Err(eyre!("validator order is canonical; expected `{slug}`"));
    }
    validate_platform(&validator.platform, scope.includes_inrou().then_some(12))?;
    for (label, value) in [
        ("validator node fingerprint", &validator.node_fingerprint),
        ("validator build fingerprint", &validator.build_fingerprint),
        (
            "validator config fingerprint",
            &validator.config_fingerprint,
        ),
    ] {
        validate_canonical_iroha_hash(label, value)?;
    }
    let service_root = format!("/srv/taira/{slug}");
    let state_root = format!("/var/lib/taira/{slug}");
    if validator.service_root != service_root
        || validator.state_root != state_root
        || validator.reset_guard != format!("/var/lib/taira/.public-reset-control-v1/{slug}")
        || validator.systemd_unit != format!("iroha3d-{slug}.service")
    {
        return Err(eyre!(
            "validator `{slug}` does not use its exact guarded V1 roots/unit"
        ));
    }
    validate_endpoint(&validator.endpoint, &service_root, revision)?;
    validate_lower_hex(
        "validator systemd unit SHA-256",
        &validator.systemd_unit_sha256,
        64,
    )?;
    validate_artifacts(
        &validator.artifacts,
        &VALIDATOR_ARTIFACT_ROLES,
        &service_root,
        revision,
        BUILD_TARGET,
    )?;
    let release_root = format!("{service_root}/releases/{}", revision.commit);
    require_remote_artifact(
        &validator.artifacts,
        "iroha3d",
        &format!("{release_root}/bin/iroha3d_taira"),
    )?;
    require_remote_artifact(
        &validator.artifacts,
        "iroha_cli",
        &format!("{release_root}/bin/iroha"),
    )?;
    require_remote_artifact(
        &validator.artifacts,
        "kagami",
        &format!("{release_root}/bin/kagami"),
    )?;
    require_remote_artifact(
        &validator.artifacts,
        "sorafs_node",
        &format!("{release_root}/bin/sorafs-node"),
    )?;
    require_remote_artifact(
        &validator.artifacts,
        "config",
        &format!("{release_root}/config/config.toml"),
    )?;
    require_remote_artifact(
        &validator.artifacts,
        "genesis",
        &format!("{release_root}/genesis/genesis.json"),
    )?;
    require_remote_artifact(
        &validator.artifacts,
        "genesis_hash",
        &format!("{release_root}/genesis/genesis.sha256"),
    )?;
    require_remote_artifact(
        &validator.artifacts,
        "validator_unit",
        &format!("{release_root}/systemd/{}", validator.systemd_unit),
    )?;
    if artifact(&validator.artifacts, "validator_unit")?.sha256 != validator.systemd_unit_sha256 {
        return Err(eyre!(
            "candidate unit pin differs from its installed artifact"
        ));
    }
    if validator.endpoint.remote_cli != format!("{release_root}/bin/iroha") {
        return Err(eyre!(
            "validator `{slug}` remote CLI is not the exact same-revision artifact"
        ));
    }
    if validator.is_vacant() {
        return Ok(());
    }
    let release = validator.admitted_release()?;
    validate_lower_hex("admitted validator release commit", &release.commit, 40)?;
    if release.commit == revision.commit
        || release.release_root != format!("{service_root}/releases/{}", release.commit)
    {
        return Err(eyre!(
            "validator `{slug}` admitted release is not a distinct canonical prior release"
        ));
    }
    host::occupied::validate_occupied_binding(validator)
}

fn validate_edge(
    edge: &EdgeV1,
    revision: &RevisionV1,
    hosts: &host_pair::ResetHostPairV1,
) -> Result<()> {
    hosts.validate()?;
    edge.native_capability.validate(hosts)?;
    let native = &hosts.native_edge;
    let service_root = format!("{}/.local/share/iroha/taira/edge", native.owner_home);
    if edge.slug != "taira-edge"
        || edge.service_root != service_root
        || edge.state_root != format!("{service_root}/state")
        || edge.reset_guard != format!("{}/taira-edge", native.custody_root)
        || edge.nginx_config
            != edge
                .native_capability
                .incumbent
                .claims
                .owned_publication
                .publication
                .file
                .path
        || edge.platform.os != "macos"
        || edge.platform.arch != "aarch64"
        || edge.platform.kvm_api_version != 0
        || edge.endpoint.hostname != native.endpoint.hostname
        || edge.endpoint.user != native.endpoint.user
        || edge.endpoint.port != native.endpoint.port
        || edge.endpoint.known_host_line_sha256 != native.endpoint.known_host_line_sha256
        || edge.endpoint.host_identity_sha256 != native.endpoint.host_identity_sha256
        || edge.endpoint.upload_guard_sha256 != native.guard_sha256
    {
        return Err(eyre!(
            "edge does not use the exact independently guarded native Mac identity and roots"
        ));
    }
    if let EdgeInitialStateV1::AdmittedRelease(release) = &edge.initial_state {
        validate_lower_hex("admitted edge release commit", &release.commit, 40)?;
        if release.commit == revision.commit
            || release.release_root != format!("{}/releases/{}", edge.service_root, release.commit)
        {
            return Err(eyre!(
                "edge admitted release is not a distinct canonical prior release"
            ));
        }
        validate_lower_hex("edge rollback CLI SHA-256", &release.cli_sha256, 64)?;
        validate_lower_hex("edge rollback config SHA-256", &release.config_sha256, 64)?;
        if json::to_json(release)?
            != json::to_json(&edge.native_capability.incumbent.claims.release)?
        {
            return Err(eyre!(
                "native edge rollback release differs from its signed captured incumbent"
            ));
        }
    } else {
        return Err(eyre!(
            "native edge requires an independently captured owned incumbent publication"
        ));
    }
    validate_artifacts(
        &edge.artifacts,
        &EDGE_ARTIFACT_ROLES,
        &edge.service_root,
        revision,
        host_pair::NATIVE_EDGE_TARGET,
    )?;
    let release_root = format!("{}/releases/{}", edge.service_root, revision.commit);
    require_remote_artifact(
        &edge.artifacts,
        "iroha_cli",
        &format!("{release_root}/bin/iroha"),
    )?;
    require_remote_artifact(
        &edge.artifacts,
        "edge_config",
        &format!("{release_root}/taira.conf"),
    )?;
    if edge.endpoint.remote_cli != format!("{release_root}/bin/iroha")
        || artifact(&edge.artifacts, "iroha_cli")?.sha256 != native.dispatcher_sha256
    {
        return Err(eyre!(
            "edge remote CLI is not the exact same-revision artifact"
        ));
    }
    Ok(())
}

fn validate_platform(platform: &PlatformV1, required_kvm_api_version: Option<u32>) -> Result<()> {
    if platform.os != "linux" || platform.arch != "aarch64" {
        return Err(eyre!("public Taira hosts must be Linux/AArch64"));
    }
    // Core validators report observed KVM availability without requiring a guest runtime.
    if !matches!(platform.kvm_api_version, 0 | 12)
        || required_kvm_api_version.is_some_and(|required| platform.kvm_api_version != required)
    {
        return Err(eyre!(
            "core validators may declare KVM API 0 or 12, full_inrou validators require 12, and the edge requires 0"
        ));
    }
    Ok(())
}

/// Public validator routing is selected by the reviewed inventory, independently
/// of role slugs. Preserve the signed request path by admitting HTTPS roots only.
fn validate_validator_public_origin(origin: &str) -> Result<()> {
    let url = url::Url::parse(origin).wrap_err("validator public Torii origin is invalid")?;
    let Some(url::Host::Domain(host)) = url.host() else {
        return Err(eyre!(
            "validator public Torii origin requires a DNS hostname"
        ));
    };
    validate_hostname(host).wrap_err("validator public Torii hostname is invalid")?;
    if host.split('.').any(|label| {
        label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
    }) || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.port() == Some(0)
        || url.as_str() != origin
    {
        return Err(eyre!(
            "validator public Torii origin must be one canonical HTTPS DNS root without credentials, query, fragment, or path prefix"
        ));
    }
    Ok(())
}

/// Candidate probes stay on the authenticated deployment host and bypass public DNS/edge.
fn validate_candidate_probe_origin(origin: &str) -> Result<std::net::SocketAddr> {
    let url = url::Url::parse(origin).wrap_err("candidate Torii origin is invalid")?;
    let port = url
        .port()
        .filter(|port| *port != 0)
        .ok_or_else(|| eyre!("candidate Torii origin requires an explicit nonzero port"))?;
    if origin != format!("http://127.0.0.1:{port}/") {
        return Err(eyre!(
            "candidate Torii origin must be one exact loopback HTTP origin"
        ));
    }
    Ok(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
}

fn validate_candidate_probe_bind(
    origin: &str,
    bind: &iroha_primitives::addr::SocketAddr,
) -> Result<()> {
    let probe = validate_candidate_probe_origin(origin)?;
    let bind_ip = bind.ip().map(std::net::IpAddr::from);
    if bind.port() != probe.port()
        || !(bind_ip == Some(probe.ip()) || bind_ip == Some(std::net::Ipv4Addr::UNSPECIFIED.into()))
    {
        return Err(eyre!(
            "candidate Torii origin differs from its signed validator bind address"
        ));
    }
    Ok(())
}

fn validate_endpoint(
    endpoint: &EndpointV1,
    service_root: &str,
    revision: &RevisionV1,
) -> Result<()> {
    validate_hostname(&endpoint.hostname)?;
    if endpoint.port != 22 || endpoint.user != "root" {
        return Err(eyre!(
            "public-reset SSH endpoints require exact root@host:22"
        ));
    }
    validate_lower_hex(
        "known-host line SHA-256",
        &endpoint.known_host_line_sha256,
        64,
    )?;
    validate_lower_hex("host identity SHA-256", &endpoint.host_identity_sha256, 64)?;
    validate_lower_hex("upload guard SHA-256", &endpoint.upload_guard_sha256, 64)?;
    let expected_cli = format!("{service_root}/releases/{}/bin/iroha", revision.commit);
    if endpoint.remote_cli != expected_cli {
        return Err(eyre!("endpoint remote CLI must be `{expected_cli}`"));
    }
    Ok(())
}

fn validate_artifacts(
    artifacts: &[ArtifactV1],
    roles: &[&str],
    service_root: &str,
    revision: &RevisionV1,
    target: &str,
) -> Result<()> {
    if artifacts.len() != roles.len() {
        return Err(eyre!(
            "artifact list must contain the exact V1 role closure"
        ));
    }
    let release_root = format!("{service_root}/releases/{}/", revision.commit);
    let mut remote_paths = BTreeSet::new();
    for (artifact, role) in artifacts.iter().zip(roles.iter().copied()) {
        if artifact.role != role {
            return Err(eyre!("artifact order is canonical; expected role `{role}`"));
        }
        validate_lower_hex("artifact SHA-256", &artifact.sha256, 64)?;
        let (expected_mode, maximum) = artifact_role_policy(role)?;
        if artifact.size == 0
            || artifact.size > maximum
            || artifact.mode != expected_mode
            || artifact.source_commit != revision.commit
            || artifact.target != target
            || !Path::new(&artifact.local_path).is_absolute()
            || !artifact.remote_path.starts_with(&release_root)
            || !remote_paths.insert(artifact.remote_path.clone())
        {
            return Err(eyre!(
                "artifact `{role}` is not an exact same-revision V1 artifact"
            ));
        }
        validate_absolute_normal_path(Path::new(&artifact.local_path), "local artifact path")?;
        validate_absolute_normal_path(Path::new(&artifact.remote_path), "remote artifact path")?;
    }
    Ok(())
}

fn require_remote_artifact(artifacts: &[ArtifactV1], role: &str, path: &str) -> Result<()> {
    if artifacts
        .iter()
        .any(|artifact| artifact.role == role && artifact.remote_path == path)
    {
        Ok(())
    } else {
        Err(eyre!(
            "artifact role `{role}` must install at exact path `{path}`"
        ))
    }
}

fn validate_inrou(canary: &InrouCanaryV1) -> Result<()> {
    if canary.public_root != PUBLIC_ROOT
        || canary.service_name != "taira_inrou_canary"
        || canary.replicas != 4
        || canary.route_host != "taira.sora.org"
        || canary.route_path_prefix != "/api/v1/inrou-canary"
        || canary.healthcheck_path != "/health"
        || canary.discovery_payload_dir != "payloads/discovery"
        || canary.discovery_manifest_file != "manifests/discovery.to"
        || canary.stage_bytes == 0
        || canary.stage_bytes > MAX_INROU_STAGE_BYTES
    {
        return Err(eyre!(
            "Inrou canary must use the exact first-release four-replica identity"
        ));
    }
    if canary.placement_targets.len() != 4 {
        return Err(eyre!(
            "Inrou canary must bind exactly four distinct placement targets"
        ));
    }
    for target in &canary.placement_targets {
        target.validate()?;
    }
    let service_revision = canary
        .service_version
        .strip_prefix(INROU_CANARY_SERVICE_VERSION_PREFIX_V1)
        .ok_or_else(|| {
            eyre!(
                "Inrou canary service version must use the canonical first-release artifact identity"
            )
        })?;
    // The inventory admits only a canonical Iroha hash spelling here. Apply separately loads the
    // complete retained stage and recomputes the bundle-derived Blake2b-256 service version before
    // any host mutation; the inventory does not contain enough bundle material to reproduce it.
    validate_canonical_iroha_hash("Inrou canary service artifact revision", service_revision)?;
    validate_lower_hex("Inrou stage tree SHA-256", &canary.stage_tree_sha256, 64)?;
    for (label, value) in [
        (
            "Inrou bundle manifest digest",
            canary.bundle_manifest_digest_hex.as_str(),
        ),
        (
            "Inrou guest manifest digest",
            canary.guest_manifest_digest_hex.as_str(),
        ),
        (
            "Inrou discovery manifest digest",
            canary.discovery_manifest_digest_hex.as_str(),
        ),
    ] {
        validate_lower_hex(label, value, 64)?;
    }
    for (label, value) in [
        (
            "Inrou bundle content CID",
            canary.bundle_content_cid.as_str(),
        ),
        ("Inrou guest content CID", canary.guest_content_cid.as_str()),
        (
            "Inrou discovery content CID",
            canary.discovery_content_cid.as_str(),
        ),
    ] {
        if value.is_empty()
            || value.len() > 256
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(eyre!("{label} is outside the exact printable V1 bound"));
        }
    }
    for (label, value) in [
        ("Inrou bundle hash", canary.bundle_hash.as_str()),
        (
            "Inrou discovery document hash",
            canary.discovery_document_hash.as_str(),
        ),
        (
            "Inrou deployment bundle hash",
            canary.deployment_bundle_hash.as_str(),
        ),
        (
            "Inrou container manifest hash",
            canary.container_manifest_hash.as_str(),
        ),
        (
            "Inrou service manifest hash",
            canary.service_manifest_hash.as_str(),
        ),
    ] {
        validate_canonical_iroha_hash(label, value)?;
    }
    let expected_public_discovery_url = format!(
        "https://taira.sora.org/sorafs/cid/{}/index.json",
        canary.discovery_content_cid
    );
    let expected_public_discovery_cid_host_url = format!(
        "https://{}.sorafs.taira.sora.org/index.json",
        canary.discovery_content_cid
    );
    if canary.public_discovery_url != expected_public_discovery_url
        || canary.public_discovery_cid_host_url != expected_public_discovery_cid_host_url
    {
        return Err(eyre!(
            "Inrou public discovery URLs must be the exact path and CID-host V1 projections"
        ));
    }
    validate_lower_hex("Inrou receipt SHA-256", &canary.receipt_sha256, 64)?;
    for (label, value) in [
        ("Inrou container SHA-256", canary.container_sha256.as_str()),
        ("Inrou service SHA-256", canary.service_sha256.as_str()),
        (
            "Inrou bundle payload SHA-256",
            canary.bundle_payload_sha256.as_str(),
        ),
        (
            "Inrou bundle manifest SHA-256",
            canary.bundle_manifest_sha256.as_str(),
        ),
        (
            "Inrou guest manifest SHA-256",
            canary.guest_manifest_sha256.as_str(),
        ),
        (
            "Inrou discovery document SHA-256",
            canary.discovery_document_sha256.as_str(),
        ),
        (
            "Inrou discovery manifest SHA-256",
            canary.discovery_manifest_sha256.as_str(),
        ),
    ] {
        validate_lower_hex(label, value, 64)?;
    }
    Ok(())
}

fn validate_canary_onboarding_request(request: &AccountOnboardingPlanRequestV1) -> Result<()> {
    let account = AccountId::parse_encoded(&request.account_id)
        .wrap_err("public-reset canary account is not a canonical I105 identity")?;
    let canonical = AccountOnboardingPlanRequestV1::try_new(
        request.alias.clone(),
        &account,
        request.permissions.clone(),
    )?;
    let signatory = account
        .try_signatory()
        .ok_or_else(|| eyre!("public-reset canary account must be a single-signatory identity"))?;
    let expected_alias = crate::taira::canary_alias(signatory);
    if request != &canonical || request.alias != expected_alias || !request.permissions.is_empty() {
        return Err(eyre!(
            "public-reset canary onboarding request must be the exact empty-permission V1 canary identity"
        ));
    }
    Ok(())
}

fn validate_faucet_policy(policy: &FaucetPolicyV1) -> Result<()> {
    let authority = AccountId::parse_encoded(&policy.authority)
        .wrap_err("public-reset faucet authority is not a canonical I105 identity")?;
    if authority.to_string() != policy.authority || authority.try_signatory().is_none() {
        return Err(eyre!(
            "public-reset faucet authority must be one canonical single-signatory AccountId"
        ));
    }
    let asset_definition_id = AssetDefinitionId::from_str(&policy.asset_definition_id)
        .wrap_err("public-reset faucet asset definition is invalid")?;
    if asset_definition_id.to_string() != policy.asset_definition_id
        || policy.asset_definition_id != crate::taira::DEFAULT_GAS_ASSET_ID
    {
        return Err(eyre!(
            "public-reset faucet asset must be the canonical Taira V1 fee asset"
        ));
    }
    if policy.amount.is_zero() {
        return Err(eyre!(
            "public-reset faucet amount must be greater than zero"
        ));
    }
    Ok(())
}

fn validate_fee_intent(intent: &FeeIntentV1) -> Result<()> {
    match intent.payer.as_str() {
        "authority" => {
            if intent.sponsor_program.is_some() || intent.sponsor_program_revision.is_some() {
                return Err(eyre!(
                    "authority fee intent cannot carry sponsor-program fields"
                ));
            }
        }
        "sponsor" => {
            let raw = intent
                .sponsor_program
                .as_deref()
                .ok_or_else(|| eyre!("sponsor fee intent requires an exact program ID"))?;
            let program = FeeSponsorProgramId::from_str(raw)
                .wrap_err("sponsor fee intent program ID is invalid")?;
            if program.to_string() != raw {
                return Err(eyre!("sponsor fee intent program ID is not canonical"));
            }
            if intent
                .sponsor_program_revision
                .is_none_or(|revision| revision == 0)
            {
                return Err(eyre!(
                    "sponsor fee intent requires an exact nonzero program revision"
                ));
            }
        }
        _ => return Err(eyre!("fee intent payer must be `authority` or `sponsor`")),
    }
    Ok(())
}

fn validate_cleanup(cleanup: &CleanupV1) -> Result<()> {
    const MIN_RECLAIM_BYTES: u64 = 1024 * 1024;
    const MAX_RECLAIM_BYTES: u64 = 256 * 1024 * 1024 * 1024;
    if cleanup.policy != "marker_bound_generated_waste_v1"
        || !(MIN_RECLAIM_BYTES..=MAX_RECLAIM_BYTES).contains(&cleanup.max_reclaim_bytes_per_host)
        || !(3_600..=2_592_000).contains(&cleanup.minimum_age_secs)
        || !(2..=8).contains(&cleanup.retain_successful_releases)
        || !cleanup.delete_only_marker_bound_generated_paths
        || !cleanup.preserve_state
        || !cleanup.preserve_secrets
        || !cleanup.preserve_rollback_release
    {
        return Err(eyre!(
            "cleanup must use the bounded marker-only V1 policy and preserve state, secrets, and rollback releases"
        ));
    }
    Ok(())
}

fn artifact_role_policy(role: &str) -> Result<(u16, u64)> {
    const MIB: u64 = 1024 * 1024;
    match role {
        "iroha3d" | "iroha_cli" | "kagami" | "sorafs_node" => Ok((0o755, 512 * MIB)),
        "config" => Ok((0o600, MIB)),
        "genesis" => Ok((0o644, 64 * MIB)),
        "genesis_hash" => Ok((0o644, 65)),
        "edge_config" => Ok((0o640, MIB)),
        "validator_unit" => Ok((0o644, MIB)),
        _ => Err(eyre!("unsupported first-release artifact role `{role}`")),
    }
}

fn artifact<'a>(artifacts: &'a [ArtifactV1], role: &str) -> Result<&'a ArtifactV1> {
    artifacts
        .iter()
        .find(|artifact| artifact.role == role)
        .ok_or_else(|| eyre!("missing artifact role `{role}`"))
}

fn validate_artifact_files(inventory: &InventoryV1) -> Result<Vec<PinnedArtifact>> {
    validate_artifact_files_with(inventory, sha256_reader)
}

fn validate_artifact_files_with(
    inventory: &InventoryV1,
    mut hash: impl FnMut(&mut File, &Path) -> Result<String>,
) -> Result<Vec<PinnedArtifact>> {
    let mut pinned = Vec::new();
    let mut sources = BTreeMap::<PathBuf, ValidatedArtifactSource>::new();
    for (slug, artifacts) in inventory
        .validators
        .iter()
        .map(|validator| (validator.slug.as_str(), &validator.artifacts))
        .chain(std::iter::once((
            inventory.edge.slug.as_str(),
            &inventory.edge.artifacts,
        )))
    {
        for artifact in artifacts {
            let path = Path::new(&artifact.local_path);
            let source = match sources.entry(path.to_path_buf()) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let (mut file, snapshot) = open_pinned_regular(path, "artifact")?;
                    if snapshot.len != artifact.size {
                        return Err(eyre!(
                            "artifact `{}` is not the pinned direct regular file",
                            path.display()
                        ));
                    }
                    let actual = hash(&mut file, path)?;
                    ensure_pinned_unchanged(path, "artifact", &file, &snapshot)?;
                    if actual != artifact.sha256 {
                        return Err(eyre!("artifact `{}` SHA-256 drifted", path.display()));
                    }
                    #[cfg(unix)]
                    if snapshot.uid != rustix::process::geteuid().as_raw()
                        || snapshot.mode & 0o7777 != u32::from(artifact.mode)
                        || snapshot.nlink != 1
                    {
                        return Err(eyre!(
                            "artifact `{}` does not have its exact owner/mode/single-link custody",
                            path.display()
                        ));
                    }
                    entry.insert(ValidatedArtifactSource {
                        sha256: actual,
                        size: snapshot.len,
                        mode: artifact.mode,
                        input: PinnedInput {
                            path: path.to_path_buf(),
                            file,
                            snapshot,
                        },
                    })
                }
            };
            if source.sha256 != artifact.sha256
                || source.size != artifact.size
                || source.mode != artifact.mode
            {
                return Err(eyre!(
                    "artifact `{}` has conflicting content, size, or mode declarations",
                    path.display()
                ));
            }
            let input = clone_revalidated_pinned(&source.input, "artifact")?;
            pinned.push(PinnedArtifact {
                slug: slug.to_owned(),
                role: artifact.role.clone(),
                artifact: artifact.clone(),
                input,
            });
        }
    }
    Ok(pinned)
}

/// Admit the complete signed-genesis startup closure without external TOML sources.
fn validate_validator_genesis_config(
    bytes: &[u8],
    signed_genesis: &Path,
    expected_hash: &str,
) -> Result<()> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| eyre!("validator startup config is not UTF-8"))?;
    let mut table: toml::Table =
        toml::from_str(text).map_err(|_| eyre!("validator startup config is not TOML"))?;
    let result = (|| {
        if table.contains_key("extends") {
            return Err(eyre!(
                "validator startup config cannot inherit unbound TOML"
            ));
        }
        let genesis = table
            .get("genesis")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| eyre!("validator startup config omits its genesis table"))?;
        if genesis.contains_key("manifest_json") || genesis.contains_key("expected_hash_file") {
            return Err(eyre!(
                "validator startup config cannot use an unbound genesis manifest or identity file"
            ));
        }
        if genesis.get("file").and_then(toml::Value::as_str) != signed_genesis.to_str() {
            return Err(eyre!(
                "validator startup config does not select its exact signed genesis artifact"
            ));
        }
        let literal = genesis
            .get("expected_hash")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                eyre!("validator startup config requires an inline checked network identity")
            })?;
        let network = literal
            .parse::<iroha::data_model::NetworkId>()
            .map_err(|_| eyre!("validator startup network identity is not canonical"))?;
        validate_canonical_iroha_hash("signed genesis hash", expected_hash)?;
        let expected = hex::decode(expected_hash)?;
        if network.to_string() != literal || network.as_bytes().as_slice() != expected.as_slice() {
            return Err(eyre!(
                "validator startup network identity differs from its signed genesis hash"
            ));
        }
        Ok(())
    })();
    crate::soracloud::zeroize_taira_toml_table(&mut table);
    result
}

/// Require one explicit canonical operator identity in the signed inventory.
fn validator_operator_public_key(value: &str) -> Result<iroha_crypto::PublicKey> {
    let key = value
        .parse::<iroha_crypto::PublicKey>()
        .map_err(|_| eyre!("validator operator public key must be canonical Ed25519"))?;
    if key.try_algorithm().ok() != Some(Algorithm::Ed25519) || key.to_string() != value {
        return Err(eyre!(
            "validator operator public key must be canonical Ed25519"
        ));
    }
    Ok(key)
}

/// Check that startup policy accepts the credential used by deployment probes.
fn validate_validator_operator_config(bytes: &[u8], expected_public_key: &str) -> Result<()> {
    validator_operator_public_key(expected_public_key)?;
    let text =
        std::str::from_utf8(bytes).map_err(|_| eyre!("validator startup config is not UTF-8"))?;
    let mut table: toml::Table =
        toml::from_str(text).map_err(|_| eyre!("validator startup config is not TOML"))?;
    let result = (|| {
        if table.contains_key("extends") {
            return Err(eyre!(
                "validator startup config cannot inherit unbound TOML"
            ));
        }
        let policy = table
            .get("torii")
            .and_then(toml::Value::as_table)
            .and_then(|torii| torii.get("operator_signatures"))
            .and_then(toml::Value::as_table)
            .ok_or_else(|| eyre!("validator config requires explicit operator signing policy"))?;
        if policy.get("enabled").and_then(toml::Value::as_bool) != Some(true)
            || !policy
                .get("allowed_public_keys")
                .and_then(toml::Value::as_array)
                .is_some_and(|keys| {
                    keys.iter()
                        .any(|key| key.as_str() == Some(expected_public_key))
                })
        {
            return Err(eyre!(
                "validator config does not authorize the signed operator public key"
            ));
        }
        Ok(())
    })();
    crate::soracloud::zeroize_taira_toml_table(&mut table);
    result
}

/// Bind the public startup policy to independently authorized intent without opening signer files.
fn validate_validator_faucet_config(bytes: &[u8], expected: &FaucetPolicyV1) -> Result<()> {
    use iroha_config::{
        base::{read::ConfigReader, toml::TomlSource},
        parameters::user,
    };

    validate_faucet_policy(expected)
        .map_err(|_| eyre!("signed faucet policy failed canonical admission"))?;
    let text =
        std::str::from_utf8(bytes).map_err(|_| eyre!("validator startup config is not UTF-8"))?;
    let table: toml::Table =
        toml::from_str(text).map_err(|_| eyre!("validator startup config is not TOML"))?;
    let path = PathBuf::from("validator-faucet");
    let mut source = TomlSource::new_sensitive(
        path.clone(),
        table,
        crate::soracloud::zeroize_taira_toml_table,
    );
    let root = source.table_mut();
    if root.contains_key("extends") {
        return Err(eyre!(
            "validator startup config cannot inherit unbound TOML"
        ));
    }
    let faucet = root
        .get("torii")
        .and_then(toml::Value::as_table)
        .and_then(|torii| torii.get("faucet"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| eyre!("validator config requires explicit faucet policy"))?
        .clone();
    // Read the native user fields, including Quantity and defaults, but do not
    // parse the runtime signer or infer policy from its key or the public API.
    let parsed = ConfigReader::new()
        .without_env()
        .with_toml_source(TomlSource::new_sensitive(
            path,
            faucet,
            crate::soracloud::zeroize_taira_toml_table,
        ))
        .read_and_complete::<user::ToriiFaucet>()
        .map_err(|_| eyre!("validator faucet policy failed typed admission"))?;
    if !parsed.enabled {
        return Err(eyre!("validator faucet must be enabled for public reset"));
    }
    if parsed.authority != expected.authority {
        return Err(eyre!(
            "validator faucet authority differs from signed intent"
        ));
    }
    if parsed.asset_definition_id != expected.asset_definition_id {
        return Err(eyre!("validator faucet asset differs from signed intent"));
    }
    if parsed.amount != expected.amount {
        return Err(eyre!("validator faucet amount differs from signed intent"));
    }
    Ok(())
}

fn validate_pinned_validator_genesis_configs(
    inventory: &InventoryV1,
    pinned: &[PinnedArtifact],
) -> Result<()> {
    for validator in &inventory.validators {
        let input = &pinned
            .iter()
            .find(|entry| entry.slug == validator.slug && entry.role == "config")
            .ok_or_else(|| eyre!("validator startup config was not pinned"))?
            .input;
        let mut file = input.file.try_clone()?;
        file.rewind()?;
        let bytes = zeroize::Zeroizing::new(read_pinned_bytes(
            &input.path,
            "validator startup config",
            file,
            &input.snapshot,
            1024 * 1024,
        )?);
        validate_validator_genesis_config(
            &bytes,
            Path::new(&artifact(&validator.artifacts, "genesis")?.remote_path),
            &inventory.next_genesis_hash,
        )?;
        validate_validator_operator_config(&bytes, &inventory.operator_public_key)?;
        validate_validator_faucet_config(&bytes, &inventory.faucet_policy)?;
    }
    Ok(())
}

fn validate_known_hosts(inventory: &InventoryV1, path: &Path) -> Result<PinnedInput> {
    let endpoints = inventory
        .validators
        .iter()
        .map(|v| &v.endpoint)
        .chain(std::iter::once(&inventory.edge.endpoint))
        .collect::<Vec<_>>();
    validate_known_host_endpoints(&endpoints, path)
}
fn validate_known_host_endpoints(endpoints: &[&EndpointV1], path: &Path) -> Result<PinnedInput> {
    let (file, snapshot) = open_pinned_regular(path, "OpenSSH known-hosts")?;
    require_owner_private_snapshot(&snapshot, "OpenSSH known-hosts")?;
    let bytes = read_pinned_bytes(
        path,
        "OpenSSH known-hosts",
        file.try_clone()
            .wrap_err("failed to retain known-hosts descriptor")?,
        &snapshot,
        MAX_JSON_BYTES,
    )?;
    let text = std::str::from_utf8(&bytes).wrap_err("known-hosts must be UTF-8")?;
    if !text.ends_with('\n') || text.lines().any(|line| line.is_empty()) {
        return Err(eyre!(
            "known-hosts must be an exact non-empty newline-terminated closure"
        ));
    }
    let lines: Vec<&str> = text.lines().collect();
    let mut physical = BTreeMap::new();
    for endpoint in endpoints {
        let route = (&endpoint.hostname, endpoint.port, &endpoint.user);
        if let Some(previous) = physical.insert(route, *endpoint)
            && (previous.host_identity_sha256 != endpoint.host_identity_sha256
                || previous.known_host_line_sha256 != endpoint.known_host_line_sha256)
        {
            return Err(eyre!(
                "roles sharing one SSH route disagree on its independently admitted pins"
            ));
        }
    }
    if physical.len() != 2 || lines.len() != physical.len() {
        return Err(eyre!(
            "known-hosts must contain exactly two admitted physical host lines"
        ));
    }
    let mut seen_hosts = BTreeSet::new();
    let mut seen_lines = BTreeSet::new();
    for line in &lines {
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.len() != 3
            || fields[0].starts_with('@')
            || fields[0]
                .bytes()
                .any(|byte| matches!(byte, b',' | b'*' | b'?' | b'!' | b'[' | b']'))
            || fields[1] != "ssh-ed25519"
            || !seen_hosts.insert(fields[0])
            || !seen_lines.insert(sha256_hex(line.as_bytes()))
        {
            return Err(eyre!(
                "known-hosts lines must be unique exact host ssh-ed25519 key triples"
            ));
        }
    }
    for endpoint in physical.values() {
        let expected_host = endpoint.hostname.as_str();
        let mut matched = false;
        for line in &lines {
            if sha256_hex(line.as_bytes()) == endpoint.known_host_line_sha256 {
                let fields: Vec<&str> = line.split_ascii_whitespace().collect();
                let host_field = fields[0];
                if host_field != expected_host {
                    return Err(eyre!(
                        "pinned known-host line does not name `{expected_host}` exactly"
                    ));
                }
                let identity = format!("{} {}", fields[1], fields[2]);
                if sha256_hex(identity.as_bytes()) != endpoint.host_identity_sha256 {
                    return Err(eyre!(
                        "pinned known-host key identity for `{expected_host}` does not match inventory"
                    ));
                }
                matched = true;
            }
        }
        if !matched {
            return Err(eyre!(
                "known-hosts is missing the pinned line for `{expected_host}`"
            ));
        }
    }
    ensure_pinned_unchanged(path, "OpenSSH known-hosts", &file, &snapshot)?;
    Ok(PinnedInput {
        path: path.to_path_buf(),
        file,
        snapshot,
    })
}

fn validate_shared_validator_closure(inventory: &InventoryV1) -> Result<()> {
    let first = &inventory.validators[0].artifacts;
    for role in [
        "iroha3d",
        "iroha_cli",
        "kagami",
        "sorafs_node",
        "genesis",
        "genesis_hash",
    ] {
        let expected = artifact(first, role)?;
        for validator in inventory.validators.iter().skip(1) {
            let actual = artifact(&validator.artifacts, role)?;
            if actual.sha256 != expected.sha256
                || actual.size != expected.size
                || actual.mode != expected.mode
            {
                return Err(eyre!(
                    "validator role `{role}` must be byte-identical on all four hosts"
                ));
            }
        }
    }
    let config_hashes = inventory
        .validators
        .iter()
        .map(|validator| artifact(&validator.artifacts, "config").map(|value| value.sha256.clone()))
        .collect::<Result<BTreeSet<_>>>()?;
    if config_hashes.len() != VALIDATOR_SLUGS.len() {
        return Err(eyre!("each validator configuration must be distinct"));
    }
    let first_cli = artifact(first, "iroha_cli")?;
    let edge_cli = artifact(&inventory.edge.artifacts, "iroha_cli")?;
    if first_cli.target != BUILD_TARGET
        || edge_cli.target != host_pair::NATIVE_EDGE_TARGET
        || first_cli.source_commit != edge_cli.source_commit
        || first_cli.mode != 0o755
        || edge_cli.mode != 0o755
        || edge_cli.sha256 != inventory.hosts.native_edge.dispatcher_sha256
    {
        return Err(eyre!(
            "guest and native edge CLI artifacts must share source with their independently admitted targets"
        ));
    }
    Ok(())
}

fn validate_genesis_hash_files(inventory: &InventoryV1, pinned: &[PinnedArtifact]) -> Result<()> {
    let expected = format!("{}\n", inventory.next_genesis_hash);
    for entry in pinned.iter().filter(|entry| entry.role == "genesis_hash") {
        let mut file = entry
            .input
            .file
            .try_clone()
            .wrap_err("failed to duplicate pinned genesis-hash descriptor")?;
        file.rewind()
            .wrap_err("failed to rewind pinned genesis-hash descriptor")?;
        let mut bytes = Vec::new();
        file.take(66)
            .read_to_end(&mut bytes)
            .wrap_err("failed to read pinned genesis-hash descriptor")?;
        ensure_pinned_unchanged(
            &entry.input.path,
            "genesis-hash artifact",
            &entry.input.file,
            &entry.input.snapshot,
        )?;
        if bytes != expected.as_bytes() {
            return Err(eyre!(
                "validator `{}` genesis-hash artifact does not contain the declared next genesis hash",
                entry.slug
            ));
        }
    }
    Ok(())
}

/// Validate individual action bounds and their complete signed execution lease without IO.
fn validate_timeout_policy(inventory: &InventoryV1) -> Result<()> {
    validate_timeouts(&inventory.timeouts)?;
    execution_lifetime_ms(inventory).map(|_| ())
}

fn validate_timeouts(timeouts: &TimeoutsV1) -> Result<()> {
    for (name, value) in [
        ("stop", timeouts.stop_secs),
        ("install", timeouts.install_secs),
        ("reset", timeouts.reset_secs),
        ("start", timeouts.start_secs),
        ("convergence", timeouts.convergence_secs),
        ("canary", timeouts.canary_secs),
        ("restart", timeouts.restart_secs),
        ("edge", timeouts.edge_secs),
        ("cleanup", timeouts.cleanup_secs),
        ("rollback", timeouts.rollback_secs),
    ] {
        if !(1..=600).contains(&value) {
            return Err(eyre!("{name} timeout must be within 1..=600 seconds"));
        }
    }
    if !(1..=3_600).contains(&timeouts.preseed_secs) {
        return Err(eyre!("preseed timeout must be within 1..=3600 seconds"));
    }
    Ok(())
}

fn artifact_closure_sha256<Beacon>(inventory: &InventoryRecordV1<Beacon>) -> String {
    let mut digest = Sha256::new();
    digest.update(b"iroha:taira:public-reset:artifact-closure:v1\0");
    for value in [
        inventory.revision.commit.as_str(),
        inventory.revision.branch.as_str(),
        inventory.revision.tree.as_str(),
        inventory.revision.cargo_lock_sha256.as_str(),
        inventory.revision.source_manifest_sha256.as_str(),
        inventory.revision.source_closure_sha256.as_str(),
        inventory.revision.target.as_str(),
        inventory.revision.profile.as_str(),
        inventory.previous_genesis_hash.as_str(),
        inventory.next_genesis_hash.as_str(),
    ] {
        update_framed(&mut digest, value.as_bytes());
    }
    for artifact in inventory
        .validators
        .iter()
        .flat_map(|validator| validator.artifacts.iter())
        .chain(inventory.edge.artifacts.iter())
    {
        for value in [
            artifact.role.as_str(),
            artifact.remote_path.as_str(),
            artifact.sha256.as_str(),
        ] {
            update_framed(&mut digest, value.as_bytes());
        }
        update_framed(&mut digest, &artifact.size.to_be_bytes());
        update_framed(&mut digest, &artifact.mode.to_be_bytes());
    }
    hex::encode(digest.finalize())
}

fn update_framed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(bytes);
}

fn validate_slug(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || value.starts_with('-')
        || value.ends_with('-')
    {
        return Err(eyre!("{label} must be a canonical lowercase slug"));
    }
    Ok(())
}

fn validate_nonce(value: &str) -> Result<()> {
    if value.len() != 32
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
    {
        return Err(eyre!(
            "authorization nonce must be exactly 32 lowercase URL-safe ASCII characters"
        ));
    }
    Ok(())
}

fn validate_hostname(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 253
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
        })
        || !value.contains('.')
        || value.starts_with('.')
        || value.ends_with('.')
    {
        return Err(eyre!("SSH hostname must be a canonical lowercase DNS name"));
    }
    Ok(())
}

fn validate_lower_hex(label: &str, value: &str, length: usize) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(eyre!(
            "{label} must be exactly {length} lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn validate_canonical_iroha_hash(label: &str, value: &str) -> Result<()> {
    let hash = value
        .parse::<Hash>()
        .wrap_err_with(|| format!("{label} is not a canonical Iroha hash"))?;
    if hash.to_string() != value {
        return Err(eyre!("{label} is not a canonical Iroha hash"));
    }
    Ok(())
}

fn validate_recovery_intent(
    intent: &RecoveryIntentV1,
    step: executor_model::ExecutionStep,
) -> Result<()> {
    if intent.schema != RECOVERY_INTENT_SCHEMA_V1
        || intent.step_label != step.label()
        || intent.mutations.is_empty()
        || intent.mutations.len() > 64
    {
        return Err(eyre!(
            "recovery intent does not bind the exact prepared step"
        ));
    }
    let next_mutation = usize::from(intent.next_mutation);
    if next_mutation > intent.mutations.len() {
        return Err(eyre!(
            "recovery intent cursor exceeds its ordered mutation list"
        ));
    }
    let mut identities = BTreeSet::new();
    let mut idempotency_keys = BTreeSet::new();
    let mut receipt_names = BTreeSet::new();
    for (index, mutation) in intent.mutations.iter().enumerate() {
        for (label, value) in [
            ("recovery mutation kind", mutation.kind.as_str()),
            ("recovery mutation phase", mutation.phase.as_str()),
        ] {
            if value.is_empty()
                || value.len() > 128
                || !value.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'-')
                })
            {
                return Err(eyre!("{label} is not a canonical V1 label"));
            }
        }
        if mutation.idempotency_key.len() != 64
            || !mutation
                .idempotency_key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(eyre!(
                "recovery mutation idempotency key must be an exact lowercase SHA-256 digest"
            ));
        }
        let receipt = Path::new(&mutation.receipt_name);
        if mutation.receipt_name.is_empty()
            || mutation.receipt_name.len() > 255
            || receipt.components().count() != 1
            || !matches!(receipt.components().next(), Some(Component::Normal(_)))
        {
            return Err(eyre!("recovery receipt name must be one exact basename"));
        }
        if !identities.insert((
            mutation.kind.as_str(),
            mutation.phase.as_str(),
            mutation.idempotency_key.as_str(),
            mutation.receipt_name.as_str(),
        )) {
            return Err(eyre!(
                "recovery intent contains a duplicate mutation identity"
            ));
        }
        if !idempotency_keys.insert(mutation.idempotency_key.as_str())
            || !receipt_names.insert(mutation.receipt_name.as_str())
        {
            return Err(eyre!(
                "recovery intent reuses an idempotency key or receipt name"
            ));
        }
        let valid_state = if index < next_mutation {
            mutation.state == RecoveryMutationStateV1::Applied
        } else if index == next_mutation {
            matches!(
                mutation.state,
                RecoveryMutationStateV1::Prepared | RecoveryMutationStateV1::Submitted
            )
        } else {
            mutation.state == RecoveryMutationStateV1::Prepared
        };
        if !valid_state {
            return Err(eyre!(
                "recovery mutation states do not match their exact ordered cursor"
            ));
        }
    }
    Ok(())
}

fn recovery_ready_to_continue(
    intent: &RecoveryIntentV1,
    step: executor_model::ExecutionStep,
) -> bool {
    validate_recovery_intent(intent, step).is_ok()
        && intent
            .mutations
            .get(usize::from(intent.next_mutation))
            .is_some_and(|mutation| mutation.state == RecoveryMutationStateV1::Prepared)
}

/// Only a host-side provider publication can retain Submitted while resuming
/// forward work. Ceremony and ledger submissions have no such continuation.
fn recovery_ready_to_resume_beacon_activation(
    intent: &RecoveryIntentV1,
    step: executor_model::ExecutionStep,
) -> bool {
    if step != executor_model::ExecutionStep::Canary
        || validate_recovery_intent(intent, step).is_err()
    {
        return false;
    }
    let index = usize::from(intent.next_mutation);
    (4..8).contains(&index)
        && intent.mutations.get(index).is_some_and(|mutation| {
            mutation.state == RecoveryMutationStateV1::Submitted
                && mutation.phase == "pre_edge"
                && mutation.kind == format!("beacon_provider_{}", index - 3)
        })
}

fn recovery_has_forward_frontier(
    intent: &RecoveryIntentV1,
    step: executor_model::ExecutionStep,
) -> bool {
    recovery_ready_to_continue(intent, step)
        || recovery_ready_to_resume_beacon_activation(intent, step)
}

fn validate_absolute_normal_path(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(eyre!("{label} must be an absolute normalized path"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileSnapshot {
    len: u64,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    nlink: u64,
    #[cfg(unix)]
    ctime: i64,
    #[cfg(unix)]
    ctime_nsec: i64,
    modified: SystemTime,
}

#[cfg(unix)]
fn file_snapshot(metadata: &fs::Metadata) -> Result<FileSnapshot> {
    Ok(FileSnapshot {
        len: metadata.len(),
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        nlink: metadata.nlink(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
        modified: metadata
            .modified()
            .wrap_err("failed to read file modification time")?,
    })
}

#[cfg(unix)]
fn open_pinned_regular(path: &Path, label: &str) -> Result<(File, FileSnapshot)> {
    validate_no_symlink_ancestors(path, label)?;
    let before = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("failed to inspect {label} `{}`", path.display()))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(eyre!(
            "{label} must be a direct regular file: `{}`",
            path.display()
        ));
    }
    let expected = file_snapshot(&before)?;
    let current_uid = rustix::process::geteuid().as_raw();
    if (expected.uid != 0 && expected.uid != current_uid)
        || expected.mode & 0o022 != 0
        || expected.nlink != 1
    {
        return Err(eyre!("{label} has unsafe ownership, mode, or link count"));
    }
    let file = File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .wrap_err_with(|| format!("failed to securely open {label} `{}`", path.display()))?,
    );
    let opened = file_snapshot(&file.metadata()?)?;
    if opened != expected {
        return Err(eyre!(
            "{label} changed between path inspection and descriptor open"
        ));
    }
    Ok((file, opened))
}

#[cfg(not(unix))]
fn open_pinned_regular(_path: &Path, _label: &str) -> Result<(File, FileSnapshot)> {
    Err(eyre!(
        "public Taira reset is supported only on Unix operator hosts"
    ))
}

#[cfg(unix)]
fn ensure_pinned_unchanged(
    path: &Path,
    label: &str,
    file: &File,
    expected: &FileSnapshot,
) -> Result<()> {
    let descriptor = file_snapshot(&file.metadata()?)?;
    let path_metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("failed to re-inspect {label} `{}`", path.display()))?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || descriptor != *expected
        || file_snapshot(&path_metadata)? != *expected
    {
        return Err(eyre!("{label} changed during descriptor-bound validation"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_pinned_unchanged(
    _path: &Path,
    _label: &str,
    _file: &File,
    _expected: &FileSnapshot,
) -> Result<()> {
    Err(eyre!(
        "public Taira reset is supported only on Unix operator hosts"
    ))
}

#[cfg(unix)]
fn require_owner_private_snapshot(snapshot: &FileSnapshot, label: &str) -> Result<()> {
    if snapshot.uid != rustix::process::geteuid().as_raw()
        || !matches!(snapshot.mode & 0o7777, 0o400 | 0o600)
        || snapshot.nlink != 1
    {
        return Err(eyre!(
            "{label} must be an owner-private single-link regular file"
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_owner_private_snapshot(_snapshot: &FileSnapshot, _label: &str) -> Result<()> {
    Err(eyre!(
        "public Taira reset is supported only on Unix operator hosts"
    ))
}

fn read_pinned_bytes(
    path: &Path,
    label: &str,
    mut file: File,
    snapshot: &FileSnapshot,
    maximum: u64,
) -> Result<Vec<u8>> {
    if snapshot.len > maximum {
        return Err(eyre!("{label} exceeds the {maximum}-byte V1 limit"));
    }
    let capacity =
        usize::try_from(snapshot.len).wrap_err("pinned input length is not representable")?;
    let mut bytes = Vec::with_capacity(capacity);
    {
        let mut limited = (&mut file).take(maximum.saturating_add(1));
        limited
            .read_to_end(&mut bytes)
            .wrap_err_with(|| format!("failed to read {label} `{}`", path.display()))?;
    }
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(eyre!("{label} exceeds the {maximum}-byte V1 limit"));
    }
    ensure_pinned_unchanged(path, label, &file, snapshot)?;
    Ok(bytes)
}

fn pin_owner_private_file(path: &Path, label: &str) -> Result<PinnedInput> {
    let (file, snapshot) = open_pinned_regular(path, label)?;
    require_owner_private_snapshot(&snapshot, label)?;
    ensure_pinned_unchanged(path, label, &file, &snapshot)?;
    Ok(PinnedInput {
        path: path.to_path_buf(),
        file,
        snapshot,
    })
}

fn revalidate_pinned(input: &PinnedInput, label: &str) -> Result<()> {
    ensure_pinned_unchanged(&input.path, label, &input.file, &input.snapshot)
}

fn clone_revalidated_pinned(input: &PinnedInput, label: &str) -> Result<PinnedInput> {
    revalidate_pinned(input, label)?;
    let file = input
        .file
        .try_clone()
        .wrap_err_with(|| format!("failed to duplicate pinned {label} descriptor"))?;
    #[cfg(unix)]
    {
        let snapshot = file_snapshot(&file.metadata()?)?;
        if snapshot != input.snapshot {
            return Err(eyre!(
                "{label} descriptor changed while duplicating its pinned handle"
            ));
        }
    }
    Ok(PinnedInput {
        path: input.path.clone(),
        file,
        snapshot: input.snapshot.clone(),
    })
}

fn ensure_authorization_current(admitted: &AdmittedReset) -> Result<()> {
    revalidate_pinned(&admitted.ssh_identity, "OpenSSH identity")?;
    revalidate_pinned(&admitted.known_hosts, "OpenSSH known-hosts")?;
    verify_execution_authorization(
        &admitted.inventory,
        &admitted.inventory_sha256,
        &admitted.authorization,
        &admitted.trusted_key,
        now_unix_ms()?,
    )
    .wrap_err("public-reset authorization expired or drifted before mutation")
}

#[cfg(unix)]
fn validate_owner_private_dir(path: &Path, label: &str) -> Result<()> {
    validate_no_symlink_ancestors(path, label)?;
    let metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("failed to inspect {label} `{}`", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(eyre!("{label} must be a direct owner-only directory"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_private_dir(_path: &Path, _label: &str) -> Result<()> {
    Err(eyre!(
        "public Taira reset is supported only on Unix operator hosts"
    ))
}

#[cfg(unix)]
fn validate_no_symlink_ancestors(path: &Path, label: &str) -> Result<()> {
    validate_absolute_normal_path(path, label)?;
    let parent = path
        .parent()
        .ok_or_else(|| eyre!("{label} has no parent"))?;
    let current_uid = rustix::process::geteuid().as_raw();
    let mut cursor = PathBuf::new();
    for component in parent.components() {
        cursor.push(component.as_os_str());
        if cursor == Path::new("/") {
            continue;
        }
        let metadata = fs::symlink_metadata(&cursor).wrap_err_with(|| {
            format!("failed to inspect {label} ancestor `{}`", cursor.display())
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != current_uid)
            || metadata.mode() & 0o022 != 0
        {
            return Err(eyre!(
                "{label} ancestor `{}` has unsafe custody",
                cursor.display()
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_no_symlink_ancestors(_path: &Path, _label: &str) -> Result<()> {
    Err(eyre!(
        "public Taira reset is supported only on Unix operator hosts"
    ))
}

#[cfg(unix)]
fn validate_fixed_executable(path: &Path, label: &str) -> Result<()> {
    let (file, snapshot) = open_pinned_regular(path, label)?;
    if snapshot.uid != 0 || snapshot.mode & 0o022 != 0 || snapshot.mode & 0o111 == 0 {
        return Err(eyre!(
            "fixed {label} must be a direct root-owned non-writable executable"
        ));
    }
    ensure_pinned_unchanged(path, label, &file, &snapshot)
}

#[cfg(not(unix))]
fn validate_fixed_executable(_path: &Path, _label: &str) -> Result<()> {
    Err(eyre!(
        "public Taira reset is supported only on Unix operator hosts"
    ))
}

fn sha256_reader(file: &mut File, path: &Path) -> Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .wrap_err_with(|| format!("failed to hash artifact `{}`", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now_unix_ms() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("system clock is before the Unix epoch")?;
    u64::try_from(elapsed.as_millis()).wrap_err("current Unix time does not fit u64")
}

fn report(admitted: &AdmittedReset, command: &str, status: &str, detail: &str) -> Value {
    let mut object = Map::new();
    object.insert("schema".into(), Value::String(REPORT_SCHEMA_V1.to_owned()));
    object.insert(
        "qualification_scope".into(),
        Value::String(admitted.inventory.qualification_scope.as_str().to_owned()),
    );
    object.insert("command".into(), Value::String(command.to_owned()));
    object.insert("status".into(), Value::String(status.to_owned()));
    object.insert("detail".into(), Value::String(detail.to_owned()));
    object.insert(
        "deployment_id".into(),
        Value::String(admitted.inventory.deployment_id.clone()),
    );
    object.insert(
        "revision".into(),
        Value::String(admitted.inventory.revision.commit.clone()),
    );
    object.insert(
        "inventory_sha256".into(),
        Value::String(admitted.inventory_sha256.clone()),
    );
    object.insert(
        "authorization_sha256".into(),
        Value::String(admitted.authorization_sha256.clone()),
    );
    object.insert(
        "inventory_bytes".into(),
        Value::from(u64::try_from(admitted.inventory_bytes.len()).unwrap_or(u64::MAX)),
    );
    object.insert(
        "authorization_bytes".into(),
        Value::from(u64::try_from(admitted.authorization_bytes.len()).unwrap_or(u64::MAX)),
    );
    object.insert(
        "trusted_key_sha256".into(),
        Value::String(sha256_hex(&admitted.trusted_key_bytes)),
    );
    object.insert("validator_count".into(), Value::from(4_u64));
    object.insert("edge_count".into(), Value::from(1_u64));
    Value::Object(object)
}

mod executor_model {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
    #[norito(deny_unknown_fields)]
    pub(super) struct JournalV1 {
        schema: String,
        qualification_scope: QualificationScopeV1,
        deployment_id: String,
        inventory_sha256: String,
        authorization_sha256: String,
        authorization_nonce: String,
        status: String,
        phase: String,
        next_step: u16,
        #[norito(required)]
        recovery_intent: Option<RecoveryIntentV1>,
        touched_validators: Vec<String>,
        edge_touched: bool,
        edge_rollback_complete: bool,
        rollback_next_validator: u16,
        failure_summary: String,
        rollback_failures: Vec<String>,
    }

    pub(super) trait JournalStore {
        fn state(&self) -> &JournalV1;
        fn replace(&mut self, state: JournalV1) -> Result<()>;
        fn mark_deployment_proven(&mut self, state: JournalV1) -> Result<()>;
        fn finish(&mut self, state: JournalV1) -> Result<()>;
        fn finish_rollback(&mut self, state: JournalV1) -> Result<()>;
    }

    pub(super) enum JournalOpen {
        Fresh(JournalSeed),
        Resumable(DurableJournal),
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum ResumeDisposition {
        Forward,
        RecoveryPending,
        Sealing,
        Rollback,
        CleanupPending,
    }

    /// Exclusive journal lock whose release follows its owning admission.
    struct JournalLock {
        file: File,
    }

    impl Drop for JournalLock {
        fn drop(&mut self) {
            // Closing our descriptor alone can leave the lock held by an
            // unrelated child between fork and exec, before CLOEXEC takes effect.
            let _ = self.file.unlock();
        }
    }

    pub(super) struct JournalSeed {
        directory: PathBuf,
        current_path: PathBuf,
        receipt_path: PathBuf,
        deployment_receipt_path: PathBuf,
        aborted_receipt_path: PathBuf,
        rollback_receipt_path: PathBuf,
        _lock: JournalLock,
    }

    pub(super) struct DurableJournal {
        directory: PathBuf,
        current_path: PathBuf,
        receipt_path: PathBuf,
        deployment_receipt_path: PathBuf,
        aborted_receipt_path: PathBuf,
        rollback_receipt_path: PathBuf,
        state: JournalV1,
        _lock: JournalLock,
    }

    impl DurableJournal {
        #[cfg(test)]
        pub(super) fn open(directory: &Path, admitted: &AdmittedReset) -> Result<Self> {
            match Self::classify(directory, admitted)? {
                JournalOpen::Fresh(seed) => Self::initialize(seed, admitted),
                JournalOpen::Resumable(journal) => Ok(journal),
            }
        }

        pub(super) fn classify(directory: &Path, admitted: &AdmittedReset) -> Result<JournalOpen> {
            validate_owner_private_dir(directory, "public-reset journal directory")?;
            let lock_path = directory.join("public-reset.lock");
            let lock = open_private_rw(&lock_path)?;
            lock.try_lock()
                .wrap_err("another public-reset executor holds the journal lock")?;
            let lock = JournalLock { file: lock };

            let completed_dir = directory.join("completed");
            if !completed_dir.exists() {
                fs::create_dir(&completed_dir)
                    .wrap_err("failed to create completed-receipt directory")?;
                set_owner_only_dir(&completed_dir)?;
                sync_directory(directory)?;
            }
            validate_owner_private_dir(&completed_dir, "completed-receipt directory")?;
            let deployment_dir = directory.join("deployment-proven");
            if !deployment_dir.exists() {
                fs::create_dir(&deployment_dir)
                    .wrap_err("failed to create deployment-proven receipt directory")?;
                set_owner_only_dir(&deployment_dir)?;
                sync_directory(directory)?;
            }
            validate_owner_private_dir(&deployment_dir, "deployment-proven receipt directory")?;
            let aborted_dir = directory.join("aborted-before-mutation");
            if !aborted_dir.exists() {
                fs::create_dir(&aborted_dir)
                    .wrap_err("failed to create aborted-before-mutation receipt directory")?;
                set_owner_only_dir(&aborted_dir)?;
                sync_directory(directory)?;
            }
            validate_owner_private_dir(&aborted_dir, "aborted-before-mutation receipt directory")?;
            let rolled_back_dir = directory.join("rolled-back");
            if !rolled_back_dir.exists() {
                fs::create_dir(&rolled_back_dir)
                    .wrap_err("failed to create rolled-back receipt directory")?;
                set_owner_only_dir(&rolled_back_dir)?;
                sync_directory(directory)?;
            }
            validate_owner_private_dir(&rolled_back_dir, "rolled-back receipt directory")?;
            let receipt_path =
                completed_dir.join(format!("{}.json", admitted.authorization_sha256));
            let deployment_receipt_path =
                deployment_dir.join(format!("{}.json", admitted.authorization_sha256));
            let aborted_receipt_path =
                aborted_dir.join(format!("{}.json", admitted.authorization_sha256));
            let rollback_receipt_path =
                rolled_back_dir.join(format!("{}.json", admitted.authorization_sha256));
            if receipt_path.exists() {
                reconcile_completed_journal(directory, admitted, &receipt_path)?;
                return Err(eyre!(
                    "authorization replay rejected: completed receipt already exists"
                ));
            }
            if aborted_receipt_path.exists() {
                reconcile_aborted_journal(directory, admitted, &aborted_receipt_path)?;
                return Err(eyre!(
                    "authorization replay rejected: reset was aborted before mutation"
                ));
            }
            if rollback_receipt_path.exists() {
                reconcile_rolled_back_journal(directory, admitted, &rollback_receipt_path)?;
                return Err(eyre!(
                    "authorization replay rejected: rolled-back receipt already exists"
                ));
            }
            let current_path =
                directory.join(format!("{}.journal.json", admitted.inventory.deployment_id));
            let expected = initial_journal(admitted);
            reconcile_journal_staging(directory, &current_path, &expected)?;
            let state = if current_path.exists() {
                let (state, _) = read_json::<JournalV1>(&current_path, "public-reset journal")?;
                validate_resumable_journal(&state, &expected)?;
                if state.status == "finishing" {
                    recover_deployment_receipt(&deployment_receipt_path, &state)?;
                    recover_finishing_receipt(directory, &current_path, &receipt_path, &state)?;
                    return Err(eyre!(
                        "previous public-reset completed; its immutable receipt was recovered"
                    ));
                }
                if state.status == "rolled_back" {
                    recover_rolled_back_receipt(
                        directory,
                        &current_path,
                        &rollback_receipt_path,
                        &state,
                    )?;
                    return Err(eyre!(
                        "previous public-reset rolled back; its immutable receipt was recovered"
                    ));
                }
                if state.status == "aborted_before_mutation" {
                    recover_aborted_receipt(
                        directory,
                        &current_path,
                        &aborted_receipt_path,
                        &state,
                    )?;
                    return Err(eyre!(
                        "previous untouched public reset was durably aborted; its immutable receipt was recovered"
                    ));
                }
                if matches!(state.status.as_str(), "sealing" | "cleanup_pending") {
                    recover_deployment_receipt(&deployment_receipt_path, &state)?;
                }
                state
            } else {
                return Ok(JournalOpen::Fresh(JournalSeed {
                    directory: directory.to_path_buf(),
                    current_path,
                    receipt_path,
                    deployment_receipt_path,
                    aborted_receipt_path,
                    rollback_receipt_path,
                    _lock: lock,
                }));
            };
            Ok(JournalOpen::Resumable(Self {
                directory: directory.to_path_buf(),
                current_path,
                receipt_path,
                deployment_receipt_path,
                aborted_receipt_path,
                rollback_receipt_path,
                state,
                _lock: lock,
            }))
        }

        pub(super) fn initialize(seed: JournalSeed, admitted: &AdmittedReset) -> Result<Self> {
            let expected = initial_journal(admitted);
            if seed.current_path.exists() {
                return Err(eyre!(
                    "public-reset journal appeared while its exclusive lock was held"
                ));
            }
            publish_json(&seed.directory, &seed.current_path, &expected)?;
            Ok(Self {
                directory: seed.directory,
                current_path: seed.current_path,
                receipt_path: seed.receipt_path,
                deployment_receipt_path: seed.deployment_receipt_path,
                aborted_receipt_path: seed.aborted_receipt_path,
                rollback_receipt_path: seed.rollback_receipt_path,
                state: expected,
                _lock: seed._lock,
            })
        }

        pub(super) fn resume_disposition(&self) -> ResumeDisposition {
            match self.state.status.as_str() {
                "in_progress" => ResumeDisposition::Forward,
                "recovery_pending" => ResumeDisposition::RecoveryPending,
                "sealing" => ResumeDisposition::Sealing,
                "rolling_back" => ResumeDisposition::Rollback,
                "cleanup_pending" => ResumeDisposition::CleanupPending,
                status => unreachable!("validated journal has non-resumable status `{status}`"),
            }
        }

        pub(super) fn pending_recovery_step(&self) -> Result<ExecutionStep> {
            if self.state.status != "recovery_pending" {
                return Err(eyre!("journal is not at a recovery-pending boundary"));
            }
            execution_steps(self.state.qualification_scope)
                .get(usize::from(self.state.next_step))
                .copied()
                .filter(|step| step.supports_recovery())
                .ok_or_else(|| eyre!("journal recovery step is outside the closed V1 plan"))
        }

        pub(super) fn has_touched_hosts(&self) -> bool {
            !self.state.touched_validators.is_empty() || self.state.edge_touched
        }

        pub(super) fn abort_before_mutation(&mut self) -> Result<()> {
            if self.has_touched_hosts()
                || self.state.status != "in_progress"
                || self.state.recovery_intent.is_some()
            {
                return Err(eyre!(
                    "only an untouched in-progress reset can be aborted locally"
                ));
            }
            let mut state = self.state.clone();
            state.status = "aborted_before_mutation".to_owned();
            state.phase = "aborted_before_mutation".to_owned();
            publish_json(&self.directory, &self.current_path, &state)?;
            recover_aborted_receipt(
                &self.directory,
                &self.current_path,
                &self.aborted_receipt_path,
                &state,
            )?;
            self.state = state;
            Ok(())
        }
    }

    include!("taira_public_reset_abandon.rs");

    impl JournalStore for DurableJournal {
        fn state(&self) -> &JournalV1 {
            &self.state
        }

        fn replace(&mut self, state: JournalV1) -> Result<()> {
            publish_json(&self.directory, &self.current_path, &state)?;
            self.state = state;
            Ok(())
        }

        fn mark_deployment_proven(&mut self, state: JournalV1) -> Result<()> {
            if state.status != "sealing"
                || state.phase != "seal"
                || usize::from(state.next_step)
                    != execution_steps(state.qualification_scope).len() - 2
            {
                return Err(eyre!(
                    "deployment proof is not at the exact sealing boundary"
                ));
            }
            publish_json(&self.directory, &self.current_path, &state)?;
            recover_deployment_receipt(&self.deployment_receipt_path, &state)?;
            self.state = state;
            Ok(())
        }

        fn finish(&mut self, mut state: JournalV1) -> Result<()> {
            state.status = "finishing".to_owned();
            state.phase = "finishing".to_owned();
            recover_deployment_receipt(&self.deployment_receipt_path, &state)?;
            publish_json(&self.directory, &self.current_path, &state)?;
            recover_finishing_receipt(
                &self.directory,
                &self.current_path,
                &self.receipt_path,
                &state,
            )?;
            state.status = "completed".to_owned();
            state.phase = "completed".to_owned();
            sync_directory(self.receipt_path.parent().expect("receipt has parent"))?;
            sync_directory(&self.directory)?;
            self.state = state;
            Ok(())
        }

        fn finish_rollback(&mut self, mut state: JournalV1) -> Result<()> {
            state.status = "rolled_back".to_owned();
            state.phase = "rolled_back".to_owned();
            publish_json(&self.directory, &self.current_path, &state)?;
            recover_rolled_back_receipt(
                &self.directory,
                &self.current_path,
                &self.rollback_receipt_path,
                &state,
            )?;
            sync_directory(
                self.rollback_receipt_path
                    .parent()
                    .expect("rollback receipt has parent"),
            )?;
            sync_directory(&self.directory)?;
            self.state = state;
            Ok(())
        }
    }

    fn initial_journal(admitted: &AdmittedReset) -> JournalV1 {
        JournalV1 {
            schema: JOURNAL_SCHEMA_V1.to_owned(),
            qualification_scope: admitted.inventory.qualification_scope,
            deployment_id: admitted.inventory.deployment_id.clone(),
            inventory_sha256: admitted.inventory_sha256.clone(),
            authorization_sha256: admitted.authorization_sha256.clone(),
            authorization_nonce: admitted.inventory.authorization_nonce.clone(),
            status: "in_progress".to_owned(),
            phase: "admitted".to_owned(),
            next_step: 0,
            recovery_intent: None,
            touched_validators: Vec::new(),
            edge_touched: false,
            edge_rollback_complete: false,
            rollback_next_validator: 0,
            failure_summary: String::new(),
            rollback_failures: Vec::new(),
        }
    }

    fn validate_resumable_journal(actual: &JournalV1, expected: &JournalV1) -> Result<()> {
        if actual.schema != JOURNAL_SCHEMA_V1
            || actual.qualification_scope != expected.qualification_scope
            || actual.deployment_id != expected.deployment_id
            || actual.inventory_sha256 != expected.inventory_sha256
            || actual.authorization_sha256 != expected.authorization_sha256
            || actual.authorization_nonce != expected.authorization_nonce
            || !matches!(
                actual.status.as_str(),
                "in_progress"
                    | "recovery_pending"
                    | "sealing"
                    | "cleanup_pending"
                    | "aborted_before_mutation"
                    | "rolling_back"
                    | "finishing"
                    | "rolled_back"
            )
            || usize::from(actual.next_step) > execution_steps(actual.qualification_scope).len()
            || usize::from(actual.rollback_next_validator) > actual.touched_validators.len()
            || actual.failure_summary.len() > 512
            || actual.rollback_failures.len() > 5
            || actual
                .rollback_failures
                .iter()
                .any(|value| value.len() > 512)
        {
            return Err(eyre!(
                "existing journal is not an exact resumable execution of this authorization"
            ));
        }
        let canonical_prefix = VALIDATOR_SLUGS
            .iter()
            .take(actual.touched_validators.len())
            .copied()
            .collect::<Vec<_>>();
        let edge_stage_index = execution_steps(actual.qualification_scope)
            .iter()
            .position(|step| *step == ExecutionStep::EdgeStage)
            .expect("the canonical plan contains edge staging");
        if matches!(actual.status.as_str(), "in_progress" | "recovery_pending")
            && ((usize::from(actual.next_step) < edge_stage_index && actual.edge_touched)
                || (usize::from(actual.next_step) > edge_stage_index && !actual.edge_touched))
        {
            return Err(eyre!(
                "journal edge custody differs from the candidate qualification frontier"
            ));
        }
        let valid_recovery = if actual.status == "recovery_pending" {
            execution_steps(actual.qualification_scope)
                .get(usize::from(actual.next_step))
                .copied()
                .filter(|step| step.supports_recovery())
                .is_some_and(|step| {
                    actual.phase == step.label()
                        && actual
                            .recovery_intent
                            .as_ref()
                            .is_some_and(|intent| validate_recovery_intent(intent, step).is_ok())
                })
        } else {
            true
        };
        if actual
            .touched_validators
            .iter()
            .map(String::as_str)
            .ne(canonical_prefix)
            || (actual.edge_rollback_complete && !actual.edge_touched)
            || (actual.status == "in_progress"
                && (!valid_in_progress_phase(actual)
                    || actual.recovery_intent.as_ref().is_some_and(|intent| {
                        !execution_steps(actual.qualification_scope)
                            .get(usize::from(actual.next_step))
                            .copied()
                            .is_some_and(|step| {
                                step.supports_recovery()
                                    && recovery_has_forward_frontier(intent, step)
                            })
                    })
                    || actual.edge_rollback_complete
                    || actual.rollback_next_validator != 0
                    || !actual.failure_summary.is_empty()
                    || !actual.rollback_failures.is_empty()))
            || (actual.status == "recovery_pending"
                && (!valid_recovery
                    || actual.edge_rollback_complete
                    || actual.rollback_next_validator != 0
                    || !actual.rollback_failures.is_empty()))
            || (actual.status == "sealing"
                && (actual.phase != "seal"
                    || usize::from(actual.next_step)
                        != execution_steps(actual.qualification_scope).len() - 2
                    || actual.recovery_intent.is_some()
                    || actual.edge_rollback_complete
                    || actual.rollback_next_validator != 0
                    || !actual.rollback_failures.is_empty()))
            || (actual.status == "rolling_back"
                && (actual.phase != "rollback"
                    || actual.recovery_intent.is_some()
                    || actual.failure_summary.is_empty()))
            || (actual.status == "cleanup_pending"
                && (actual.phase != "cleanup_pending"
                    || usize::from(actual.next_step)
                        != execution_steps(actual.qualification_scope).len() - 1
                    || actual.recovery_intent.is_some()
                    || actual.edge_rollback_complete
                    || actual.rollback_next_validator != 0
                    || !actual.rollback_failures.is_empty()))
            || (actual.status == "aborted_before_mutation"
                && (actual.phase != "aborted_before_mutation"
                    || usize::from(actual.next_step) > 1
                    || actual.recovery_intent.is_some()
                    || !actual.touched_validators.is_empty()
                    || actual.edge_touched
                    || actual.edge_rollback_complete
                    || actual.rollback_next_validator != 0
                    || !actual.failure_summary.is_empty()
                    || !actual.rollback_failures.is_empty()))
            || (actual.status == "rolled_back"
                && (actual.phase != "rolled_back"
                    || actual.recovery_intent.is_some()
                    || usize::from(actual.rollback_next_validator)
                        != actual.touched_validators.len()
                    || (actual.edge_touched && !actual.edge_rollback_complete)))
            || (actual.status == "finishing"
                && (usize::from(actual.next_step)
                    != execution_steps(actual.qualification_scope).len()
                    || actual.phase != "finishing"
                    || actual.recovery_intent.is_some()
                    || actual.edge_rollback_complete
                    || actual.rollback_next_validator != 0
                    || !actual.failure_summary.is_empty()
                    || !actual.rollback_failures.is_empty()))
        {
            return Err(eyre!("existing journal progress invariants are invalid"));
        }
        Ok(())
    }

    fn valid_in_progress_phase(state: &JournalV1) -> bool {
        let next = usize::from(state.next_step);
        if next >= execution_steps(state.qualification_scope).len() - 2 {
            return false;
        }
        (next == 0 && state.phase == "admitted")
            || execution_steps(state.qualification_scope)
                .get(next)
                .is_some_and(|step| state.phase == step.label())
    }

    fn reconcile_journal_staging(
        directory: &Path,
        current: &Path,
        expected: &JournalV1,
    ) -> Result<()> {
        let name = current
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| eyre!("journal path has no UTF-8 name"))?;
        let staging = directory.join(format!(".{name}.next"));
        if !staging.exists() {
            return Ok(());
        }
        let (successor, _) = match read_json::<JournalV1>(&staging, "staged journal successor") {
            Ok(staged) => staged,
            Err(parse_error) => {
                let (file, snapshot) = open_pinned_regular(&staging, "partial journal staging")?;
                require_owner_private_snapshot(&snapshot, "partial journal staging")?;
                let bytes = read_pinned_bytes(
                    &staging,
                    "partial journal staging",
                    file,
                    &snapshot,
                    MAX_JSON_BYTES,
                )?;
                if bytes.ends_with(b"\n") {
                    return Err(parse_error
                        .wrap_err("complete journal staging is invalid and cannot be discarded"));
                }
                let parent = File::open(directory)?;
                rustix::fs::unlinkat(
                    &parent,
                    staging.file_name().expect("staging name"),
                    rustix::fs::AtFlags::empty(),
                )
                .wrap_err("failed to discard provably partial journal staging")?;
                parent
                    .sync_all()
                    .wrap_err("failed to fsync partial journal staging removal")?;
                return Ok(());
            }
        };
        let (staged_file, staged_snapshot) =
            open_pinned_regular(&staging, "complete journal staging")?;
        require_owner_private_snapshot(&staged_snapshot, "complete journal staging")?;
        staged_file
            .sync_all()
            .wrap_err("failed to fsync recovered complete journal staging")?;
        validate_resumable_journal(&successor, expected)?;
        if current.exists() {
            let (predecessor, _) = read_json::<JournalV1>(current, "journal predecessor")?;
            validate_resumable_journal(&predecessor, expected)?;
            if !valid_journal_successor(&predecessor, &successor) {
                return Err(eyre!(
                    "staged journal is not a monotonic successor of the durable journal"
                ));
            }
        } else if successor != *expected {
            return Err(eyre!(
                "orphaned staged journal is not the exact initial journal"
            ));
        }
        let parent = File::open(directory)?;
        rustix::fs::renameat_with(
            &parent,
            staging.file_name().expect("staging name"),
            &parent,
            current.file_name().expect("journal name"),
            rustix::fs::RenameFlags::empty(),
        )?;
        parent.sync_all()?;
        Ok(())
    }

    fn valid_journal_successor(before: &JournalV1, after: &JournalV1) -> bool {
        before.schema == after.schema
            && before.qualification_scope == after.qualification_scope
            && before.deployment_id == after.deployment_id
            && before.inventory_sha256 == after.inventory_sha256
            && before.authorization_sha256 == after.authorization_sha256
            && before.authorization_nonce == after.authorization_nonce
            && after.next_step >= before.next_step
            && after.next_step <= before.next_step.saturating_add(1)
            && after
                .touched_validators
                .starts_with(&before.touched_validators)
            && after.touched_validators.len() <= before.touched_validators.len() + 1
            && (!before.edge_touched || after.edge_touched)
            && (!before.edge_rollback_complete || after.edge_rollback_complete)
            && after.rollback_next_validator >= before.rollback_next_validator
            && after.rollback_next_validator <= before.rollback_next_validator.saturating_add(1)
            && after
                .rollback_failures
                .starts_with(&before.rollback_failures)
            && valid_recovery_intent_transition(before, after)
            && valid_status_transition(before, after)
    }

    fn valid_recovery_intent_transition(before: &JournalV1, after: &JournalV1) -> bool {
        match (before.status.as_str(), after.status.as_str()) {
            ("in_progress", "recovery_pending") => {
                after.recovery_intent.is_some()
                    && (before.recovery_intent.is_none()
                        || before.recovery_intent == after.recovery_intent)
                    && after.next_step == before.next_step
            }
            ("recovery_pending", "recovery_pending") => {
                before
                    .recovery_intent
                    .as_ref()
                    .zip(after.recovery_intent.as_ref())
                    .is_some_and(|(before, after)| valid_recovery_progress(before, after))
                    && after.next_step == before.next_step
            }
            ("recovery_pending", "in_progress") if after.recovery_intent.is_some() => {
                before.recovery_intent == after.recovery_intent
                    && after.next_step == before.next_step
                    && execution_steps(after.qualification_scope)
                        .get(usize::from(after.next_step))
                        .copied()
                        .zip(after.recovery_intent.as_ref())
                        .is_some_and(|(step, intent)| recovery_has_forward_frontier(intent, step))
            }
            ("in_progress", "in_progress") => before.recovery_intent == after.recovery_intent,
            ("in_progress", "rolling_back") => after.recovery_intent.is_none(),
            ("recovery_pending", "in_progress" | "sealing" | "rolling_back") => {
                before.recovery_intent.is_some() && after.recovery_intent.is_none()
            }
            _ => before.recovery_intent.is_none() && after.recovery_intent.is_none(),
        }
    }

    fn valid_recovery_progress(before: &RecoveryIntentV1, after: &RecoveryIntentV1) -> bool {
        if before == after {
            return true;
        }
        if before.schema != after.schema
            || before.step_label != after.step_label
            || before.mutations.len() != after.mutations.len()
        {
            return false;
        }
        let changed = before
            .mutations
            .iter()
            .zip(&after.mutations)
            .enumerate()
            .filter(|(_, (before, after))| before != after)
            .collect::<Vec<_>>();
        if changed.len() != 1 {
            return false;
        }
        let (index, (before_mutation, after_mutation)) = changed[0];
        let same_identity = before_mutation.kind == after_mutation.kind
            && before_mutation.phase == after_mutation.phase
            && before_mutation.idempotency_key == after_mutation.idempotency_key
            && before_mutation.receipt_name == after_mutation.receipt_name;
        if !same_identity || index != usize::from(before.next_mutation) {
            return false;
        }
        match (before_mutation.state, after_mutation.state) {
            (RecoveryMutationStateV1::Prepared, RecoveryMutationStateV1::Submitted) => {
                after.next_mutation == before.next_mutation
            }
            (RecoveryMutationStateV1::Submitted, RecoveryMutationStateV1::Applied) => {
                after.next_mutation == before.next_mutation.saturating_add(1)
            }
            _ => false,
        }
    }

    fn valid_status_transition(before: &JournalV1, after: &JournalV1) -> bool {
        if before.status == after.status {
            return true;
        }
        matches!(
            (before.status.as_str(), after.status.as_str()),
            (
                "in_progress",
                "recovery_pending" | "sealing" | "rolling_back" | "aborted_before_mutation"
            ) | (
                "recovery_pending",
                "in_progress" | "sealing" | "rolling_back"
            ) | ("sealing", "cleanup_pending")
                | ("cleanup_pending", "finishing")
                | ("rolling_back", "rolled_back")
        )
    }

    #[cfg(unix)]
    fn open_private_rw(path: &Path) -> Result<File> {
        let file = File::from(
            rustix::fs::open(
                path,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .wrap_err_with(|| {
                format!("failed to securely open private file `{}`", path.display())
            })?,
        );
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(eyre!(
                "private file `{}` has unsafe custody",
                path.display()
            ));
        }
        Ok(file)
    }

    #[cfg(not(unix))]
    fn open_private_rw(_path: &Path) -> Result<File> {
        Err(eyre!(
            "public Taira reset is supported only on Unix operator hosts"
        ))
    }

    #[cfg(unix)]
    fn create_private_new(path: &Path) -> Result<File> {
        Ok(File::from(
            rustix::fs::open(
                path,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .wrap_err_with(|| {
                format!("failed to create private staging file `{}`", path.display())
            })?,
        ))
    }

    #[cfg(not(unix))]
    fn create_private_new(_path: &Path) -> Result<File> {
        Err(eyre!(
            "public Taira reset is supported only on Unix operator hosts"
        ))
    }

    #[cfg(unix)]
    fn set_owner_only_dir(path: &Path) -> Result<()> {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .wrap_err_with(|| format!("failed to set owner-only mode on `{}`", path.display()))
    }

    #[cfg(not(unix))]
    fn set_owner_only_dir(_path: &Path) -> Result<()> {
        Err(eyre!(
            "public Taira reset is supported only on Unix operator hosts"
        ))
    }

    fn publish_json<T: JsonSerialize>(
        directory: &Path,
        destination: &Path,
        value: &T,
    ) -> Result<()> {
        let file_name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| eyre!("journal destination has no UTF-8 file name"))?;
        let staging = directory.join(format!(".{file_name}.next"));
        let rendered = json::to_json(value).wrap_err("failed to encode journal Norito JSON")?;
        let mut expected = rendered.into_bytes();
        expected.push(b'\n');
        match create_private_new(&staging) {
            Ok(mut file) => {
                file.write_all(&expected)
                    .wrap_err("failed to write journal staging file")?;
                file.sync_all()
                    .wrap_err("failed to fsync journal staging file")?;
            }
            Err(error) if staging.exists() => {
                let (file, snapshot) = open_pinned_regular(&staging, "stale journal staging")?;
                require_owner_private_snapshot(&snapshot, "stale journal staging")?;
                let actual = read_pinned_bytes(
                    &staging,
                    "stale journal staging",
                    file,
                    &snapshot,
                    MAX_JSON_BYTES,
                )?;
                if actual != expected {
                    return Err(error.wrap_err(
                        "stale journal staging does not match the exact idempotent retry",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
        let parent = File::open(directory).wrap_err("failed to open journal directory")?;
        rustix::fs::renameat_with(
            &parent,
            staging.file_name().expect("journal staging has name"),
            &parent,
            destination
                .file_name()
                .expect("journal destination has name"),
            rustix::fs::RenameFlags::empty(),
        )
        .wrap_err("failed to atomically replace journal through its directory descriptor")?;
        sync_directory(directory)
    }

    fn recover_finishing_receipt(
        directory: &Path,
        current: &Path,
        receipt: &Path,
        finishing: &JournalV1,
    ) -> Result<()> {
        if finishing.status != "finishing"
            || finishing.phase != "finishing"
            || usize::from(finishing.next_step)
                != execution_steps(finishing.qualification_scope).len()
        {
            return Err(eyre!("journal is not at the exact finishing boundary"));
        }
        let mut completed = finishing.clone();
        completed.status = "completed".to_owned();
        completed.phase = "completed".to_owned();
        publish_json_no_replace(receipt, &completed)?;
        if current.exists() {
            let (actual, _) = read_json::<JournalV1>(current, "finishing journal")?;
            if actual.status != "finishing"
                || actual.authorization_sha256 != finishing.authorization_sha256
                || actual.inventory_sha256 != finishing.inventory_sha256
            {
                return Err(eyre!("finishing journal drifted before receipt cleanup"));
            }
            let parent = File::open(directory)?;
            rustix::fs::unlinkat(
                &parent,
                current
                    .file_name()
                    .ok_or_else(|| eyre!("journal has no file name"))?,
                rustix::fs::AtFlags::empty(),
            )?;
            parent.sync_all()?;
        }
        Ok(())
    }

    fn recover_deployment_receipt(receipt: &Path, state: &JournalV1) -> Result<()> {
        let mut proven = state.clone();
        let valid_boundary = match state.status.as_str() {
            "sealing" => {
                state.phase == "seal"
                    && usize::from(state.next_step)
                        == execution_steps(state.qualification_scope).len() - 2
            }
            "cleanup_pending" => {
                state.phase == "cleanup_pending"
                    && usize::from(state.next_step)
                        == execution_steps(state.qualification_scope).len() - 1
            }
            "finishing" => {
                state.phase == "finishing"
                    && usize::from(state.next_step)
                        == execution_steps(state.qualification_scope).len()
            }
            "completed" => {
                state.phase == "completed"
                    && usize::from(state.next_step)
                        == execution_steps(state.qualification_scope).len()
            }
            _ => false,
        };
        if !valid_boundary
            || state.edge_rollback_complete
            || state.rollback_next_validator != 0
            || !state.rollback_failures.is_empty()
        {
            return Err(eyre!(
                "journal is not at the exact immutable deployment-proven boundary"
            ));
        }
        proven.status = "sealing".to_owned();
        proven.phase = "seal".to_owned();
        proven.next_step = u16::try_from(execution_steps(state.qualification_scope).len() - 2)
            .expect("bounded execution plan");
        proven.failure_summary.clear();
        if state.status == "sealing" {
            publish_json_no_replace(receipt, &proven)
        } else {
            if !receipt.exists() {
                return Err(eyre!(
                    "immutable deployment-proven receipt is missing after host sealing began"
                ));
            }
            let (actual, _) = read_json::<JournalV1>(receipt, "deployment-proven receipt")?;
            if actual != proven {
                return Err(eyre!(
                    "immutable deployment-proven receipt conflicts with terminal progress"
                ));
            }
            Ok(())
        }
    }

    fn recover_rolled_back_receipt(
        directory: &Path,
        current: &Path,
        receipt: &Path,
        rolled_back: &JournalV1,
    ) -> Result<()> {
        if rolled_back.status != "rolled_back"
            || rolled_back.phase != "rolled_back"
            || usize::from(rolled_back.rollback_next_validator)
                != rolled_back.touched_validators.len()
            || (rolled_back.edge_touched && !rolled_back.edge_rollback_complete)
        {
            return Err(eyre!("journal is not at the exact rolled-back boundary"));
        }
        publish_json_no_replace(receipt, rolled_back)?;
        remove_matching_current(directory, current, rolled_back, "rolled_back")
    }

    fn recover_aborted_receipt(
        directory: &Path,
        current: &Path,
        receipt: &Path,
        aborted: &JournalV1,
    ) -> Result<()> {
        if aborted.status != "aborted_before_mutation"
            || aborted.phase != "aborted_before_mutation"
            || usize::from(aborted.next_step) > 1
            || aborted.recovery_intent.is_some()
            || !aborted.touched_validators.is_empty()
            || aborted.edge_touched
            || aborted.edge_rollback_complete
            || aborted.rollback_next_validator != 0
            || !aborted.failure_summary.is_empty()
            || !aborted.rollback_failures.is_empty()
        {
            return Err(eyre!(
                "journal is not at the exact aborted-before-mutation boundary"
            ));
        }
        publish_json_no_replace(receipt, aborted)?;
        remove_matching_current(directory, current, aborted, "aborted_before_mutation")
    }

    fn remove_matching_current(
        directory: &Path,
        current: &Path,
        expected: &JournalV1,
        status: &str,
    ) -> Result<()> {
        if !current.exists() {
            return Ok(());
        }
        let (actual, _) = read_json::<JournalV1>(current, "terminal reset journal")?;
        if actual.status != status || actual != *expected {
            return Err(eyre!("terminal journal drifted before receipt cleanup"));
        }
        let parent = File::open(directory)?;
        rustix::fs::unlinkat(
            &parent,
            current
                .file_name()
                .ok_or_else(|| eyre!("journal has no file name"))?,
            rustix::fs::AtFlags::empty(),
        )?;
        parent.sync_all()?;
        Ok(())
    }

    fn publish_json_no_replace<T: JsonSerialize>(destination: &Path, value: &T) -> Result<()> {
        let directory = destination
            .parent()
            .ok_or_else(|| eyre!("receipt destination has no parent"))?;
        let name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| eyre!("receipt destination has no UTF-8 name"))?;
        let mut bytes = json::to_json(value)?.into_bytes();
        bytes.push(b'\n');
        let staging = directory.join(format!(".{name}.next"));
        let parent = File::open(directory)?;
        match create_private_new(&staging) {
            Ok(mut file) => {
                file.write_all(&bytes)?;
                file.sync_all()?;
            }
            Err(create_error) if staging.exists() => {
                let (file, snapshot) = open_pinned_regular(&staging, "stale receipt staging")?;
                require_owner_private_snapshot(&snapshot, "stale receipt staging")?;
                let actual = read_pinned_bytes(
                    &staging,
                    "stale receipt staging",
                    file.try_clone()?,
                    &snapshot,
                    MAX_JSON_BYTES,
                )?;
                if actual == bytes {
                    file.sync_all()
                        .wrap_err("failed to fsync recovered complete receipt staging")?;
                } else if actual.len() < bytes.len() && bytes.starts_with(&actual) {
                    drop(file);
                    rustix::fs::unlinkat(
                        &parent,
                        staging.file_name().expect("staging name"),
                        rustix::fs::AtFlags::empty(),
                    )
                    .wrap_err("failed to remove provably partial receipt staging")?;
                    parent
                        .sync_all()
                        .wrap_err("failed to fsync partial receipt staging removal")?;
                    let mut file = create_private_new(&staging)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                } else {
                    return Err(create_error.wrap_err(
                        "stale receipt staging conflicts with the exact terminal journal",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
        match rustix::fs::renameat_with(
            &parent,
            staging.file_name().expect("staging name"),
            &parent,
            destination.file_name().expect("receipt name"),
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => parent
                .sync_all()
                .wrap_err("failed to fsync completed receipt"),
            Err(rustix::io::Errno::EXIST) => {
                let (file, snapshot) = open_pinned_regular(destination, "completed receipt")?;
                require_owner_private_snapshot(&snapshot, "completed receipt")?;
                let actual = read_pinned_bytes(
                    destination,
                    "completed receipt",
                    file,
                    &snapshot,
                    MAX_JSON_BYTES,
                )?;
                if actual != bytes {
                    return Err(eyre!(
                        "completed receipt already exists with different bytes"
                    ));
                }
                rustix::fs::unlinkat(
                    &parent,
                    staging.file_name().expect("staging name"),
                    rustix::fs::AtFlags::empty(),
                )?;
                parent
                    .sync_all()
                    .wrap_err("failed to fsync recovered receipt")
            }
            Err(error) => Err(error.into()),
        }
    }

    fn reconcile_completed_journal(
        directory: &Path,
        admitted: &AdmittedReset,
        receipt: &Path,
    ) -> Result<()> {
        let (completed, _) = read_json::<JournalV1>(receipt, "completed reset receipt")?;
        let expected = initial_journal(admitted);
        if completed.schema != JOURNAL_SCHEMA_V1
            || completed.qualification_scope != expected.qualification_scope
            || completed.status != "completed"
            || completed.phase != "completed"
            || completed.inventory_sha256 != expected.inventory_sha256
            || completed.authorization_sha256 != expected.authorization_sha256
            || usize::from(completed.next_step)
                != execution_steps(completed.qualification_scope).len()
        {
            return Err(eyre!(
                "completed receipt is not this exact finished execution"
            ));
        }
        let deployment_receipt = directory
            .join("deployment-proven")
            .join(format!("{}.json", admitted.authorization_sha256));
        recover_deployment_receipt(&deployment_receipt, &completed)?;
        let current = directory.join(format!("{}.journal.json", admitted.inventory.deployment_id));
        if current.exists() {
            let (state, _) = read_json::<JournalV1>(&current, "stale finishing journal")?;
            let mut expected_completed = state.clone();
            expected_completed.status = "completed".to_owned();
            expected_completed.phase = "completed".to_owned();
            if state.status != "finishing" || completed != expected_completed {
                return Err(eyre!("completed receipt conflicts with active journal"));
            }
            let parent = File::open(directory)?;
            rustix::fs::unlinkat(
                &parent,
                current.file_name().expect("journal name"),
                rustix::fs::AtFlags::empty(),
            )?;
            parent.sync_all()?;
        }
        Ok(())
    }

    fn reconcile_rolled_back_journal(
        directory: &Path,
        admitted: &AdmittedReset,
        receipt: &Path,
    ) -> Result<()> {
        let (rolled_back, _) = read_json::<JournalV1>(receipt, "rolled-back reset receipt")?;
        let expected = initial_journal(admitted);
        validate_resumable_journal(&rolled_back, &expected)?;
        if rolled_back.status != "rolled_back" || rolled_back.phase != "rolled_back" {
            return Err(eyre!(
                "rolled-back receipt is not this exact terminal execution"
            ));
        }
        let current = directory.join(format!("{}.journal.json", admitted.inventory.deployment_id));
        remove_matching_current(directory, &current, &rolled_back, "rolled_back")
    }

    fn reconcile_aborted_journal(
        directory: &Path,
        admitted: &AdmittedReset,
        receipt: &Path,
    ) -> Result<()> {
        let (aborted, _) = read_json::<JournalV1>(receipt, "aborted reset receipt")?;
        let expected = initial_journal(admitted);
        validate_resumable_journal(&aborted, &expected)?;
        recover_aborted_receipt(
            directory,
            &directory.join(format!("{}.journal.json", admitted.inventory.deployment_id)),
            receipt,
            &aborted,
        )
    }

    fn sync_directory(path: &Path) -> Result<()> {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .wrap_err_with(|| format!("failed to fsync directory `{}`", path.display()))
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum ExecutionStep {
        Preflight,
        Stage,
        Stop,
        Install,
        Reset,
        Preseed,
        Start,
        Convergence,
        Canary,
        RestartProof,
        EdgeStage,
        EdgeCutover,
        EdgeVerify,
        Seal,
        Cleanup,
    }

    // Deployment schedules required bootstrap and live readiness, without
    // automatically injecting diagnostic canaries or validator restart proofs.
    const FULL_INROU_EXECUTION_STEPS: [ExecutionStep; 14] = [
        ExecutionStep::Preflight,
        ExecutionStep::Stage,
        ExecutionStep::Stop,
        ExecutionStep::Install,
        ExecutionStep::Reset,
        ExecutionStep::Preseed,
        ExecutionStep::Start,
        ExecutionStep::Canary,
        ExecutionStep::Convergence,
        ExecutionStep::EdgeStage,
        ExecutionStep::EdgeCutover,
        ExecutionStep::EdgeVerify,
        ExecutionStep::Seal,
        ExecutionStep::Cleanup,
    ];

    const CORE_TESTNET_EXECUTION_STEPS: [ExecutionStep; 13] = [
        ExecutionStep::Preflight,
        ExecutionStep::Stage,
        ExecutionStep::Stop,
        ExecutionStep::Install,
        ExecutionStep::Reset,
        ExecutionStep::Start,
        ExecutionStep::Canary,
        ExecutionStep::Convergence,
        ExecutionStep::EdgeStage,
        ExecutionStep::EdgeCutover,
        ExecutionStep::EdgeVerify,
        ExecutionStep::Seal,
        ExecutionStep::Cleanup,
    ];

    fn execution_steps(scope: QualificationScopeV1) -> &'static [ExecutionStep] {
        match scope {
            QualificationScopeV1::CoreTestnet => &CORE_TESTNET_EXECUTION_STEPS,
            QualificationScopeV1::FullInrou => &FULL_INROU_EXECUTION_STEPS,
        }
    }

    impl ExecutionStep {
        pub(super) const fn label(self) -> &'static str {
            match self {
                Self::Preflight => "preflight",
                Self::Stage => "stage",
                Self::Stop => "stop",
                Self::Install => "install",
                Self::Reset => "reset",
                Self::Preseed => "preseed",
                Self::Start => "start",
                Self::Convergence => "convergence",
                Self::Canary => "canary",
                Self::RestartProof => "restart_proof",
                Self::EdgeStage => "edge_stage",
                Self::EdgeCutover => "edge_cutover",
                Self::EdgeVerify => "edge_verify",
                Self::Seal => "seal",
                Self::Cleanup => "cleanup",
            }
        }

        const fn timeout(self, timeouts: &TimeoutsV1) -> u64 {
            match self {
                Self::Preflight => timeouts.install_secs,
                Self::Stage => timeouts.install_secs,
                Self::Stop => timeouts.stop_secs,
                Self::Install => timeouts.install_secs,
                Self::Reset => timeouts.reset_secs,
                Self::Preseed => timeouts.preseed_secs,
                Self::Start => timeouts.start_secs,
                Self::Convergence => timeouts.convergence_secs,
                Self::Canary => timeouts.canary_secs,
                Self::RestartProof => timeouts.restart_secs,
                Self::EdgeStage | Self::EdgeCutover | Self::EdgeVerify | Self::Seal => {
                    timeouts.edge_secs
                }
                Self::Cleanup => timeouts.cleanup_secs,
            }
        }

        const fn records_validator_touch(self) -> bool {
            matches!(
                self,
                Self::Stage | Self::Stop | Self::Install | Self::Reset | Self::Start
            )
        }

        const fn is_validator_step(self) -> bool {
            matches!(
                self,
                Self::Preflight
                    | Self::Stage
                    | Self::Stop
                    | Self::Install
                    | Self::Reset
                    | Self::Start
            )
        }

        const fn is_edge_step(self) -> bool {
            matches!(self, Self::EdgeStage | Self::EdgeCutover | Self::EdgeVerify)
        }

        pub(super) const fn supports_recovery(self) -> bool {
            matches!(self, Self::Canary | Self::RestartProof)
        }
    }

    pub(super) trait RecoveryProgress {
        fn mark_submitted(&mut self, mutation_index: usize) -> Result<()>;
        fn mark_applied(&mut self, mutation_index: usize) -> Result<()>;
    }

    pub(super) trait ResetTransport {
        fn recovery_intent(
            &self,
            _inventory: &InventoryV1,
            step: ExecutionStep,
        ) -> Result<Option<RecoveryIntentV1>> {
            Err(eyre!(
                "transport cannot prepare read-only recovery for `{}`",
                step.label()
            ))
        }

        fn recover_step(
            &mut self,
            _inventory: &InventoryV1,
            step: ExecutionStep,
            _timeout_secs: u64,
            _intent: &RecoveryIntentV1,
            _progress: &mut dyn RecoveryProgress,
        ) -> Result<RecoveryOutcome> {
            Err(eyre!(
                "transport cannot perform read-only recovery for `{}`",
                step.label()
            ))
        }

        fn run_recoverable_step(
            &mut self,
            _inventory: &InventoryV1,
            step: ExecutionStep,
            _timeout_secs: u64,
            _intent: &RecoveryIntentV1,
            _progress: &mut dyn RecoveryProgress,
        ) -> Result<()> {
            Err(eyre!(
                "transport cannot execute journaled recovery-sensitive step `{}`",
                step.label()
            ))
        }

        /// Every mutating implementation must make `(authorization_nonce, step, host)` idempotent.
        fn validator_step(
            &mut self,
            inventory: &InventoryV1,
            validator: &ValidatorV1,
            step: ExecutionStep,
            timeout_secs: u64,
        ) -> Result<()>;
        fn cohort_step(
            &mut self,
            inventory: &InventoryV1,
            step: ExecutionStep,
            timeout_secs: u64,
        ) -> Result<()>;
        fn edge_step(
            &mut self,
            inventory: &InventoryV1,
            step: ExecutionStep,
            timeout_secs: u64,
        ) -> Result<()>;
        fn rollback_validator(
            &mut self,
            inventory: &InventoryV1,
            validator: &ValidatorV1,
            timeout_secs: u64,
        ) -> Result<()>;
        fn rollback_edge(&mut self, inventory: &InventoryV1, timeout_secs: u64) -> Result<()>;
    }

    pub(super) fn execute_plan<T: ResetTransport, J: JournalStore>(
        inventory: &InventoryV1,
        transport: &mut T,
        journal: &mut J,
    ) -> Result<()> {
        execute_plan_with_recovery_classifier(
            inventory,
            transport,
            journal,
            host::is_local_mutation_recovery_pending,
        )
    }

    fn execute_plan_with_recovery_classifier<T, J, F>(
        inventory: &InventoryV1,
        transport: &mut T,
        journal: &mut J,
        is_recovery_pending: F,
    ) -> Result<()>
    where
        T: ResetTransport,
        J: JournalStore,
        F: Fn(&eyre::Report) -> bool,
    {
        if journal.state().status == "recovery_pending" {
            return recover_pending_step(inventory, transport, journal);
        }
        if journal.state().status == "rolling_back" {
            resume_rollback(inventory, transport, journal)?;
            return Err(eyre!("resumed public-reset rollback completed"));
        }
        let start = usize::from(journal.state().next_step);
        for (index, step) in execution_steps(inventory.qualification_scope)
            .iter()
            .copied()
            .enumerate()
            .skip(start)
        {
            let mut state = journal.state().clone();
            if step != ExecutionStep::Cleanup || state.status != "cleanup_pending" {
                state.phase = step.label().to_owned();
            }
            journal.replace(state)?;
            if step.supports_recovery() {
                let intent = match transport.recovery_intent(inventory, step) {
                    Ok(Some(intent)) => intent,
                    Ok(None) => {
                        return rollback_after_failure(
                            inventory,
                            transport,
                            journal,
                            eyre!(
                                "recovery-sensitive step `{}` has no exact mutation intent",
                                step.label()
                            ),
                        );
                    }
                    Err(error) => {
                        return rollback_after_failure(inventory, transport, journal, error);
                    }
                };
                if let Err(error) = validate_recovery_intent(&intent, step) {
                    return rollback_after_failure(inventory, transport, journal, error);
                }
                let intent = if let Some(retained) = journal.state().recovery_intent.as_ref() {
                    if !recovery_has_forward_frontier(retained, step)
                        || !host::recovery_intent_identity_matches(retained, &intent)
                    {
                        return rollback_after_failure(
                            inventory,
                            transport,
                            journal,
                            eyre!(
                                "forward mutation continuation differs from its exact prepared intent"
                            ),
                        );
                    }
                    retained.clone()
                } else {
                    intent
                };
                let mut prepared = journal.state().clone();
                prepared.status = "recovery_pending".to_owned();
                prepared.phase = step.label().to_owned();
                prepared.recovery_intent = Some(intent);
                prepared.failure_summary.clear();
                journal.replace(prepared)?;
            }
            let result = if step.supports_recovery() {
                let intent = journal
                    .state()
                    .recovery_intent
                    .clone()
                    .ok_or_else(|| eyre!("prepared recovery step omits its durable intent"))?;
                let mut progress = JournalRecoveryProgress { journal, step };
                transport.run_recoverable_step(
                    inventory,
                    step,
                    step.timeout(&inventory.timeouts),
                    &intent,
                    &mut progress,
                )
            } else {
                run_step(inventory, transport, journal, step)
            };
            if let Err(error) = result {
                if step == ExecutionStep::Seal || journal.state().status == "sealing" {
                    return preserve_sealing(journal, error);
                }
                if step.supports_recovery() && is_recovery_pending(&error) {
                    return preserve_recovery_pending(journal, step, error);
                }
                if step == ExecutionStep::Cleanup {
                    return preserve_cleanup_pending(journal, error);
                }
                return rollback_after_failure(inventory, transport, journal, error);
            }
            if step.supports_recovery() {
                let completed = journal
                    .state()
                    .recovery_intent
                    .as_ref()
                    .filter(|intent| validate_recovery_intent(intent, step).is_ok())
                    .is_some_and(|intent| {
                        usize::from(intent.next_mutation) == intent.mutations.len()
                    });
                if !completed {
                    return preserve_recovery_pending(
                        journal,
                        step,
                        eyre!(
                            "recovery-sensitive step returned success before every mutation was durably applied"
                        ),
                    );
                }
            }
            let mut state = journal.state().clone();
            state.next_step = u16::try_from(index + 1).expect("bounded execution step count");
            if state.status == "recovery_pending" {
                state.status = "in_progress".to_owned();
                state.recovery_intent = None;
                state.failure_summary.clear();
            }
            if state.status == "sealing" {
                state.failure_summary.clear();
            }
            if step == ExecutionStep::Cleanup {
                state.failure_summary.clear();
                journal.finish(state)?;
                return Ok(());
            }
            if step == ExecutionStep::EdgeVerify {
                state.status = "sealing".to_owned();
                state.phase = "seal".to_owned();
                journal.mark_deployment_proven(state)?;
                continue;
            }
            if step == ExecutionStep::Seal {
                state.status = "cleanup_pending".to_owned();
                state.phase = "cleanup_pending".to_owned();
                journal.replace(state)?;
                continue;
            }
            set_forward_successor_phase(&mut state, index)?;
            journal.replace(state)?;
        }
        journal.finish(journal.state().clone())
    }

    fn set_forward_successor_phase(state: &mut JournalV1, completed_index: usize) -> Result<()> {
        let successor_index = completed_index
            .checked_add(1)
            .ok_or_else(|| eyre!("execution-step successor index overflow"))?;
        if state.status != "in_progress" || usize::from(state.next_step) != successor_index {
            return Err(eyre!(
                "journal cannot publish a forward successor outside its exact cursor"
            ));
        }
        let successor = execution_steps(state.qualification_scope)
            .get(successor_index)
            .ok_or_else(|| eyre!("execution step has no forward successor"))?;
        state.phase = successor.label().to_owned();
        Ok(())
    }

    struct JournalRecoveryProgress<'a, J> {
        journal: &'a mut J,
        step: ExecutionStep,
    }

    impl<J: JournalStore> JournalRecoveryProgress<'_, J> {
        fn mutate(
            &mut self,
            mutation_index: usize,
            expected: RecoveryMutationStateV1,
            replacement: RecoveryMutationStateV1,
            advance: bool,
        ) -> Result<()> {
            let mut state = self.journal.state().clone();
            if state.status != "recovery_pending" || state.phase != self.step.label() {
                return Err(eyre!(
                    "recovery mutation progress is outside its exact prepared step"
                ));
            }
            let intent = state
                .recovery_intent
                .as_mut()
                .ok_or_else(|| eyre!("recovery mutation progress has no durable intent"))?;
            validate_recovery_intent(intent, self.step)?;
            if usize::from(intent.next_mutation) != mutation_index {
                return Err(eyre!(
                    "recovery mutation progress is not the next ordered mutation"
                ));
            }
            let mutation = intent
                .mutations
                .get_mut(mutation_index)
                .ok_or_else(|| eyre!("recovery mutation index is outside its intent"))?;
            if mutation.state != expected {
                return Err(eyre!("recovery mutation state transition is not exact"));
            }
            mutation.state = replacement;
            if advance {
                intent.next_mutation = intent
                    .next_mutation
                    .checked_add(1)
                    .ok_or_else(|| eyre!("recovery mutation cursor overflow"))?;
            }
            validate_recovery_intent(intent, self.step)?;
            self.journal.replace(state)
        }
    }

    impl<J: JournalStore> RecoveryProgress for JournalRecoveryProgress<'_, J> {
        fn mark_submitted(&mut self, mutation_index: usize) -> Result<()> {
            self.mutate(
                mutation_index,
                RecoveryMutationStateV1::Prepared,
                RecoveryMutationStateV1::Submitted,
                false,
            )
        }

        fn mark_applied(&mut self, mutation_index: usize) -> Result<()> {
            self.mutate(
                mutation_index,
                RecoveryMutationStateV1::Submitted,
                RecoveryMutationStateV1::Applied,
                true,
            )
        }
    }

    fn recover_pending_step<T: ResetTransport, J: JournalStore>(
        inventory: &InventoryV1,
        transport: &mut T,
        journal: &mut J,
    ) -> Result<()> {
        let index = usize::from(journal.state().next_step);
        let step = execution_steps(inventory.qualification_scope)
            .get(index)
            .copied()
            .filter(|step| step.supports_recovery())
            .ok_or_else(|| eyre!("recovery journal does not identify an exact recoverable step"))?;
        let intent = journal
            .state()
            .recovery_intent
            .clone()
            .ok_or_else(|| eyre!("recovery journal omits its exact mutation intent"))?;
        validate_recovery_intent(&intent, step)?;
        let outcome = match transport.recover_step(
            inventory,
            step,
            step.timeout(&inventory.timeouts),
            &intent,
            &mut JournalRecoveryProgress { journal, step },
        ) {
            Ok(outcome) => outcome,
            Err(error) => return preserve_recovery_pending(journal, step, error),
        };
        match outcome {
            RecoveryOutcome::ReadyToContinue => {
                let mut state = journal.state().clone();
                if !state
                    .recovery_intent
                    .as_ref()
                    .is_some_and(|intent| recovery_ready_to_continue(intent, step))
                {
                    return preserve_recovery_pending(
                        journal,
                        step,
                        eyre!(
                            "read-only recovery did not establish an exact Prepared continuation frontier"
                        ),
                    );
                }
                state.status = "in_progress".to_owned();
                state.failure_summary.clear();
                journal.replace(state)?;
                Err(eyre!(
                    "read-only recovery advanced the mutation cursor; resume remaining Prepared mutations with the original forward authorization"
                ))
            }
            RecoveryOutcome::ResumeSubmittedBeaconActivation => {
                let mut state = journal.state().clone();
                if !state
                    .recovery_intent
                    .as_ref()
                    .is_some_and(|intent| recovery_ready_to_resume_beacon_activation(intent, step))
                {
                    return preserve_recovery_pending(
                        journal,
                        step,
                        eyre!("provider continuation is outside its exact submitted host intent"),
                    );
                }
                // The transport verified the exact host intent and live original
                // authorization. Retain Submitted; a normal forward reopen verifies
                // that authorization again before any host mutation.
                state.status = "in_progress".to_owned();
                state.failure_summary.clear();
                journal.replace(state)?;
                Err(eyre!(
                    "provider publication can resume only with the original forward authorization"
                ))
            }
            RecoveryOutcome::Applied => {
                let recovered = journal
                    .state()
                    .recovery_intent
                    .as_ref()
                    .ok_or_else(|| eyre!("applied recovery lost its durable intent"))?;
                validate_recovery_intent(recovered, step)?;
                if usize::from(recovered.next_mutation) != recovered.mutations.len() {
                    return preserve_recovery_pending(
                        journal,
                        step,
                        eyre!(
                            "transport claimed outer-step recovery before every mutation was applied"
                        ),
                    );
                }
                let mut state = journal.state().clone();
                state.next_step = u16::try_from(index + 1).expect("bounded execution step count");
                state.recovery_intent = None;
                state.failure_summary.clear();
                if step == ExecutionStep::EdgeVerify {
                    state.status = "sealing".to_owned();
                    state.phase = "seal".to_owned();
                    journal.mark_deployment_proven(state)?;
                } else {
                    state.status = "in_progress".to_owned();
                    set_forward_successor_phase(&mut state, index)?;
                    journal.replace(state)?;
                }
                Err(eyre!(
                    "read-only recovery proved `{}` applied; resume from its durable successor",
                    step.label()
                ))
            }
            RecoveryOutcome::Pending => preserve_recovery_pending(
                journal,
                step,
                eyre!("read-only recovery outcome is still pending"),
            ),
            RecoveryOutcome::Rejected(class) => {
                validate_recovery_rejection_class(&class)?;
                let error = eyre!(
                    "read-only recovery definitively rejected `{}` with class `{class}`",
                    step.label()
                );
                begin_rollback_after_preparation_failure(journal, &error)?;
                Err(error.wrap_err(
                    "durable ambiguity was rejected; rollback is now the only permitted action",
                ))
            }
        }
    }

    fn validate_recovery_rejection_class(class: &str) -> Result<()> {
        if class.is_empty()
            || class.len() > 64
            || !class.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
        {
            return Err(eyre!("recovery rejection class is not a stable V1 label"));
        }
        Ok(())
    }

    fn preserve_recovery_pending<J: JournalStore>(
        journal: &mut J,
        step: ExecutionStep,
        original: eyre::Report,
    ) -> Result<()> {
        let mut state = journal.state().clone();
        let intent = state
            .recovery_intent
            .as_ref()
            .ok_or_else(|| eyre!("recovery-pending state omits its durable mutation intent"))?;
        validate_recovery_intent(intent, step)?;
        state.status = "recovery_pending".to_owned();
        state.phase = step.label().to_owned();
        eprintln!("public-reset local mutation recovery remains pending (ephemeral): {original:#}");
        state.failure_summary = stable_error_record(&state.phase, "local_mutation", &original);
        journal.replace(state)?;
        Err(original.wrap_err(
            "local mutation recovery remains pending; only read-only recovery may run before rollback",
        ))
    }

    fn preserve_cleanup_pending<J: JournalStore>(
        journal: &mut J,
        original: eyre::Report,
    ) -> Result<()> {
        let mut state = journal.state().clone();
        state.status = "cleanup_pending".to_owned();
        state.phase = "cleanup_pending".to_owned();
        eprintln!("public-reset cleanup remains pending (ephemeral): {original:#}");
        state.failure_summary = stable_error_record(&state.phase, "cleanup", &original);
        journal.replace(state)?;
        Err(original.wrap_err(
            "cleanup remains durably pending after proven deployment and must be retried",
        ))
    }

    fn preserve_sealing<J: JournalStore>(journal: &mut J, original: eyre::Report) -> Result<()> {
        let mut state = journal.state().clone();
        state.status = "sealing".to_owned();
        state.phase = "seal".to_owned();
        eprintln!("public-reset host seal remains pending (ephemeral): {original:#}");
        state.failure_summary = stable_error_record(&state.phase, "commit_distribution", &original);
        journal.replace(state)?;
        Err(original.wrap_err(
            "deployment is proven and host seal distribution remains pending; rollback is forbidden",
        ))
    }

    fn run_step<T: ResetTransport, J: JournalStore>(
        inventory: &InventoryV1,
        transport: &mut T,
        journal: &mut J,
        step: ExecutionStep,
    ) -> Result<()> {
        let timeout = step.timeout(&inventory.timeouts);
        if step == ExecutionStep::Preflight {
            for validator in &inventory.validators {
                transport
                    .validator_step(inventory, validator, step, timeout)
                    .wrap_err_with(|| {
                        format!("{} failed for `{}`", step.label(), validator.slug)
                    })?;
            }
            transport
                .edge_step(inventory, step, timeout)
                .wrap_err("preflight failed for public edge")?;
        } else if step.is_validator_step() {
            for validator in &inventory.validators {
                if step.records_validator_touch() {
                    let mut state = journal.state().clone();
                    if !state.touched_validators.contains(&validator.slug) {
                        state.touched_validators.push(validator.slug.clone());
                        journal.replace(state)?;
                    }
                }
                transport
                    .validator_step(inventory, validator, step, timeout)
                    .wrap_err_with(|| {
                        format!("{} failed for `{}`", step.label(), validator.slug)
                    })?;
            }
        } else if step.is_edge_step() {
            if matches!(step, ExecutionStep::EdgeStage | ExecutionStep::EdgeCutover) {
                let mut state = journal.state().clone();
                state.edge_touched = true;
                journal.replace(state)?;
            }
            transport
                .edge_step(inventory, step, timeout)
                .wrap_err_with(|| format!("{} failed", step.label()))?;
        } else {
            transport
                .cohort_step(inventory, step, timeout)
                .wrap_err_with(|| format!("{} failed", step.label()))?;
        }
        Ok(())
    }

    fn rollback_after_failure<T: ResetTransport, J: JournalStore>(
        inventory: &InventoryV1,
        transport: &mut T,
        journal: &mut J,
        original: eyre::Report,
    ) -> Result<()> {
        begin_rollback_after_preparation_failure(journal, &original)?;
        resume_rollback_after_preparation_failure(inventory, transport, journal, original)
    }

    pub(super) fn begin_rollback_after_preparation_failure<J: JournalStore>(
        journal: &mut J,
        original: &eyre::Report,
    ) -> Result<()> {
        let mut state = journal.state().clone();
        if matches!(state.status.as_str(), "sealing" | "cleanup_pending") {
            return Err(eyre!(
                "deployment-proven sealing and cleanup journals cannot enter rollback"
            ));
        }
        state.status = "rolling_back".to_owned();
        state.phase = "rollback".to_owned();
        state.recovery_intent = None;
        eprintln!("public-reset phase failure (ephemeral): {original:#}");
        state.failure_summary = stable_error_record(&state.phase, "forward", original);
        journal.replace(state)
    }

    pub(super) fn resume_rollback_after_preparation_failure<T: ResetTransport, J: JournalStore>(
        inventory: &InventoryV1,
        transport: &mut T,
        journal: &mut J,
        original: eyre::Report,
    ) -> Result<()> {
        match resume_rollback(inventory, transport, journal) {
            Ok(()) => {
                Err(original.wrap_err("public-reset phase failed; touched hosts were rolled back"))
            }
            Err(rollback) => Err(original.wrap_err(format!(
                "public-reset phase failed and rollback remains resumable: {}",
                stable_error_record("rollback", "resume", &rollback)
            ))),
        }
    }

    fn resume_rollback<T: ResetTransport, J: JournalStore>(
        inventory: &InventoryV1,
        transport: &mut T,
        journal: &mut J,
    ) -> Result<()> {
        let timeout = inventory.timeouts.rollback_secs;
        if journal.state().edge_touched && !journal.state().edge_rollback_complete {
            if let Err(error) = transport.rollback_edge(inventory, timeout) {
                record_rollback_failure(journal, "edge", &error)?;
                return Err(error.wrap_err("edge rollback failed"));
            }
            let mut state = journal.state().clone();
            state.edge_rollback_complete = true;
            journal.replace(state)?;
        }
        while usize::from(journal.state().rollback_next_validator)
            < journal.state().touched_validators.len()
        {
            let index = journal.state().touched_validators.len()
                - 1
                - usize::from(journal.state().rollback_next_validator);
            let slug = journal.state().touched_validators[index].clone();
            let validator = inventory
                .validators
                .iter()
                .find(|validator| validator.slug == slug)
                .ok_or_else(|| eyre!("journal references unknown validator"))?;
            if let Err(error) = transport.rollback_validator(inventory, validator, timeout) {
                record_rollback_failure(journal, &slug, &error)?;
                return Err(error.wrap_err("validator rollback failed"));
            }
            let mut state = journal.state().clone();
            state.rollback_next_validator += 1;
            journal.replace(state)?;
        }
        journal.finish_rollback(journal.state().clone())
    }

    fn record_rollback_failure<J: JournalStore>(
        journal: &mut J,
        target: &str,
        error: &eyre::Report,
    ) -> Result<()> {
        let mut state = journal.state().clone();
        eprintln!("public-reset rollback failure for {target} (ephemeral): {error:#}");
        let entry = stable_error_record("rollback", target, error);
        if state.rollback_failures.last() != Some(&entry) && state.rollback_failures.len() < 5 {
            state.rollback_failures.push(entry);
        }
        journal.replace(state)
    }

    fn stable_error_record(phase: &str, target: &str, error: &eyre::Report) -> String {
        let digest = sha256_hex(error.to_string().as_bytes());
        format!("phase={phase};target={target};class=operation_failed;sha256={digest}")
    }

    #[cfg(test)]
    pub(super) mod tests {
        use super::*;
        use iroha_crypto::{KeyPair, Signature};

        include!("taira_public_reset_abandon_tests.rs");

        #[test]
        fn recovery_args_accept_identical_forward_inputs_without_admitting_unused_paths() {
            let unavailable = PathBuf::from("/unused-public-reset-recovery-input");
            let validator_configs = (0..4)
                .map(|index| unavailable.join(format!("validator-{index}.toml")))
                .collect::<Vec<_>>();
            let mut args = PublicResetApply {
                inventory: unavailable.join("inventory.json"),
                authorization: unavailable.join("authorization.json"),
                trusted_public_key: unavailable.join("trusted-key.json"),
                ssh_identity: unavailable.join("identity"),
                known_hosts: unavailable.join("known-hosts"),
                validator_operator_key: Some(unavailable.join("operator.key")),
                runtime_client_config: Some(unavailable.join("runtime.toml")),
                validator_client_config: validator_configs.clone(),
                onboarding_token: Some(unavailable.join("onboarding-token")),
                inrou_stage_dir: Some(unavailable.join("inrou-stage")),
            };
            for step in [ExecutionStep::EdgeVerify] {
                assert!(
                    args.recovery_validator_client_configs(step)
                        .expect("identical forward arguments permit read-only recovery")
                        .is_empty(),
                    "unused validator paths must not reach recovery custody"
                );
            }
            assert_eq!(
                args.recovery_validator_client_configs(ExecutionStep::Canary)
                    .unwrap(),
                validator_configs
            );
            assert_eq!(
                args.recovery_validator_client_configs(ExecutionStep::RestartProof)
                    .expect("RestartProof retains its exact ordered four-config closure"),
                validator_configs
            );
            for count in [0, 3, 5] {
                args.validator_client_config = (0..count)
                    .map(|index| unavailable.join(format!("validator-{index}.toml")))
                    .collect();
                assert!(
                    args.recovery_validator_client_configs(ExecutionStep::RestartProof)
                        .is_err(),
                    "RestartProof must reject {count} configs"
                );
                assert!(
                    args.recovery_validator_client_configs(ExecutionStep::Canary)
                        .is_err()
                );
            }
            assert!(
                args.recovery_validator_operator_key(ExecutionStep::RestartProof)
                    .unwrap()
                    .is_some()
            );
            assert!(
                args.recovery_validator_operator_key(ExecutionStep::Canary)
                    .unwrap()
                    .is_some()
            );
            args.validator_operator_key = None;
            assert!(
                args.recovery_validator_operator_key(ExecutionStep::RestartProof)
                    .is_err()
            );
            assert!(
                args.recovery_validator_operator_key(ExecutionStep::Canary)
                    .is_err()
            );
            args.validator_client_config.clear();
            assert!(
                args.recovery_validator_client_configs(ExecutionStep::Canary)
                    .is_err()
            );
            assert!(
                args.recovery_validator_operator_key(ExecutionStep::EdgeVerify)
                    .unwrap()
                    .is_none()
            );
            assert!(
                args.recovery_validator_client_configs(ExecutionStep::EdgeVerify)
                    .unwrap()
                    .is_empty()
            );
        }

        struct MemoryJournal {
            state: JournalV1,
            finished: bool,
        }

        impl JournalStore for MemoryJournal {
            fn state(&self) -> &JournalV1 {
                &self.state
            }

            fn replace(&mut self, state: JournalV1) -> Result<()> {
                self.state = state;
                Ok(())
            }

            fn mark_deployment_proven(&mut self, state: JournalV1) -> Result<()> {
                self.state = state;
                Ok(())
            }

            fn finish(&mut self, mut state: JournalV1) -> Result<()> {
                state.status = "completed".to_owned();
                state.phase = "completed".to_owned();
                self.state = state;
                self.finished = true;
                Ok(())
            }

            fn finish_rollback(&mut self, mut state: JournalV1) -> Result<()> {
                state.status = "rolled_back".to_owned();
                state.phase = "rolled_back".to_owned();
                self.state = state;
                self.finished = true;
                Ok(())
            }
        }

        struct CrashAfterDurableSuccessor {
            journal: DurableJournal,
            next_step: u16,
            crashed: bool,
        }

        impl JournalStore for CrashAfterDurableSuccessor {
            fn state(&self) -> &JournalV1 {
                self.journal.state()
            }

            fn replace(&mut self, state: JournalV1) -> Result<()> {
                let crash = !self.crashed
                    && state.status == "in_progress"
                    && state.next_step == self.next_step
                    && state.recovery_intent.is_none();
                self.journal.replace(state)?;
                if crash {
                    self.crashed = true;
                    return Err(eyre!("injected crash after durable successor publish"));
                }
                Ok(())
            }

            fn mark_deployment_proven(&mut self, state: JournalV1) -> Result<()> {
                self.journal.mark_deployment_proven(state)
            }

            fn finish(&mut self, state: JournalV1) -> Result<()> {
                self.journal.finish(state)
            }

            fn finish_rollback(&mut self, state: JournalV1) -> Result<()> {
                self.journal.finish_rollback(state)
            }
        }

        #[derive(Default)]
        struct MockTransport {
            events: Vec<String>,
            mutation_dispatches: Vec<(ExecutionStep, usize)>,
            fail: Option<String>,
            recovery_outcome: Option<RecoveryOutcome>,
            submitted_step: Option<ExecutionStep>,
            submitted_outcome: Option<fn() -> Result<host::PreparedMutationOutcome>>,
        }

        impl MockTransport {
            fn record(&mut self, event: String) -> Result<()> {
                self.events.push(event.clone());
                if self.fail.as_deref() == Some(event.as_str()) {
                    return Err(eyre!("injected failure at {event}"));
                }
                Ok(())
            }
        }

        impl ResetTransport for MockTransport {
            fn recovery_intent(
                &self,
                _inventory: &InventoryV1,
                step: ExecutionStep,
            ) -> Result<Option<RecoveryIntentV1>> {
                Ok(Some(test_recovery_intent(step)))
            }

            fn recover_step(
                &mut self,
                _inventory: &InventoryV1,
                step: ExecutionStep,
                _timeout_secs: u64,
                intent: &RecoveryIntentV1,
                progress: &mut dyn RecoveryProgress,
            ) -> Result<RecoveryOutcome> {
                validate_recovery_intent(intent, step)?;
                self.events.push(format!("recover:{}", step.label()));
                if let Some(outcome) = self.recovery_outcome.take() {
                    return Ok(outcome);
                }
                let index = usize::from(intent.next_mutation);
                if index == intent.mutations.len() {
                    return Ok(RecoveryOutcome::Applied);
                }
                match intent.mutations[index].state {
                    RecoveryMutationStateV1::Submitted => {
                        progress.mark_applied(index)?;
                        if index + 1 == intent.mutations.len() {
                            Ok(RecoveryOutcome::Applied)
                        } else {
                            Ok(RecoveryOutcome::ReadyToContinue)
                        }
                    }
                    RecoveryMutationStateV1::Prepared => Ok(RecoveryOutcome::ReadyToContinue),
                    RecoveryMutationStateV1::Applied => {
                        Err(eyre!("cursor cannot point at an applied mutation"))
                    }
                }
            }

            fn run_recoverable_step(
                &mut self,
                _inventory: &InventoryV1,
                step: ExecutionStep,
                _timeout_secs: u64,
                intent: &RecoveryIntentV1,
                progress: &mut dyn RecoveryProgress,
            ) -> Result<()> {
                validate_recovery_intent(intent, step)?;
                for index in usize::from(intent.next_mutation)..intent.mutations.len() {
                    self.mutation_dispatches.push((step, index));
                    if self.submitted_step == Some(step) && index + 1 == intent.mutations.len() {
                        self.events
                            .push(format!("dispatch:{}:{index}", step.label()));
                        return host::run_journaled_submitted_mutation(
                            progress,
                            index,
                            self.submitted_outcome
                                .take()
                                .expect("submitted outcome fixture"),
                        );
                    }
                    progress.mark_submitted(index)?;
                    progress.mark_applied(index)?;
                }
                self.record(step.label().to_owned())
            }

            fn validator_step(
                &mut self,
                _inventory: &InventoryV1,
                validator: &ValidatorV1,
                step: ExecutionStep,
                _timeout_secs: u64,
            ) -> Result<()> {
                self.record(format!("{}:{}", step.label(), validator.slug))
            }

            fn cohort_step(
                &mut self,
                _inventory: &InventoryV1,
                step: ExecutionStep,
                _timeout_secs: u64,
            ) -> Result<()> {
                self.record(step.label().to_owned())
            }

            fn edge_step(
                &mut self,
                _inventory: &InventoryV1,
                step: ExecutionStep,
                _timeout_secs: u64,
            ) -> Result<()> {
                self.record(step.label().to_owned())
            }

            fn rollback_validator(
                &mut self,
                _inventory: &InventoryV1,
                validator: &ValidatorV1,
                _timeout_secs: u64,
            ) -> Result<()> {
                self.record(format!("rollback:{}", validator.slug))
            }

            fn rollback_edge(
                &mut self,
                _inventory: &InventoryV1,
                _timeout_secs: u64,
            ) -> Result<()> {
                self.record("rollback:edge".to_owned())
            }
        }

        fn test_recovery_intent(step: ExecutionStep) -> RecoveryIntentV1 {
            RecoveryIntentV1 {
                schema: RECOVERY_INTENT_SCHEMA_V1.to_owned(),
                step_label: step.label().to_owned(),
                next_mutation: 0,
                mutations: (0..match step {
                    ExecutionStep::Canary => 3,
                    ExecutionStep::RestartProof => 16,
                    ExecutionStep::EdgeVerify => 3,
                    _ => 1,
                })
                    .map(|index| RecoveryMutationV1 {
                        kind: "local_cli".to_owned(),
                        phase: format!("{}-{index}", step.label()),
                        idempotency_key: sha256_hex(
                            format!("test:{}:{index}:idempotency", step.label()).as_bytes(),
                        ),
                        receipt_name: format!("{}-{index}.json", step.label()),
                        state: RecoveryMutationStateV1::Prepared,
                    })
                    .collect(),
            }
        }

        fn unmarked_iroha_hash(seed: &[u8]) -> String {
            let mut bytes = *Hash::new(seed).as_ref();
            bytes[Hash::LENGTH - 1] &= !1_u8;
            hex::encode(bytes)
        }

        #[test]
        fn canonical_iroha_hash_validation_preserves_raw_sha256_semantics() {
            let canonical = Hash::new(b"canonical Iroha hash fixture").to_string();
            validate_canonical_iroha_hash("fixture hash", &canonical)
                .expect("canonical marked Iroha hash");

            let unmarked = unmarked_iroha_hash(b"unmarked Iroha hash fixture");
            validate_lower_hex("raw SHA-256 fixture", &unmarked, 64)
                .expect("raw SHA-256 does not impose Iroha marker semantics");
            let _error = validate_canonical_iroha_hash("fixture hash", &unmarked)
                .expect_err("an Iroha hash must carry its marker bit");

            let _error =
                validate_canonical_iroha_hash("fixture hash", &canonical.to_ascii_uppercase())
                    .expect_err("an Iroha hash must use its canonical lowercase spelling");
        }

        #[test]
        fn inventory_validation_uses_the_exact_taira_chain_discriminant() {
            let inventory = sample_inventory();
            let _conflicting_process_guard = ChainDiscriminantGuard::enter(753);
            AccountId::parse_encoded(&inventory.canary_onboarding_request.account_id)
                .expect_err("a Taira I105 identity must not parse under the SORA discriminant");

            validate_inventory_structure(&inventory)
                .expect("inventory validation enters the signed Taira discriminant");
            let _inventory_guard = enter_inventory_chain_discriminant(&inventory)
                .expect("canonical Taira inventory chain guard");
            let account = AccountId::parse_encoded(&inventory.canary_onboarding_request.account_id)
                .expect("Taira I105 identity parses under discriminant 369");
            assert_eq!(
                account.to_string(),
                inventory.canary_onboarding_request.account_id
            );
        }

        #[test]
        fn inventory_wire_roundtrip_scopes_nonempty_placements_before_decode() {
            use iroha::data_model::account::address::chain_discriminant;
            let _ambient = ChainDiscriminantGuard::enter(753);
            let inventory = sample_inventory();
            assert_eq!(
                inventory
                    .inrou_canary
                    .as_ref()
                    .expect("full Inrou fixture")
                    .placement_targets
                    .len(),
                4
            );
            let bytes = canonical_inventory_bytes(&inventory).expect("canonical Taira inventory");
            assert_eq!(chain_discriminant(), 753, "serializer restores its caller");
            let value: Value = json::from_slice(&bytes).expect("public inventory JSON");
            for target in value
                .pointer("/inrou_canary/placement_targets")
                .and_then(Value::as_array)
                .expect("four serialized placements")
            {
                assert!(
                    target
                        .get("validator_account_id")
                        .and_then(Value::as_str)
                        .expect("typed placement account")
                        .starts_with("test")
                );
            }
            assert!(
                json::from_slice::<InventoryV1>(&bytes).is_err(),
                "unscoped fresh-process decoding reproduces the original failure"
            );
            {
                let (decoded, _guard) = decode_inventory(&bytes, "retained inventory")
                    .expect("fixed-network boundary decodes all four placements");
                assert_eq!(chain_discriminant(), CHAIN_DISCRIMINANT);
                assert_eq!(
                    decoded
                        .inrou_canary
                        .as_ref()
                        .expect("full Inrou fixture")
                        .placement_targets,
                    inventory
                        .inrou_canary
                        .as_ref()
                        .expect("full Inrou fixture")
                        .placement_targets
                );
                validate_inventory_structure(&decoded)
                    .expect("decoded inventory remains admissible");
                assert_eq!(
                    canonical_inventory_bytes(&decoded).expect("reencode"),
                    bytes
                );
            }
            assert_eq!(
                chain_discriminant(),
                753,
                "decoder guard restores its caller"
            );
            assert_eq!(
                assembled_inventory_bytes(&inventory).expect("assembler self-roundtrip"),
                bytes
            );
            assert_eq!(
                chain_discriminant(),
                753,
                "assembly check restores its caller"
            );
        }

        #[test]
        fn inventory_wire_rejects_wrong_chain_foreign_accounts_and_unknown_fields() {
            use iroha::data_model::account::address::chain_discriminant;
            let _ambient = ChainDiscriminantGuard::enter(753);
            let inventory = sample_inventory();
            let bytes = canonical_inventory_bytes(&inventory).expect("valid inventory");
            let canonical: Value = json::from_slice(&bytes).expect("public inventory value");
            let foreign_account = inventory
                .inrou_canary
                .as_ref()
                .expect("full Inrou fixture")
                .placement_targets
                .iter()
                .next()
                .expect("placement")
                .validator_account_id
                .to_string();
            assert!(foreign_account.starts_with("sora"));
            for (path, replacement) in [
                ("/chain_discriminant", Value::from(753_u16)),
                ("/chain_id", Value::String("wrong-chain".to_owned())),
                (
                    "/inrou_canary/placement_targets/0/validator_account_id",
                    Value::String(foreign_account),
                ),
            ] {
                let mut invalid = canonical.clone();
                *invalid.pointer_mut(path).expect("exact inventory field") = replacement;
                assert!(
                    decode_inventory(
                        &json::to_vec(&invalid).expect("invalid inventory bytes"),
                        "inventory"
                    )
                    .is_err()
                );
                assert_eq!(
                    chain_discriminant(),
                    753,
                    "failed decoding restores its caller"
                );
            }
            for path in ["", "/inrou_canary/placement_targets/0"] {
                let mut invalid = canonical.clone();
                let object = if path.is_empty() {
                    &mut invalid
                } else {
                    invalid.pointer_mut(path).expect("placement")
                };
                object
                    .as_object_mut()
                    .expect("inventory object")
                    .insert("retired_field".to_owned(), Value::Null);
                assert!(
                    decode_inventory(
                        &json::to_vec(&invalid).expect("unknown-field inventory"),
                        "inventory"
                    )
                    .is_err()
                );
                assert_eq!(chain_discriminant(), 753);
            }
            let mut wrong = inventory;
            wrong.chain_discriminant = 753;
            assert!(canonical_inventory_bytes(&wrong).is_err());
            assert_eq!(chain_discriminant(), 753);
        }

        #[test]
        fn qualification_scope_requires_exact_nullable_inrou_closure() {
            let full = sample_inventory();
            validate_inventory_structure(&full).expect("complete full_inrou fixture");
            let mut core = full.clone();
            core.qualification_scope = QualificationScopeV1::CoreTestnet;
            assert!(
                validate_inventory_structure(&core).is_err(),
                "core rejects an Inrou object"
            );
            core.inrou_canary = None;
            assert!(
                validate_inventory_structure(&core).is_err(),
                "core rejects an Inrou stage hash"
            );
            core.inrou_stage_tree_sha256 = None;
            validate_inventory_structure(&core)
                .expect("core accepts validators reporting KVM API 12");
            let mut no_kvm_core = core.clone();
            for validator in &mut no_kvm_core.validators {
                validator.platform.kvm_api_version = 0;
            }
            no_kvm_core.hosts.validator_guest.platform.kvm_api_version = 0;
            no_kvm_core.edge.native_capability = native_edge_protocol::fixture_capability(
                &no_kvm_core.hosts,
                no_kvm_core.edge.admitted_release().unwrap().clone(),
                &no_kvm_core.authorization_nonce,
                &no_kvm_core.previous_genesis_hash,
            );
            validate_inventory_structure(&no_kvm_core)
                .expect("all four core validators may run without KVM");
            for index in 0..full.validators.len() {
                let mut no_kvm_full = full.clone();
                no_kvm_full.validators[index].platform.kvm_api_version = 0;
                assert!(
                    validate_inventory_structure(&no_kvm_full).is_err(),
                    "every full_inrou validator requires KVM API 12"
                );
            }
            let mut unknown_kvm_core = no_kvm_core.clone();
            unknown_kvm_core.validators[0].platform.kvm_api_version = 11;
            assert!(
                validate_inventory_structure(&unknown_kvm_core).is_err(),
                "core still rejects unsupported observed KVM API versions"
            );
            let mut kvm_edge = no_kvm_core.clone();
            kvm_edge.edge.platform.kvm_api_version = 12;
            assert!(
                validate_inventory_structure(&kvm_edge).is_err(),
                "the edge must still declare KVM API 0"
            );
            for inventory in [&core, &full] {
                let encoded = json::to_value(inventory).expect("typed inventory");
                for field in ["inrou_canary", "inrou_stage_tree_sha256"] {
                    let mut missing = encoded.clone();
                    missing.as_object_mut().unwrap().remove(field);
                    assert!(
                        json::from_value::<InventoryV1>(missing).is_err(),
                        "{field} must be explicit, even when null"
                    );
                }
                let authority = admitted((*inventory).clone());
                let mut claims = json::to_value(&authority.authorization.claims).unwrap();
                claims
                    .as_object_mut()
                    .unwrap()
                    .remove("inrou_stage_tree_sha256");
                assert!(json::from_value::<AuthorizationClaimsV1>(claims).is_err());
            }
            for remove_canary in [true, false] {
                let mut incomplete = full.clone();
                if remove_canary {
                    incomplete.inrou_canary = None;
                } else {
                    incomplete.inrou_stage_tree_sha256 = None;
                }
                assert!(
                    validate_inventory_structure(&incomplete).is_err(),
                    "full scope never defaults a missing stage dependency"
                );
            }
            let mut drift = full.clone();
            drift.inrou_stage_tree_sha256 = Some("b".repeat(64));
            assert!(validate_inventory_structure(&drift).is_err());
            assert!(
                json::from_value::<QualificationScopeV1>(Value::String("inrou".to_owned()))
                    .is_err(),
                "no old scope alias"
            );
            let path = Path::new("/unopened-inrou-stage");
            assert!(
                QualificationScopeV1::CoreTestnet
                    .validate_stage_argument(None)
                    .is_ok()
            );
            assert!(
                QualificationScopeV1::CoreTestnet
                    .validate_stage_argument(Some(path))
                    .is_err()
            );
            assert!(
                QualificationScopeV1::FullInrou
                    .validate_stage_argument(None)
                    .is_err()
            );
            assert!(
                QualificationScopeV1::FullInrou
                    .validate_stage_argument(Some(path))
                    .is_ok()
            );
        }

        #[test]
        fn qualification_scope_reopens_exact_durable_execution_boundaries() {
            for scope in [
                QualificationScopeV1::CoreTestnet,
                QualificationScopeV1::FullInrou,
            ] {
                let mut inventory = sample_inventory();
                inventory.qualification_scope = scope;
                if !scope.includes_inrou() {
                    inventory.inrou_canary = None;
                    inventory.inrou_stage_tree_sha256 = None;
                }
                let steps = execution_steps(scope);
                assert_eq!(steps.len(), if scope.includes_inrou() { 14 } else { 13 });
                assert_eq!(
                    steps.contains(&ExecutionStep::Preseed),
                    scope.includes_inrou()
                );
                for boundary in [5, 6, steps.len() - 3] {
                    let admitted = admitted(inventory.clone());
                    let directory = private_tempdir();
                    let canonical = directory.path().canonicalize().unwrap();
                    let journal = DurableJournal::open(&canonical, &admitted).unwrap();
                    let mut crashing = CrashAfterDurableSuccessor {
                        journal,
                        next_step: u16::try_from(boundary).unwrap(),
                        crashed: false,
                    };
                    let mut first = MockTransport::default();
                    let error = execute_plan(&admitted.inventory, &mut first, &mut crashing)
                        .expect_err("crash after durable boundary");
                    assert!(
                        format!("{error:#}").contains("injected crash after durable successor")
                    );
                    assert_eq!(crashing.state().phase, steps[boundary].label());
                    let mut wrong = crashing.state().clone();
                    wrong.phase = if scope.includes_inrou() {
                        "missing-full-stage"
                    } else {
                        "preseed"
                    }
                    .to_owned();
                    assert!(validate_resumable_journal(&wrong, crashing.state()).is_err());
                    drop(crashing);
                    let mut resumed = match DurableJournal::classify(&canonical, &admitted).unwrap()
                    {
                        JournalOpen::Resumable(journal) => journal,
                        JournalOpen::Fresh(_) => panic!("durable boundary must remain resumable"),
                    };
                    assert_eq!(resumed.state().phase, steps[boundary].label());
                    let mut retry = MockTransport::default();
                    execute_plan(&admitted.inventory, &mut retry, &mut resumed)
                        .expect("exact scope resumes to completion");
                    assert_eq!(usize::from(resumed.state().next_step), steps.len());
                    assert_eq!(resumed.state().status, "completed");
                    if !scope.includes_inrou() {
                        assert!(
                            !first
                                .events
                                .iter()
                                .chain(&retry.events)
                                .any(|event| event.contains("preseed")),
                            "core records no fake preseed work"
                        );
                    }
                }
            }
        }

        #[test]
        fn qualification_scope_is_required_and_canonical_in_all_authority_documents() {
            for scope in [
                QualificationScopeV1::CoreTestnet,
                QualificationScopeV1::FullInrou,
            ] {
                let mut inventory = sample_inventory();
                inventory.qualification_scope = scope;
                if !scope.includes_inrou() {
                    inventory.inrou_canary = None;
                    inventory.inrou_stage_tree_sha256 = None;
                }
                validate_inventory_structure(&inventory)
                    .expect("both explicit scopes are admitted");
                let bytes = canonical_inventory_bytes(&inventory).expect("inventory bytes");
                let inventory_value: Value = json::from_slice(&bytes).expect("inventory JSON");
                let (decoded, _guard) =
                    decode_inventory(&bytes, "inventory").expect("inventory scope");
                assert_eq!(decoded.qualification_scope, scope);
                let admitted = admitted(inventory);
                let claims_value =
                    json::to_value(&admitted.authorization.claims).expect("claims JSON");
                let journal_value =
                    json::to_value(&initial_journal(&admitted)).expect("journal JSON");
                assert_eq!(
                    json::from_value::<AuthorizationClaimsV1>(claims_value.clone())
                        .expect("claims scope")
                        .qualification_scope,
                    scope
                );
                assert_eq!(
                    json::from_value::<JournalV1>(journal_value.clone())
                        .expect("journal scope")
                        .qualification_scope,
                    scope
                );
                for value in [&inventory_value, &claims_value, &journal_value] {
                    assert_eq!(
                        value.get("qualification_scope").and_then(Value::as_str),
                        Some(scope.as_str())
                    );
                }
                for replacement in [
                    None,
                    Some(Value::Null),
                    Some(Value::String("all".to_owned())),
                    Some(Value::String("CoreTestnet".to_owned())),
                    Some(Value::Object(Map::new())),
                ] {
                    let corrupt = |value: &Value| {
                        let mut value = value.clone();
                        let object = value.as_object_mut().expect("authority document object");
                        match &replacement {
                            Some(replacement) => {
                                object
                                    .insert("qualification_scope".to_owned(), replacement.clone());
                            }
                            None => {
                                object.remove("qualification_scope");
                            }
                        }
                        value
                    };
                    assert!(
                        decode_inventory(
                            &json::to_vec(&corrupt(&inventory_value))
                                .expect("invalid inventory bytes"),
                            "inventory"
                        )
                        .is_err()
                    );
                    assert!(
                        json::from_value::<AuthorizationClaimsV1>(corrupt(&claims_value)).is_err()
                    );
                    assert!(json::from_value::<JournalV1>(corrupt(&journal_value)).is_err());
                }
            }
        }

        #[test]
        fn qualification_scope_is_bound_before_normal_and_recovery_signature_admission() {
            let mut inventory = sample_inventory();
            inventory.qualification_scope = QualificationScopeV1::CoreTestnet;
            inventory.inrou_canary = None;
            inventory.inrou_stage_tree_sha256 = None;
            let mut admitted = admitted(inventory);
            admitted.authorization.claims.qualification_scope = QualificationScopeV1::FullInrou;
            for admission_window in [true, false] {
                let error = verify_authorization_window(
                    &admitted.inventory,
                    &admitted.inventory_sha256,
                    &admitted.authorization,
                    &admitted.trusted_key,
                    1_000_000,
                    admission_window,
                )
                .expect_err("a scope change must fail before signature decoding");
                assert!(
                    error
                        .to_string()
                        .contains("claims do not exactly bind this reset inventory"),
                    "{error:#}"
                );
            }
        }

        #[test]
        fn qualification_scope_is_immutable_in_recovery_and_reported_explicitly() {
            let mut inventory = sample_inventory();
            inventory.qualification_scope = QualificationScopeV1::CoreTestnet;
            inventory.inrou_canary = None;
            inventory.inrou_stage_tree_sha256 = None;
            let admitted = admitted(inventory);
            let initial = initial_journal(&admitted);
            validate_resumable_journal(&initial, &initial).expect("same core scope resumes");
            let mut changed = initial.clone();
            changed.qualification_scope = QualificationScopeV1::FullInrou;
            assert!(validate_resumable_journal(&changed, &initial).is_err());
            assert!(!valid_journal_successor(&initial, &changed));
            let report = report(&admitted, "apply", "ok", "core qualification completed");
            assert_eq!(
                report.get("qualification_scope").and_then(Value::as_str),
                Some("core_testnet")
            );
            let mut full_inventory = admitted.inventory.clone();
            full_inventory.qualification_scope = QualificationScopeV1::FullInrou;
            assert_eq!(
                execution_lifetime_ms(&admitted.inventory).expect("core lease"),
                execution_lifetime_ms(&full_inventory).expect("conservative maximum lease")
            );
        }

        #[test]
        fn inventory_file_boundary_preserves_original_bytes_and_decode_guard() {
            use iroha::data_model::account::address::chain_discriminant;
            let _ambient = ChainDiscriminantGuard::enter(753);
            let directory = private_tempdir();
            let path = directory
                .path()
                .canonicalize()
                .expect("fixture root")
                .join("inventory.json");
            let inventory = sample_inventory();
            let bytes = assembled_inventory_bytes(&inventory).expect("assembler output");
            let mut file = create_private_new(&path).expect("private inventory file");
            file.write_all(&bytes)
                .expect("write exact assembler output");
            drop(file);
            {
                let (decoded, retained, _guard) = read_inventory(&path, "inventory")
                    .expect("read real retained inventory under ambient SORA context");
                assert_eq!(retained, bytes);
                assert_eq!(
                    decoded
                        .inrou_canary
                        .as_ref()
                        .expect("full Inrou fixture")
                        .placement_targets
                        .len(),
                    4
                );
                assert_eq!(chain_discriminant(), CHAIN_DISCRIMINANT);
            }
            assert_eq!(chain_discriminant(), 753);
        }

        #[test]
        fn recovery_intent_rejects_noncanonical_idempotency_digests() {
            let canonical = test_recovery_intent(ExecutionStep::Canary);
            validate_recovery_intent(&canonical, ExecutionStep::Canary)
                .expect("canonical recovery intent");
            for malformed in ["A".repeat(64), "a".repeat(63), "a".repeat(65)] {
                let mut hostile = canonical.clone();
                hostile.mutations[0].idempotency_key = malformed;
                let error = validate_recovery_intent(&hostile, ExecutionStep::Canary)
                    .expect_err("noncanonical recovery idempotency key must fail closed");
                assert!(format!("{error:#}").contains("exact lowercase SHA-256"));
            }
        }

        #[test]
        fn journal_requires_explicit_nullable_recovery_intent_slot() {
            let admitted = admitted(sample_inventory());
            let state = initial_journal(&admitted);
            let canonical = json::to_value(&state).expect("journal JSON value");
            assert!(
                canonical
                    .as_object()
                    .and_then(|object| object.get("recovery_intent"))
                    .is_some_and(norito::json::Value::is_null),
                "an empty recovery intent must serialize as an explicit null slot"
            );
            json::from_value::<JournalV1>(canonical.clone())
                .expect("explicit nullable journal slot");

            let mut missing = canonical;
            missing
                .as_object_mut()
                .expect("journal object")
                .remove("recovery_intent");
            assert!(
                json::from_value::<JournalV1>(missing).is_err(),
                "the exact V1 journal must reject an omitted recovery_intent slot"
            );
        }

        fn admitted(inventory: InventoryV1) -> AdmittedReset {
            let ssh = File::open("/dev/null").expect("open /dev/null");
            let ssh_snapshot = file_snapshot(&ssh.metadata().expect("metadata")).expect("snapshot");
            let known_hosts = ssh.try_clone().expect("clone /dev/null");
            let known_hosts_snapshot =
                file_snapshot(&known_hosts.metadata().expect("metadata")).expect("snapshot");
            let authorization = AuthorizationEnvelopeV1 {
                schema: AUTHORIZATION_SCHEMA_V1.to_owned(),
                claims: sample_claims(&inventory, &"11".repeat(32)),
                signature_hex: "00".repeat(64),
            };
            AdmittedReset {
                inventory,
                inventory_bytes: Vec::new(),
                inventory_sha256: "11".repeat(32),
                authorization_bytes: Vec::new(),
                authorization_sha256: "22".repeat(32),
                trusted_key_bytes: Vec::new(),
                authorization,
                trusted_key: TrustedKeyV1 {
                    schema: TRUSTED_KEY_SCHEMA_V1.to_owned(),
                    algorithm: "ed25519".to_owned(),
                    public_key: "ed0120".to_owned(),
                },
                pinned_artifacts: Vec::new(),
                ssh_identity: PinnedInput {
                    path: PathBuf::from("/dev/null"),
                    file: ssh,
                    snapshot: ssh_snapshot,
                },
                known_hosts: PinnedInput {
                    path: PathBuf::from("/dev/null"),
                    file: known_hosts,
                    snapshot: known_hosts_snapshot,
                },
            }
        }

        fn journal(inventory: InventoryV1) -> (InventoryV1, MemoryJournal) {
            let admitted = admitted(inventory.clone());
            let state = initial_journal(&admitted);
            (
                inventory,
                MemoryJournal {
                    state,
                    finished: false,
                },
            )
        }

        fn private_tempdir() -> tempfile::TempDir {
            private_custody_test_dir("taira-reset-journal-")
        }

        #[cfg(unix)]
        #[test]
        fn private_fixture_rejects_writable_ancestor_custody() {
            let directory = private_tempdir();
            let ancestor = directory.path().join("replaceable");
            fs::create_dir(&ancestor).expect("fixture ancestor");
            let private = ancestor.join("private");
            fs::create_dir(&private).expect("private fixture leaf");
            fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))
                .expect("safe ancestor mode");
            fs::set_permissions(&private, fs::Permissions::from_mode(0o700))
                .expect("private leaf mode");
            validate_owner_private_dir(&private, "fixture").expect("safe fixture custody");
            for mode in [0o770, 0o777, 0o1777] {
                fs::set_permissions(&ancestor, fs::Permissions::from_mode(mode))
                    .expect("replaceable ancestor mode");
                let error = validate_owner_private_dir(&private, "fixture")
                    .expect_err("a private leaf cannot repair writable ancestor custody");
                assert!(error.to_string().contains("unsafe custody"), "{error:#}");
            }
        }

        #[cfg(unix)]
        fn materialize_artifact_sources(inventory: &mut InventoryV1) -> tempfile::TempDir {
            let directory = private_custody_test_dir("taira-reset-artifacts-");
            let root = directory.path().canonicalize().expect("artifact root");
            let mut materialized = BTreeSet::new();
            let mut materialize = |slug: &str, artifact: &mut ArtifactV1| {
                let source_name = if artifact.target == host_pair::NATIVE_EDGE_TARGET {
                    format!("native-{slug}-{}", artifact.role)
                } else if matches!(artifact.role.as_str(), "config" | "validator_unit") {
                    format!("{slug}-{}", artifact.role)
                } else {
                    artifact.role.clone()
                };
                let path = root.join(&source_name);
                let bytes = source_name.as_bytes();
                if materialized.insert(path.clone()) {
                    fs::write(&path, bytes).expect("write artifact fixture");
                    fs::set_permissions(
                        &path,
                        fs::Permissions::from_mode(u32::from(artifact.mode)),
                    )
                    .expect("set artifact fixture mode");
                }
                artifact.local_path = path.to_string_lossy().into_owned();
                artifact.size = u64::try_from(bytes.len()).expect("small artifact fixture");
                artifact.sha256 = sha256_hex(bytes);
            };
            for validator in &mut inventory.validators {
                for artifact in &mut validator.artifacts {
                    materialize(&validator.slug, artifact);
                }
            }
            for artifact in &mut inventory.edge.artifacts {
                materialize(&inventory.edge.slug, artifact);
            }
            inventory.hosts.native_edge.dispatcher_sha256 =
                artifact(&inventory.edge.artifacts, "iroha_cli")
                    .unwrap()
                    .sha256
                    .clone();
            inventory.edge.native_capability = native_edge_protocol::fixture_capability(
                &inventory.hosts,
                inventory.edge.admitted_release().unwrap().clone(),
                &inventory.authorization_nonce,
                &inventory.previous_genesis_hash,
            );
            directory
        }

        #[cfg(unix)]
        #[test]
        fn shared_validator_artifacts_are_hashed_once_per_local_source() {
            let mut inventory = sample_inventory();
            let _directory = materialize_artifact_sources(&mut inventory);
            let mut hash_counts = BTreeMap::<PathBuf, usize>::new();

            validate_shared_validator_closure(&inventory)
                .expect("materialized inventory must be a valid shared closure");

            let pinned = validate_artifact_files_with(&inventory, |file, path| {
                *hash_counts.entry(path.to_path_buf()).or_default() += 1;
                sha256_reader(file, path)
            })
            .expect("shared artifact sources must validate");

            assert_eq!(pinned.len(), 4 * VALIDATOR_ARTIFACT_ROLES.len() + 2);
            assert_eq!(
                pinned
                    .iter()
                    .map(|entry| (
                        entry.slug.as_str(),
                        entry.role.as_str(),
                        entry.artifact.remote_path.as_str(),
                    ))
                    .collect::<BTreeSet<_>>()
                    .len(),
                pinned.len(),
                "deduplication must retain every host/role/remote-path entry"
            );
            assert_eq!(hash_counts.len(), 16);
            assert!(hash_counts.values().all(|count| *count == 1));
            let iroha3d = PathBuf::from(&inventory.validators[0].artifacts[0].local_path);
            assert_eq!(hash_counts.get(&iroha3d), Some(&1));
        }

        #[cfg(unix)]
        #[test]
        fn shared_artifact_declarations_must_agree_on_content_size_and_mode() {
            for mismatch in ["content", "size", "mode"] {
                let mut inventory = sample_inventory();
                let _directory = materialize_artifact_sources(&mut inventory);
                let duplicate = inventory.validators[1]
                    .artifacts
                    .iter_mut()
                    .find(|artifact| artifact.role == "iroha3d")
                    .expect("second validator iroha3d");
                match mismatch {
                    "content" => duplicate.sha256 = "0".repeat(64),
                    "size" => duplicate.size += 1,
                    "mode" => duplicate.mode ^= 0o100,
                    _ => unreachable!(),
                }

                let error = validate_artifact_files(&inventory)
                    .err()
                    .expect("conflicting shared declaration must fail closed");
                assert!(
                    format!("{error:#}")
                        .contains("conflicting content, size, or mode declarations"),
                    "unexpected {mismatch} error: {error:#}"
                );
            }
        }

        #[cfg(unix)]
        #[test]
        fn shared_artifact_descriptor_clone_rejects_path_identity_drift() {
            let mut inventory = sample_inventory();
            let _directory = materialize_artifact_sources(&mut inventory);
            let artifacts = &inventory.validators[0].artifacts;
            let daemon = artifact(artifacts, "iroha3d").expect("fixture daemon");
            let drifted = PathBuf::from(&daemon.local_path);
            let trigger = PathBuf::from(
                &artifact(artifacts, "genesis_hash")
                    .expect("fixture genesis hash")
                    .local_path,
            );
            let expected_mode = daemon.mode;
            let mut replaced = false;

            let error = validate_artifact_files_with(&inventory, |file, path| {
                let digest = sha256_reader(file, path)?;
                if path == trigger && !replaced {
                    let displaced = drifted.with_extension("displaced");
                    fs::rename(&drifted, displaced).expect("displace cached artifact path");
                    fs::write(&drifted, b"iroha3d").expect("replace cached artifact path");
                    fs::set_permissions(
                        &drifted,
                        fs::Permissions::from_mode(u32::from(expected_mode)),
                    )
                    .expect("protect replacement");
                    replaced = true;
                }
                Ok(digest)
            })
            .err()
            .expect("cached path identity drift must prevent descriptor cloning");
            assert!(replaced);
            assert!(format!("{error:#}").contains("changed during descriptor-bound validation"));
        }

        fn signed_admitted(inventory: InventoryV1, issued_at_unix_ms: u64) -> AdmittedReset {
            let mut admitted = admitted(inventory);
            let key = KeyPair::try_random_with_algorithm(Algorithm::Ed25519).expect("key");
            let mut claims = sample_claims(&admitted.inventory, &admitted.inventory_sha256);
            claims.issued_at_unix_ms = issued_at_unix_ms;
            claims.not_before_unix_ms = issued_at_unix_ms;
            claims.expires_at_unix_ms = issued_at_unix_ms + MAX_AUTHORIZATION_LIFETIME_MS;
            claims.execution_expires_at_unix_ms = issued_at_unix_ms
                + execution_lifetime_ms(&admitted.inventory).expect("execution lifetime");
            let signature = Signature::try_new(
                key.private_key(),
                &authorization_message(&claims).expect("message"),
            )
            .expect("signature");
            admitted.authorization = AuthorizationEnvelopeV1 {
                schema: AUTHORIZATION_SCHEMA_V1.to_owned(),
                claims,
                signature_hex: hex::encode(signature.payload()),
            };
            admitted.trusted_key = TrustedKeyV1 {
                schema: TRUSTED_KEY_SCHEMA_V1.to_owned(),
                algorithm: "ed25519".to_owned(),
                public_key: key.public_key().to_string(),
            };
            admitted.authorization_bytes = json::to_json(&admitted.authorization)
                .expect("authorization JSON")
                .into_bytes();
            admitted.trusted_key_bytes = json::to_json(&admitted.trusted_key)
                .expect("trusted-key JSON")
                .into_bytes();
            admitted.authorization_sha256 =
                authorization_semantic_sha256(&admitted.authorization, &admitted.trusted_key)
                    .expect("semantic authorization hash");
            admitted
        }

        #[test]
        fn authorization_rejects_wrong_signature() {
            let inventory = sample_inventory();
            let raw = canonical_inventory_bytes(&inventory).expect("inventory JSON");
            let inventory_sha = sha256_hex(&raw);
            let key = KeyPair::try_random_with_algorithm(Algorithm::Ed25519).expect("key");
            let wrong = KeyPair::try_random_with_algorithm(Algorithm::Ed25519).expect("wrong key");
            let claims = sample_claims(&inventory, &inventory_sha);
            let signature = Signature::try_new(
                wrong.private_key(),
                &authorization_message(&claims).expect("message"),
            )
            .expect("signature");
            let envelope = AuthorizationEnvelopeV1 {
                schema: AUTHORIZATION_SCHEMA_V1.to_owned(),
                claims,
                signature_hex: hex::encode(signature.payload()),
            };
            let trusted = TrustedKeyV1 {
                schema: TRUSTED_KEY_SCHEMA_V1.to_owned(),
                algorithm: "ed25519".to_owned(),
                public_key: key.public_key().to_string(),
            };
            let _ =
                verify_authorization(&inventory, &inventory_sha, &envelope, &trusted, 1_000_000)
                    .expect_err("wrong signature must fail");
        }

        #[test]
        fn inventory_pins_the_complete_first_release_canary_request() {
            let inventory = sample_inventory();
            let _chain_guard = enter_inventory_chain_discriminant(&inventory)
                .expect("admitted Taira address context");
            let request = inventory.canary_onboarding_request;
            validate_canary_onboarding_request(&request).expect("canonical canary request");

            let mut permissions = request.clone();
            permissions.permissions.push("CanReadAccounts".to_owned());
            let _ = validate_canary_onboarding_request(&permissions)
                .expect_err("public reset must not accept a permission-substituted request");

            let mut alias = request;
            alias.alias = "other@universal".to_owned();
            let _ = validate_canary_onboarding_request(&alias)
                .expect_err("public reset must not accept an alias-substituted request");
        }

        #[test]
        fn inventory_genesis_hashes_require_the_iroha_marker_bit() {
            let original = sample_inventory();
            validate_inventory_structure(&original).expect("complete genesis-bound inventory");
            let unmarked = unmarked_iroha_hash(b"unmarked Taira genesis fixture");
            for (field, label) in [
                ("previous", "previous genesis hash"),
                ("next", "next genesis hash"),
            ] {
                let hash_error = validate_canonical_iroha_hash(label, &unmarked)
                    .expect_err("both genesis anchors require the native marker bit");
                assert!(format!("{hash_error:#}").contains(label));
                let mut inventory = original.clone();
                match field {
                    "previous" => {
                        inventory.previous_genesis_hash = unmarked.clone();
                    }
                    "next" => {
                        inventory.next_genesis_hash = unmarked.clone();
                    }
                    _ => unreachable!("closed genesis-hash fixture field"),
                }
                let error = validate_inventory_structure(&inventory)
                    .expect_err("an unmarked genesis hash must fail inventory admission");
                assert!(
                    format!("{error:#}").contains(label)
                        && format!("{error:#}").contains("least significant bit of hash to be 1"),
                    "{error:#}"
                );
            }
        }

        #[test]
        fn validator_fingerprints_require_the_iroha_marker_bit() {
            let inventory = sample_inventory();
            let unmarked = unmarked_iroha_hash(b"unmarked validator fingerprint fixture");
            for field in ["node", "build", "config"] {
                let mut validator = inventory.validators[0].clone();
                let expected_label = match field {
                    "node" => {
                        validator.node_fingerprint = unmarked.clone();
                        "validator node fingerprint"
                    }
                    "build" => {
                        validator.build_fingerprint = unmarked.clone();
                        "validator build fingerprint"
                    }
                    "config" => {
                        validator.config_fingerprint = unmarked.clone();
                        "validator config fingerprint"
                    }
                    _ => unreachable!("closed validator-fingerprint fixture field"),
                };
                let error = validate_validator(
                    &validator,
                    VALIDATOR_SLUGS[0],
                    &inventory.revision,
                    inventory.qualification_scope,
                )
                .expect_err("an unmarked validator fingerprint must fail admission");
                assert!(format!("{error:#}").contains(expected_label));
            }
        }

        #[test]
        fn inrou_canary_requires_exact_first_release_service_version_format() {
            let canonical = sample_inventory().inrou_canary.expect("full Inrou fixture");
            validate_inrou(&canonical).expect("canonical artifact-version format");

            let mut another_canonical_digest = canonical.clone();
            another_canonical_digest.service_version = format!(
                "artifact-{}",
                Hash::new(b"another fixture Inrou bundle").to_string()
            );
            validate_inrou(&another_canonical_digest)
                .expect("format admission defers bundle derivation to retained-stage apply");

            for malformed in [
                "1.0.0".to_owned(),
                format!("artifact-{}", "A".repeat(64)),
                format!("artifact-{}", "a".repeat(63)),
                format!("artifact-{}", "a".repeat(65)),
                format!("release-{}", "a".repeat(64)),
                format!("artifact-{}", "8".repeat(64)),
            ] {
                let mut canary = canonical.clone();
                canary.service_version = malformed;
                let _error = validate_inrou(&canary)
                    .expect_err("legacy or malformed Inrou service revisions must fail closed");
            }
        }

        #[test]
        fn inrou_canary_rejects_printable_but_noncanonical_iroha_hashes() {
            let canonical = sample_inventory().inrou_canary.expect("full Inrou fixture");
            for mutate in [
                |canary: &mut InrouCanaryV1| canary.bundle_hash = "bundle".to_owned(),
                |canary: &mut InrouCanaryV1| {
                    canary.container_manifest_hash = "container".to_owned();
                },
                |canary: &mut InrouCanaryV1| {
                    canary.service_manifest_hash = "service".to_owned();
                },
                |canary: &mut InrouCanaryV1| {
                    canary.discovery_document_hash = "discovery".to_owned();
                },
            ] {
                let mut malformed = canonical.clone();
                mutate(&mut malformed);
                let _error = validate_inrou(&malformed)
                    .expect_err("printable legacy hash spellings must fail closed");
            }
        }

        #[test]
        fn inrou_hash_fields_require_the_iroha_marker_bit() {
            let canonical = sample_inventory().inrou_canary.expect("full Inrou fixture");
            let unmarked = unmarked_iroha_hash(b"unmarked Inrou hash fixture");
            for field in [
                "service_revision",
                "bundle",
                "container",
                "service",
                "discovery",
            ] {
                let mut malformed = canonical.clone();
                let expected_label = match field {
                    "service_revision" => {
                        malformed.service_version = format!("artifact-{unmarked}");
                        "Inrou canary service artifact revision"
                    }
                    "bundle" => {
                        malformed.bundle_hash = unmarked.clone();
                        "Inrou bundle hash"
                    }
                    "container" => {
                        malformed.container_manifest_hash = unmarked.clone();
                        "Inrou container manifest hash"
                    }
                    "service" => {
                        malformed.service_manifest_hash = unmarked.clone();
                        "Inrou service manifest hash"
                    }
                    "discovery" => {
                        malformed.discovery_document_hash = unmarked.clone();
                        "Inrou discovery document hash"
                    }
                    _ => unreachable!("closed Inrou hash fixture field"),
                };
                let error = validate_inrou(&malformed)
                    .expect_err("an unmarked Inrou hash must fail admission");
                assert!(format!("{error:#}").contains(expected_label));
            }
        }

        #[test]
        fn signed_fee_intent_binds_payer_program_and_revision() {
            let sponsor_key =
                KeyPair::try_random_with_algorithm(Algorithm::Ed25519).expect("sponsor key");
            let sponsor = FeeSponsorProgramId::new(
                iroha::data_model::account::AccountId::new(sponsor_key.public_key().clone()),
                "default".parse().expect("program name"),
            );
            let mut inventory = sample_inventory();
            inventory.fee_intent = FeeIntentV1 {
                payer: "sponsor".to_owned(),
                sponsor_program: Some(sponsor.to_string()),
                sponsor_program_revision: Some(7),
            };
            validate_fee_intent(&inventory.fee_intent).expect("canonical sponsor intent");
            let admitted = signed_admitted(inventory, 1_000_000);
            verify_authorization(
                &admitted.inventory,
                &admitted.inventory_sha256,
                &admitted.authorization,
                &admitted.trusted_key,
                1_000_000,
            )
            .expect("signed fee intent is admitted");

            let mut payer = admitted.authorization.clone();
            payer.claims.fee_intent.payer = "authority".to_owned();
            let _ = verify_authorization(
                &admitted.inventory,
                &admitted.inventory_sha256,
                &payer,
                &admitted.trusted_key,
                1_000_000,
            )
            .expect_err("payer tampering must fail");

            let mut program = admitted.authorization.clone();
            program.claims.fee_intent.sponsor_program = Some("tampered".to_owned());
            let _ = verify_authorization(
                &admitted.inventory,
                &admitted.inventory_sha256,
                &program,
                &admitted.trusted_key,
                1_000_000,
            )
            .expect_err("program tampering must fail");

            let mut revision = admitted.authorization.clone();
            revision.claims.fee_intent.sponsor_program_revision = Some(8);
            let _ = verify_authorization(
                &admitted.inventory,
                &admitted.inventory_sha256,
                &revision,
                &admitted.trusted_key,
                1_000_000,
            )
            .expect_err("program revision tampering must fail");
        }

        #[test]
        fn signed_reset_documents_require_explicit_nullable_fee_policy_slots() {
            let inventory = sample_inventory();
            let canonical: Value =
                json::from_slice(&canonical_inventory_bytes(&inventory).expect("inventory bytes"))
                    .expect("inventory JSON value");
            let fee_intent = canonical
                .as_object()
                .and_then(|object| object.get("fee_intent"))
                .and_then(norito::json::Value::as_object)
                .expect("fee-intent object");
            for field in ["sponsor_program", "sponsor_program_revision"] {
                assert!(
                    fee_intent
                        .get(field)
                        .is_some_and(norito::json::Value::is_null),
                    "authority fee intent must serialize `{field}` as explicit null"
                );
            }
            decode_inventory(
                &json::to_vec(&canonical).expect("inventory value bytes"),
                "inventory",
            )
            .expect("explicit nullable inventory slots");

            for field in ["sponsor_program", "sponsor_program_revision"] {
                let mut missing = canonical.clone();
                missing
                    .as_object_mut()
                    .and_then(|object| object.get_mut("fee_intent"))
                    .and_then(norito::json::Value::as_object_mut)
                    .expect("fee-intent object")
                    .remove(field);
                assert!(
                    decode_inventory(
                        &json::to_vec(&missing).expect("missing slot bytes"),
                        "inventory"
                    )
                    .is_err(),
                    "the signed V1 inventory must reject omitted `{field}`"
                );
            }

            let claims = sample_claims(&inventory, &"11".repeat(32));
            let canonical = json::to_value(&claims).expect("authorization claims JSON value");
            json::from_value::<AuthorizationClaimsV1>(canonical.clone())
                .expect("explicit nullable authorization-claim slots");
            for field in ["sponsor_program", "sponsor_program_revision"] {
                let mut missing = canonical.clone();
                missing
                    .as_object_mut()
                    .and_then(|object| object.get_mut("fee_intent"))
                    .and_then(norito::json::Value::as_object_mut)
                    .expect("authorization fee-intent object")
                    .remove(field);
                assert!(
                    json::from_value::<AuthorizationClaimsV1>(missing).is_err(),
                    "the signed V1 authorization must reject omitted `{field}`"
                );
            }
        }

        #[test]
        fn signed_faucet_policy_binds_authority_asset_and_amount() {
            let inventory = sample_inventory();
            let _chain_guard = enter_inventory_chain_discriminant(&inventory)
                .expect("admitted Taira address context");
            validate_faucet_policy(&inventory.faucet_policy)
                .expect("canonical faucet policy is admitted");

            let mut invalid_authority = inventory.faucet_policy.clone();
            invalid_authority.authority = "not-an-account".to_owned();
            let _error = validate_faucet_policy(&invalid_authority)
                .expect_err("invalid faucet authority must fail closed");

            let mut invalid_asset = inventory.faucet_policy.clone();
            invalid_asset.asset_definition_id = "xor#universal".to_owned();
            let _error = validate_faucet_policy(&invalid_asset)
                .expect_err("an alias or non-Taira faucet asset must fail closed");

            let mut zero_amount = inventory.faucet_policy.clone();
            zero_amount.amount = Quantity::zero();
            let _error = validate_faucet_policy(&zero_amount)
                .expect_err("zero faucet amount must fail closed");

            let admitted = signed_admitted(inventory, 1_000_000);
            let mut substituted = admitted.authorization.clone();
            substituted.claims.faucet_policy.amount = Quantity::from(1_u32);
            let _error = verify_authorization(
                &admitted.inventory,
                &admitted.inventory_sha256,
                &substituted,
                &admitted.trusted_key,
                1_000_000,
            )
            .expect_err("authorization faucet-policy substitution must fail closed");
        }

        #[test]
        fn fee_arguments_are_derived_only_from_the_signed_inventory() {
            let inventory = sample_inventory();
            assert_eq!(
                PublicResetApply::fee_args(&inventory).expect("authority args"),
                ["--fee-payer", "authority"]
                    .into_iter()
                    .map(std::ffi::OsString::from)
                    .collect::<Vec<_>>()
            );
            let mut invalid = inventory;
            invalid.fee_intent.sponsor_program = Some("unexpected".to_owned());
            let _ = PublicResetApply::fee_args(&invalid)
                .expect_err("authority cannot smuggle sponsor arguments");
        }

        #[test]
        fn fresh_and_forward_expiry_boundaries_are_exact() {
            let issued_at = 1_000_000;
            let admitted = signed_admitted(sample_inventory(), issued_at);
            let admission_expiry = admitted.authorization.claims.expires_at_unix_ms;
            verify_fresh_authorization(&admitted, admission_expiry - 1)
                .expect("last millisecond before admission expiry");
            let _ = verify_fresh_authorization(&admitted, admission_expiry)
                .expect_err("admission expiry instant bars a fresh start");
            let execution_expiry = admitted.authorization.claims.execution_expires_at_unix_ms;
            verify_forward_authorization(&admitted, execution_expiry - 1)
                .expect("last millisecond before execution expiry");
            let _ = verify_forward_authorization(&admitted, execution_expiry)
                .expect_err("execution expiry instant bars a new forward effect");
        }

        #[test]
        fn execution_lifetime_uses_the_exact_first_release_action_ledger() {
            let inventory = sample_inventory();
            let base = execution_lifetime_ms(&inventory).expect("base lifetime");
            let timeouts = &inventory.timeouts;
            let action_seconds = 46 * timeouts.install_secs
                + 4 * timeouts.stop_secs
                + 4 * timeouts.reset_secs
                + 2 * timeouts.preseed_secs
                + 4 * timeouts.start_secs
                + 10 * timeouts.edge_secs
                + 6 * timeouts.convergence_secs
                + 37 * timeouts.canary_secs
                + 4 * timeouts.restart_secs
                + 5 * timeouts.cleanup_secs
                + 5 * timeouts.rollback_secs;
            assert_eq!(
                base,
                action_seconds * 1_000 + MAX_AUTHORIZATION_LIFETIME_MS + EXECUTION_SAFETY_MARGIN_MS
            );

            macro_rules! assert_delta {
                ($field:ident, $coefficient:expr) => {{
                    let mut changed = inventory.clone();
                    changed.timeouts.$field += 1;
                    assert_eq!(
                        execution_lifetime_ms(&changed).expect("changed lifetime") - base,
                        $coefficient * 1_000,
                        stringify!($field)
                    );
                }};
            }
            assert_delta!(install_secs, 46);
            assert_delta!(stop_secs, 4);
            assert_delta!(reset_secs, 4);
            assert_delta!(preseed_secs, 2);
            assert_delta!(start_secs, 4);
            assert_delta!(edge_secs, 10);
            assert_delta!(convergence_secs, 6);
            assert_delta!(canary_secs, 37);
            assert_delta!(restart_secs, 4);
            assert_delta!(cleanup_secs, 5);
            assert_delta!(rollback_secs, 5);
            let additional_host_seconds = timeouts.install_secs + 2 * timeouts.preseed_secs;

            let mut boundary = inventory.clone();
            boundary.timeouts = TimeoutsV1 {
                stop_secs: 1,
                install_secs: 600,
                reset_secs: 1,
                preseed_secs: 3_600,
                start_secs: 1,
                convergence_secs: 1,
                canary_secs: 193,
                restart_secs: 1,
                edge_secs: 1,
                cleanup_secs: 1,
                rollback_secs: 1,
            };
            assert_eq!(
                execution_lifetime_ms(&boundary).expect("last bounded lifetime"),
                43_183_000
            );
            boundary.timeouts.canary_secs = 194;
            let _ = execution_lifetime_ms(&boundary)
                .expect_err("next exact action quantum exceeds twelve hours");

            let mut multi_host = sample_inventory();
            for (index, validator) in multi_host.validators.iter_mut().enumerate() {
                validator.endpoint.host_identity_sha256 = hex::encode([index as u8 + 1; 32]);
            }
            let multi_host_lifetime =
                execution_lifetime_ms(&multi_host).expect("four-host lifetime");
            assert_eq!(
                multi_host_lifetime - base,
                3 * additional_host_seconds * 1_000
            );
            multi_host.timeouts.install_secs += 1;
            assert_eq!(
                execution_lifetime_ms(&multi_host).expect("four-host install delta")
                    - multi_host_lifetime,
                49_000
            );
        }

        #[test]
        fn fresh_admission_expires_after_fifteen_minutes_but_durable_resume_uses_execution_lease() {
            let issued_at = 1_000_000;
            let admitted = signed_admitted(sample_inventory(), issued_at);
            let resume_at =
                admitted.authorization.claims.expires_at_unix_ms + MAX_CLOCK_SKEW_MS + 1;
            let _ = verify_authorization(
                &admitted.inventory,
                &admitted.inventory_sha256,
                &admitted.authorization,
                &admitted.trusted_key,
                resume_at,
            )
            .expect_err("fresh short-window admission must be expired");
            verify_execution_authorization(
                &admitted.inventory,
                &admitted.inventory_sha256,
                &admitted.authorization,
                &admitted.trusted_key,
                resume_at,
            )
            .expect("durable resume remains inside the signed execution lease");

            let directory = private_tempdir();
            let canonical = directory.path().canonicalize().expect("canonical tempdir");
            let seed = match DurableJournal::classify(&canonical, &admitted)
                .expect("fresh journal classification")
            {
                JournalOpen::Fresh(seed) => seed,
                JournalOpen::Resumable(_) => panic!("fresh authorization must not be resumable"),
            };
            let journal = DurableJournal::initialize(seed, &admitted).expect("initialize journal");
            drop(journal);
            let resumed = match DurableJournal::classify(&canonical, &admitted)
                .expect("durable journal classification")
            {
                JournalOpen::Fresh(_) => panic!("durable journal must classify as resumable"),
                JournalOpen::Resumable(journal) => journal,
            };
            assert_eq!(resumed.resume_disposition(), ResumeDisposition::Forward);
        }

        #[test]
        fn completed_receipt_rejects_replay() {
            let directory = private_tempdir();
            let admitted = admitted(sample_inventory());
            let completed = directory.path().join("completed");
            fs::create_dir(&completed).expect("completed");
            #[cfg(unix)]
            fs::set_permissions(&completed, fs::Permissions::from_mode(0o700)).expect("mode");
            let receipt = completed.join(format!("{}.json", admitted.authorization_sha256));
            fs::write(&receipt, b"{}\n").expect("receipt");
            let canonical = directory.path().canonicalize().expect("canonical tempdir");
            assert!(
                DurableJournal::open(&canonical, &admitted).is_err(),
                "replay must fail"
            );
        }

        #[test]
        fn journal_root_is_one_fixed_absolute_normal_namespace() {
            assert_eq!(
                JOURNAL_ROOT,
                "/private/runtime/taira-public-reset/journal-v1"
            );
            validate_absolute_normal_path(Path::new(JOURNAL_ROOT), "journal root")
                .expect("fixed journal root");
        }

        #[test]
        fn journal_lock_rejects_concurrent_same_authorization_admission() {
            let directory = private_tempdir();
            let canonical = directory.path().canonicalize().expect("canonical tempdir");
            let admitted = admitted(sample_inventory());
            let first = DurableJournal::classify(&canonical, &admitted)
                .expect("first admission holds the lock");
            assert!(matches!(&first, JournalOpen::Fresh(_)));
            assert!(
                DurableJournal::classify(&canonical, &admitted).is_err(),
                "concurrent admission must fail while the lock is held"
            );
            drop(first);
        }

        #[test]
        fn journal_lock_release_does_not_wait_for_duplicated_descriptors() {
            for initialized in [false, true] {
                let directory = private_tempdir();
                let canonical = directory.path().canonicalize().expect("canonical tempdir");
                let admitted = admitted(sample_inventory());
                let seed = match DurableJournal::classify(&canonical, &admitted)
                    .expect("fresh admission holds the lock")
                {
                    JournalOpen::Fresh(seed) => seed,
                    JournalOpen::Resumable(_) => panic!("new directory must be fresh"),
                };
                let first = if initialized {
                    JournalOpen::Resumable(
                        DurableJournal::initialize(seed, &admitted).expect("initialize journal"),
                    )
                } else {
                    JournalOpen::Fresh(seed)
                };
                // A duplicate retains the same open file description as a child
                // forked by another thread before CLOEXEC takes effect.
                let duplicate = match &first {
                    JournalOpen::Fresh(seed) => seed._lock.file.try_clone(),
                    JournalOpen::Resumable(journal) => journal._lock.file.try_clone(),
                }
                .expect("duplicate lock descriptor");
                for _ in 0..2 {
                    assert!(
                        DurableJournal::classify(&canonical, &admitted).is_err(),
                        "failed contenders must leave the active owner's lock intact"
                    );
                }
                drop(first);
                let replacement = DurableJournal::classify(&canonical, &admitted)
                    .expect("owner release must unlock even while a duplicate remains open");
                assert_eq!(
                    matches!(&replacement, JournalOpen::Resumable(_)),
                    initialized
                );
                drop(duplicate);
                assert!(
                    DurableJournal::classify(&canonical, &admitted).is_err(),
                    "closing the old duplicate must not release the replacement owner's lock"
                );
                drop(replacement);
                DurableJournal::classify(&canonical, &admitted)
                    .expect("replacement owner releases its lock");
            }
        }

        #[test]
        fn untouched_expiry_abort_rejects_old_replay_and_permits_new_authorization() {
            let directory = private_tempdir();
            let canonical = directory.path().canonicalize().expect("canonical tempdir");
            let old = signed_admitted(sample_inventory(), 1_000_000);
            let mut journal = DurableJournal::open(&canonical, &old).expect("old journal");
            journal
                .abort_before_mutation()
                .expect("durable untouched abort");
            drop(journal);
            assert!(
                DurableJournal::classify(&canonical, &old).is_err(),
                "aborted authorization replay must fail"
            );

            let mut next_inventory = sample_inventory();
            next_inventory.authorization_nonce = "zyxwvutsrqponmlkjihgfedc87654321".to_owned();
            let next = signed_admitted(next_inventory, 2_000_000);
            assert_ne!(old.authorization_sha256, next.authorization_sha256);
            assert!(matches!(
                DurableJournal::classify(&canonical, &next)
                    .expect("new exact authorization may acquire the deployment"),
                JournalOpen::Fresh(_)
            ));
        }

        #[test]
        fn every_classifier_reachable_recovery_phase_reopens_with_exact_cursor() {
            for step in [ExecutionStep::Canary] {
                let directory = private_tempdir();
                let canonical = directory.path().canonicalize().expect("canonical tempdir");
                let admitted = admitted(sample_inventory());
                let mut journal = DurableJournal::open(&canonical, &admitted).expect("journal");
                let mut state = journal.state().clone();
                state.status = "recovery_pending".to_owned();
                state.phase = step.label().to_owned();
                state.next_step = u16::try_from(
                    FULL_INROU_EXECUTION_STEPS
                        .iter()
                        .position(|candidate| *candidate == step)
                        .expect("step index"),
                )
                .expect("bounded index");
                state.recovery_intent = Some(test_recovery_intent(step));
                state.touched_validators = VALIDATOR_SLUGS
                    .iter()
                    .map(|slug| (*slug).to_owned())
                    .collect();
                state.edge_touched = step == ExecutionStep::EdgeVerify;
                journal.replace(state).expect("persist prepared recovery");
                let mut progress = JournalRecoveryProgress {
                    journal: &mut journal,
                    step,
                };
                progress
                    .mark_submitted(0)
                    .expect("persist submitted cursor");
                drop(progress);
                drop(journal);

                let resumed = match DurableJournal::classify(&canonical, &admitted)
                    .expect("reopen exact recovery phase")
                {
                    JournalOpen::Fresh(_) => panic!("recovery phase cannot become fresh"),
                    JournalOpen::Resumable(journal) => journal,
                };
                assert_eq!(
                    resumed.resume_disposition(),
                    ResumeDisposition::RecoveryPending
                );
                let intent = resumed
                    .state()
                    .recovery_intent
                    .as_ref()
                    .expect("recovery intent");
                assert_eq!(intent.next_mutation, 0);
                assert_eq!(
                    intent.mutations[0].state,
                    RecoveryMutationStateV1::Submitted
                );
            }
        }

        #[test]
        fn ordinary_successor_checkpoint_reopens_at_exact_next_phase() {
            let admitted = admitted(sample_inventory());
            let directory = private_tempdir();
            let canonical = directory.path().canonicalize().expect("canonical tempdir");
            let journal = DurableJournal::open(&canonical, &admitted).expect("journal");
            let mut crashing = CrashAfterDurableSuccessor {
                journal,
                next_step: 1,
                crashed: false,
            };
            let mut first = MockTransport::default();
            let error = execute_plan(&admitted.inventory, &mut first, &mut crashing)
                .expect_err("simulated crash must stop after the durable successor publish");
            assert!(format!("{error:#}").contains("injected crash after durable successor"));
            assert_eq!(crashing.state().status, "in_progress");
            assert_eq!(crashing.state().next_step, 1);
            assert_eq!(crashing.state().phase, ExecutionStep::Stage.label());
            drop(crashing);

            let mut resumed = match DurableJournal::classify(&canonical, &admitted)
                .expect("ordinary successor must reopen")
            {
                JournalOpen::Fresh(_) => panic!("durable successor cannot become fresh"),
                JournalOpen::Resumable(journal) => journal,
            };
            assert_eq!(resumed.resume_disposition(), ResumeDisposition::Forward);
            assert_eq!(resumed.state().next_step, 1);
            assert_eq!(resumed.state().phase, ExecutionStep::Stage.label());
            let mut retry = MockTransport::default();
            execute_plan(&admitted.inventory, &mut retry, &mut resumed)
                .expect("exact ordinary successor resumes");
            assert_eq!(
                retry.events.first().map(String::as_str),
                Some("stage:taira-validator-1")
            );
        }

        #[test]
        fn applied_recovery_successor_checkpoint_reopens_at_exact_next_phase() {
            let admitted = admitted(sample_inventory());
            let directory = private_tempdir();
            let canonical = directory.path().canonicalize().expect("canonical tempdir");
            let mut journal = DurableJournal::open(&canonical, &admitted).expect("journal");
            let step = ExecutionStep::Canary;
            let step_index = FULL_INROU_EXECUTION_STEPS
                .iter()
                .position(|candidate| *candidate == step)
                .expect("canary index");
            let mut intent = test_recovery_intent(step);
            for mutation in &mut intent.mutations {
                mutation.state = RecoveryMutationStateV1::Applied;
            }
            intent.next_mutation =
                u16::try_from(intent.mutations.len()).expect("bounded mutation count");
            let mut pending = journal.state().clone();
            pending.status = "recovery_pending".to_owned();
            pending.phase = step.label().to_owned();
            pending.next_step = u16::try_from(step_index).expect("bounded step index");
            pending.recovery_intent = Some(intent);
            pending.touched_validators = VALIDATOR_SLUGS
                .iter()
                .map(|slug| (*slug).to_owned())
                .collect();
            pending.edge_touched = false;
            journal
                .replace(pending)
                .expect("persist applied recovery boundary");

            let mut recovery = MockTransport::default();
            let error = execute_plan(&admitted.inventory, &mut recovery, &mut journal)
                .expect_err("applied recovery stops at its durable successor");
            assert!(format!("{error:#}").contains("resume from its durable successor"));
            assert_eq!(recovery.events, ["recover:canary"]);
            assert_eq!(journal.state().status, "in_progress");
            assert_eq!(usize::from(journal.state().next_step), step_index + 1);
            assert_eq!(journal.state().phase, ExecutionStep::Convergence.label());
            assert!(
                !journal.state().edge_touched,
                "candidate replay cannot establish public edge custody"
            );
            drop(journal);

            let resumed = match DurableJournal::classify(&canonical, &admitted)
                .expect("recovered successor must reopen")
            {
                JournalOpen::Fresh(_) => panic!("recovered successor cannot become fresh"),
                JournalOpen::Resumable(journal) => journal,
            };
            assert_eq!(resumed.resume_disposition(), ResumeDisposition::Forward);
            assert_eq!(usize::from(resumed.state().next_step), step_index + 1);
            assert_eq!(resumed.state().phase, ExecutionStep::Convergence.label());
        }

        #[test]
        fn crash_recovery_resumes_at_recorded_step() {
            let (inventory, mut journal) = journal(sample_inventory());
            journal.state.next_step = u16::try_from(
                execution_steps(inventory.qualification_scope)
                    .iter()
                    .position(|step| *step == ExecutionStep::Install)
                    .unwrap(),
            )
            .unwrap();
            journal.state.phase = ExecutionStep::Install.label().to_owned();
            journal.state.touched_validators = VALIDATOR_SLUGS
                .iter()
                .map(|slug| (*slug).to_owned())
                .collect();
            let mut transport = MockTransport::default();
            execute_plan(&inventory, &mut transport, &mut journal).expect("resume succeeds");
            assert!(journal.finished);
            assert_eq!(
                transport.events.first().map(String::as_str),
                Some("install:taira-validator-1")
            );
        }

        #[test]
        fn partial_cohort_failure_rolls_back_in_reverse_touch_order() {
            let (inventory, mut journal) = journal(sample_inventory());
            let mut transport = MockTransport {
                fail: Some("stop:taira-validator-2".to_owned()),
                ..MockTransport::default()
            };
            let _ =
                execute_plan(&inventory, &mut transport, &mut journal).expect_err("stop failure");
            let tail = &transport.events[transport.events.len() - 2..];
            assert_eq!(
                tail,
                ["rollback:taira-validator-2", "rollback:taira-validator-1"]
            );
            assert_eq!(journal.state.status, "rolled_back");
        }

        #[test]
        fn missing_forward_inputs_use_rollback_only_path_for_recorded_hosts() {
            let (inventory, mut journal) = journal(sample_inventory());
            journal.state.next_step = u16::try_from(
                execution_steps(inventory.qualification_scope)
                    .iter()
                    .position(|step| *step == ExecutionStep::Install)
                    .unwrap(),
            )
            .unwrap();
            journal.state.phase = ExecutionStep::Install.label().to_owned();
            journal.state.touched_validators = VALIDATOR_SLUGS[..2]
                .iter()
                .map(|slug| (*slug).to_owned())
                .collect();
            let missing = eyre!("signed candidate artifact is no longer available");
            begin_rollback_after_preparation_failure(&mut journal, &missing)
                .expect("durably enter rollback");
            let mut rollback_only = MockTransport::default();
            let _ = resume_rollback_after_preparation_failure(
                &inventory,
                &mut rollback_only,
                &mut journal,
                missing,
            )
            .expect_err("the original forward failure remains visible");
            assert_eq!(
                rollback_only.events,
                ["rollback:taira-validator-2", "rollback:taira-validator-1"]
            );
            assert_eq!(journal.state.status, "rolled_back");
        }

        #[test]
        fn ambiguous_local_mutation_uses_only_read_only_recovery_before_resume() {
            let (inventory, mut journal) = journal(sample_inventory());
            let mut ambiguous = MockTransport {
                fail: Some("canary".to_owned()),
                ..MockTransport::default()
            };
            let _ = execute_plan_with_recovery_classifier(
                &inventory,
                &mut ambiguous,
                &mut journal,
                |_| true,
            )
            .expect_err("ambiguous canary must fail stop");
            assert_eq!(journal.state.status, "recovery_pending");
            assert_eq!(journal.state.phase, "canary");
            assert_eq!(
                usize::from(journal.state.next_step),
                FULL_INROU_EXECUTION_STEPS
                    .iter()
                    .position(|step| *step == ExecutionStep::Canary)
                    .expect("canary step")
            );
            assert!(
                ambiguous
                    .events
                    .iter()
                    .all(|event| !event.starts_with("rollback:"))
            );

            let mut retry = MockTransport::default();
            let _ =
                execute_plan_with_recovery_classifier(&inventory, &mut retry, &mut journal, |_| {
                    false
                })
                .expect_err("applied recovery persists one successor and stops");
            assert_eq!(retry.events, ["recover:canary"]);
            assert_eq!(journal.state.status, "in_progress");
            assert!(journal.state.recovery_intent.is_none());

            let mut resumed = MockTransport::default();
            execute_plan(&inventory, &mut resumed, &mut journal).expect("successor resumes");
            assert!(
                resumed.events.iter().all(|event| event != "canary"),
                "recovery must never resubmit the ambiguous canary step"
            );
            assert_eq!(journal.state.status, "completed");
        }

        #[test]
        fn submitted_child_failures_preserve_parent_intent_until_read_only_recovery() {
            fn timeout() -> Result<host::PreparedMutationOutcome> {
                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "child deadline").into())
            }
            fn lost_response() -> Result<host::PreparedMutationOutcome> {
                Err(eyre!("child exited without an authenticated response"))
            }
            fn receipt_failure() -> Result<host::PreparedMutationOutcome> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Applied receipt publication failed",
                )
                .into())
            }
            fn pending() -> Result<host::PreparedMutationOutcome> {
                Ok(host::PreparedMutationOutcome::Pending)
            }
            let failures: [fn() -> Result<host::PreparedMutationOutcome>; 4] =
                [timeout, lost_response, receipt_failure, pending];
            for step in [ExecutionStep::Canary] {
                for failure in failures {
                    let (inventory, mut journal) = journal(sample_inventory());
                    let mut transport = MockTransport {
                        submitted_step: Some(step),
                        submitted_outcome: Some(failure),
                        ..MockTransport::default()
                    };
                    let error = execute_plan(&inventory, &mut transport, &mut journal)
                        .expect_err("a submitted child remains ambiguous");
                    assert!(host::is_local_mutation_recovery_pending(&error));
                    assert_eq!(journal.state.status, "recovery_pending");
                    assert_eq!(journal.state.phase, step.label());
                    assert!(!journal.finished);
                    assert!(
                        !transport
                            .events
                            .iter()
                            .any(|event| event.starts_with("rollback:"))
                    );
                    assert_eq!(
                        transport
                            .events
                            .iter()
                            .filter(|event| event.starts_with("dispatch:"))
                            .count(),
                        1
                    );

                    let mut expected = test_recovery_intent(step);
                    let last = expected.mutations.len() - 1;
                    for mutation in &mut expected.mutations[..last] {
                        mutation.state = RecoveryMutationStateV1::Applied;
                    }
                    expected.mutations[last].state = RecoveryMutationStateV1::Submitted;
                    expected.next_mutation = u16::try_from(last).unwrap();
                    assert_eq!(
                        journal.state.recovery_intent.as_ref(),
                        Some(&expected),
                        "retain exact phase, kind, idempotency key and receipt identities"
                    );

                    let mut recovery = MockTransport::default();
                    let _ = execute_plan(&inventory, &mut recovery, &mut journal)
                        .expect_err("read-only proof publishes the successor and stops");
                    assert_eq!(recovery.events, [format!("recover:{}", step.label())]);
                    assert!(journal.state.recovery_intent.is_none());
                    assert_eq!(
                        usize::from(journal.state.next_step),
                        FULL_INROU_EXECUTION_STEPS
                            .iter()
                            .position(|candidate| *candidate == step)
                            .unwrap()
                            + 1
                    );

                    let mut successor = MockTransport::default();
                    execute_plan(&inventory, &mut successor, &mut journal)
                        .expect("resume proven successor");
                    assert_eq!(journal.state.status, "completed");
                    assert!(
                        !successor.events.iter().any(|event| event == step.label()
                            || event.starts_with("dispatch:")
                            || event.starts_with("rollback:")),
                        "recovery must never resubmit the completed child or step"
                    );
                }
            }
        }

        #[test]
        fn beacon_submitted_continuation_retains_exact_host_cursor_and_excludes_ledger_work() {
            let (inventory, mut journal) = journal(sample_inventory());
            let step = ExecutionStep::Canary;
            let mut intent = host::build_recovery_intent(&inventory, step).unwrap();
            intent.next_mutation = 4;
            for previous in &mut intent.mutations[..4] {
                previous.state = RecoveryMutationStateV1::Applied;
            }
            intent.mutations[4].state = RecoveryMutationStateV1::Submitted;
            assert!(recovery_ready_to_resume_beacon_activation(&intent, step));
            assert!(!recovery_ready_to_continue(&intent, step));
            journal.state.status = "recovery_pending".into();
            journal.state.phase = step.label().into();
            journal.state.next_step = u16::try_from(
                execution_steps(inventory.qualification_scope)
                    .iter()
                    .position(|value| *value == step)
                    .unwrap(),
            )
            .unwrap();
            journal.state.recovery_intent = Some(intent.clone());
            let before = journal.state.clone();
            let mut transport = MockTransport {
                recovery_outcome: Some(RecoveryOutcome::ResumeSubmittedBeaconActivation),
                ..MockTransport::default()
            };
            assert!(recover_pending_step(&inventory, &mut transport, &mut journal).is_err());
            assert_eq!(journal.state.status, "in_progress");
            assert_eq!(journal.state.recovery_intent, before.recovery_intent);
            assert!(valid_recovery_intent_transition(&before, &journal.state));
            assert!(transport.mutation_dispatches.is_empty());
            for kind in [
                "onboarding",
                "faucet",
                "write_canary",
                "beacon_install",
                "host_restart",
                "beacon_provider_2",
            ] {
                let mut wrong = intent.clone();
                wrong.mutations[4].kind = kind.into();
                assert!(
                    !recovery_ready_to_resume_beacon_activation(&wrong, step),
                    "{kind}"
                );
            }
            let mut wrong = intent.clone();
            wrong.mutations[4].phase = "post_edge".into();
            assert!(!recovery_ready_to_resume_beacon_activation(&wrong, step));
            let mut wrong = intent;
            wrong.mutations[4].state = RecoveryMutationStateV1::Prepared;
            assert!(!recovery_ready_to_resume_beacon_activation(&wrong, step));
        }

        #[test]
        fn beacon_continuation_outcome_cannot_reclassify_submitted_ledger_transaction() {
            let (inventory, mut journal) = journal(sample_inventory());
            let step = ExecutionStep::Canary;
            let mut intent = host::build_recovery_intent(&inventory, step).unwrap();
            intent.next_mutation = 3;
            for previous in &mut intent.mutations[..3] {
                previous.state = RecoveryMutationStateV1::Applied;
            }
            intent.mutations[3].state = RecoveryMutationStateV1::Submitted;
            journal.state.status = "recovery_pending".into();
            journal.state.phase = step.label().into();
            journal.state.next_step = u16::try_from(
                execution_steps(inventory.qualification_scope)
                    .iter()
                    .position(|value| *value == step)
                    .unwrap(),
            )
            .unwrap();
            journal.state.recovery_intent = Some(intent.clone());
            let mut transport = MockTransport {
                recovery_outcome: Some(RecoveryOutcome::ResumeSubmittedBeaconActivation),
                ..MockTransport::default()
            };
            assert!(recover_pending_step(&inventory, &mut transport, &mut journal).is_err());
            assert_eq!(journal.state.status, "recovery_pending");
            assert_eq!(journal.state.recovery_intent, Some(intent));
            assert!(transport.mutation_dispatches.is_empty());
        }

        #[test]
        fn authenticated_submitted_child_rejection_remains_terminal() {
            fn rejected() -> Result<host::PreparedMutationOutcome> {
                Ok(host::PreparedMutationOutcome::Rejected(
                    "Rejected".to_owned(),
                ))
            }
            for step in [ExecutionStep::Canary] {
                let (inventory, mut journal) = journal(sample_inventory());
                let mut transport = MockTransport {
                    submitted_step: Some(step),
                    submitted_outcome: Some(rejected),
                    ..MockTransport::default()
                };
                let error = execute_plan(&inventory, &mut transport, &mut journal)
                    .expect_err("authenticated rejection permits rollback");
                assert!(!host::is_local_mutation_recovery_pending(&error));
                assert_eq!(journal.state.status, "rolled_back");
                assert!(
                    transport
                        .events
                        .iter()
                        .any(|event| event.starts_with("rollback:"))
                );
                assert!(
                    !transport
                        .events
                        .iter()
                        .any(|event| event.starts_with("recover:"))
                );
            }
        }

        pub(crate) fn assert_core_recovery_rejection_for_test(class: &str) {
            let (inventory, mut journal) = journal(sample_inventory());
            let step = ExecutionStep::Canary;
            let mut intent = test_recovery_intent(step);
            let last = intent.mutations.len() - 1;
            for mutation in &mut intent.mutations[..last] {
                mutation.state = RecoveryMutationStateV1::Applied;
            }
            intent.mutations[last].state = RecoveryMutationStateV1::Submitted;
            intent.next_mutation = u16::try_from(last).unwrap();
            journal.state.status = "recovery_pending".to_owned();
            journal.state.phase = step.label().to_owned();
            journal.state.next_step = u16::try_from(
                FULL_INROU_EXECUTION_STEPS
                    .iter()
                    .position(|candidate| *candidate == step)
                    .unwrap(),
            )
            .unwrap();
            journal.state.recovery_intent = Some(intent);
            journal.state.touched_validators = VALIDATOR_SLUGS.map(str::to_owned).to_vec();
            let mut recovery = MockTransport {
                recovery_outcome: Some(RecoveryOutcome::Rejected(class.to_owned())),
                ..MockTransport::default()
            };
            let _ = execute_plan(&inventory, &mut recovery, &mut journal)
                .expect_err("authenticated rejection publishes rollback-only successor");
            assert_eq!(recovery.events, ["recover:canary"]);
            assert_eq!(journal.state.status, "rolling_back");
            assert!(journal.state.recovery_intent.is_none());
            let mut rollback = MockTransport::default();
            let _ = execute_plan(&inventory, &mut rollback, &mut journal)
                .expect_err("rollback reports the rejected release outcome");
            assert_eq!(journal.state.status, "rolled_back");
            assert_eq!(rollback.events.len(), VALIDATOR_SLUGS.len());
            assert!(
                rollback
                    .events
                    .iter()
                    .all(|event| event.starts_with("rollback:"))
            );
        }

        #[test]
        fn pending_recovery_never_runs_the_normal_submit_path() {
            let (inventory, mut journal) = journal(sample_inventory());
            let step = ExecutionStep::Canary;
            journal.state.status = "recovery_pending".to_owned();
            journal.state.phase = step.label().to_owned();
            journal.state.next_step = u16::try_from(
                FULL_INROU_EXECUTION_STEPS
                    .iter()
                    .position(|candidate| *candidate == step)
                    .expect("canary index"),
            )
            .expect("bounded index");
            let mut intent = test_recovery_intent(step);
            intent.mutations[0].state = RecoveryMutationStateV1::Submitted;
            journal.state.recovery_intent = Some(intent.clone());
            let mut transport = MockTransport {
                recovery_outcome: Some(RecoveryOutcome::Pending),
                ..MockTransport::default()
            };
            let _ = execute_plan(&inventory, &mut transport, &mut journal)
                .expect_err("pending lookup remains pending");
            assert_eq!(transport.events, ["recover:canary"]);
            assert_eq!(journal.state.status, "recovery_pending");
            assert_eq!(journal.state.recovery_intent, Some(intent));
        }

        #[test]
        fn never_attempted_next_mutation_preserves_authorized_continuation() {
            let (inventory, mut journal) = journal(sample_inventory());
            let step = ExecutionStep::Canary;
            journal.state.status = "recovery_pending".to_owned();
            journal.state.phase = step.label().to_owned();
            journal.state.next_step = u16::try_from(
                FULL_INROU_EXECUTION_STEPS
                    .iter()
                    .position(|candidate| *candidate == step)
                    .expect("canary index"),
            )
            .expect("bounded index");
            journal.state.touched_validators = VALIDATOR_SLUGS
                .iter()
                .map(|slug| (*slug).to_owned())
                .collect();
            let mut intent = test_recovery_intent(step);
            intent.mutations[0].state = RecoveryMutationStateV1::Applied;
            intent.next_mutation = 1;
            journal.state.recovery_intent = Some(intent.clone());
            let mut transport = MockTransport::default();
            let _ = execute_plan(&inventory, &mut transport, &mut journal)
                .expect_err("read-only recovery must stop before ordinary forward continuation");
            assert_eq!(transport.events, ["recover:canary"]);
            assert!(transport.mutation_dispatches.is_empty());
            assert_eq!(journal.state.status, "in_progress");
            assert_eq!(journal.state.recovery_intent, Some(intent));
        }

        #[test]
        fn recovered_partial_mutation_reopens_and_dispatches_only_prepared_suffix() {
            for step in [ExecutionStep::Canary] {
                let count = test_recovery_intent(step).mutations.len();
                for submitted in 0..count - 1 {
                    let admitted = signed_admitted(sample_inventory(), 1_000_000);
                    let directory = private_tempdir();
                    let canonical = directory.path().canonicalize().unwrap();
                    let mut journal = DurableJournal::open(&canonical, &admitted).unwrap();
                    let mut intent = test_recovery_intent(step);
                    for mutation in &mut intent.mutations[..submitted] {
                        mutation.state = RecoveryMutationStateV1::Applied;
                    }
                    intent.mutations[submitted].state = RecoveryMutationStateV1::Submitted;
                    intent.next_mutation = u16::try_from(submitted).unwrap();
                    let mut state = journal.state().clone();
                    state.status = "recovery_pending".to_owned();
                    state.phase = step.label().to_owned();
                    state.next_step = u16::try_from(
                        FULL_INROU_EXECUTION_STEPS
                            .iter()
                            .position(|s| *s == step)
                            .unwrap(),
                    )
                    .unwrap();
                    state.touched_validators = VALIDATOR_SLUGS.map(str::to_owned).to_vec();
                    state.edge_touched = step == ExecutionStep::EdgeVerify;
                    state.recovery_intent = Some(intent.clone());
                    journal.replace(state).unwrap();
                    let outer_cursor = journal.state().next_step;
                    let mut observer = MockTransport::default();
                    let _ = execute_plan(&admitted.inventory, &mut observer, &mut journal)
                        .expect_err("observation must stop before forward siblings");
                    assert!(observer.mutation_dispatches.is_empty());
                    assert_eq!(observer.events, [format!("recover:{}", step.label())]);
                    intent.mutations[submitted].state = RecoveryMutationStateV1::Applied;
                    intent.next_mutation += 1;
                    assert_eq!(journal.state().recovery_intent.as_ref(), Some(&intent));
                    assert_eq!(journal.state().next_step, outer_cursor);
                    assert_eq!(journal.state().status, "in_progress");
                    let mut invalid = journal.state().clone();
                    invalid.recovery_intent.as_mut().unwrap().mutations[submitted + 1].state =
                        RecoveryMutationStateV1::Submitted;
                    assert!(
                        validate_resumable_journal(&invalid, journal.state()).is_err(),
                        "Submitted frontier cannot select ordinary Forward custody"
                    );
                    invalid = journal.state().clone();
                    invalid.recovery_intent.as_mut().unwrap().mutations[submitted].state =
                        RecoveryMutationStateV1::Prepared;
                    assert!(
                        validate_resumable_journal(&invalid, journal.state()).is_err(),
                        "Applied prefix cannot be forgotten"
                    );
                    invalid = journal.state().clone();
                    invalid.recovery_intent.as_mut().unwrap().mutations[submitted + 1]
                        .idempotency_key = "f".repeat(64);
                    assert!(
                        !valid_journal_successor(journal.state(), &invalid),
                        "retained mutation identity cannot change across continuation"
                    );
                    drop(journal);
                    let mut journal = match DurableJournal::classify(&canonical, &admitted).unwrap()
                    {
                        JournalOpen::Resumable(journal) => journal,
                        JournalOpen::Fresh(_) => panic!("partial recovery cannot reopen fresh"),
                    };
                    assert_eq!(journal.resume_disposition(), ResumeDisposition::Forward);
                    assert_eq!(journal.state().recovery_intent.as_ref(), Some(&intent));
                    let expires = admitted.authorization.claims.execution_expires_at_unix_ms;
                    verify_forward_authorization(&admitted, expires - 1).unwrap();
                    let mut forward = MockTransport::default();
                    execute_plan(&admitted.inventory, &mut forward, &mut journal).unwrap();
                    assert_eq!(
                        forward
                            .mutation_dispatches
                            .iter()
                            .filter(|(s, _)| *s == step)
                            .map(|(_, index)| *index)
                            .collect::<Vec<_>>(),
                        (submitted + 1..count).collect::<Vec<_>>()
                    );
                    assert!(
                        !forward
                            .events
                            .iter()
                            .any(|event| event.starts_with("rollback:"))
                    );
                    assert_eq!(journal.state().status, "completed");
                }
            }
        }

        #[test]
        fn partial_mutation_continuation_rejects_expired_forward_authorization() {
            let admitted = signed_admitted(sample_inventory(), 1_000_000);
            let (_, mut journal) = journal(admitted.inventory.clone());
            let step = ExecutionStep::Canary;
            let mut intent = test_recovery_intent(step);
            intent.mutations[0].state = RecoveryMutationStateV1::Submitted;
            journal.state.status = "recovery_pending".to_owned();
            journal.state.phase = step.label().to_owned();
            journal.state.next_step = u16::try_from(
                FULL_INROU_EXECUTION_STEPS
                    .iter()
                    .position(|s| *s == step)
                    .unwrap(),
            )
            .unwrap();
            journal.state.touched_validators = VALIDATOR_SLUGS.map(str::to_owned).to_vec();
            journal.state.recovery_intent = Some(intent);
            let mut observer = MockTransport::default();
            let _ = execute_plan(&admitted.inventory, &mut observer, &mut journal)
                .expect_err("stop after exact proof");
            assert_eq!(journal.state.status, "in_progress");
            let expiry = admitted.authorization.claims.execution_expires_at_unix_ms;
            let error = verify_forward_authorization(&admitted, expiry)
                .expect_err("original expiry cannot be refreshed");
            begin_rollback_after_preparation_failure(&mut journal, &error).unwrap();
            let mut rollback = MockTransport::default();
            let _ = execute_plan(&admitted.inventory, &mut rollback, &mut journal)
                .expect_err("expired continuation rolls back");
            assert!(rollback.mutation_dispatches.is_empty());
            assert!(
                rollback
                    .events
                    .iter()
                    .all(|event| event.starts_with("rollback:"))
            );
            assert_eq!(journal.state.status, "rolled_back");
        }

        #[test]
        fn outer_step_cannot_advance_until_every_mutation_is_applied() {
            let (inventory, mut journal) = journal(sample_inventory());
            let step = ExecutionStep::Canary;
            journal.state.status = "recovery_pending".to_owned();
            journal.state.phase = step.label().to_owned();
            journal.state.next_step = u16::try_from(
                FULL_INROU_EXECUTION_STEPS
                    .iter()
                    .position(|candidate| *candidate == step)
                    .expect("canary index"),
            )
            .expect("bounded index");
            let mut intent = test_recovery_intent(step);
            intent.mutations[0].state = RecoveryMutationStateV1::Submitted;
            journal.state.recovery_intent = Some(intent);
            let mut transport = MockTransport {
                recovery_outcome: Some(RecoveryOutcome::Applied),
                ..MockTransport::default()
            };
            let _ = execute_plan(&inventory, &mut transport, &mut journal)
                .expect_err("premature Applied outcome must fail closed");
            assert_eq!(transport.events, ["recover:canary"]);
            assert_eq!(journal.state.status, "recovery_pending");
            assert_eq!(
                FULL_INROU_EXECUTION_STEPS[usize::from(journal.state.next_step)],
                ExecutionStep::Canary
            );
        }

        #[test]
        fn seal_failure_is_resumable_and_never_rolls_back_proven_deployment() {
            let (inventory, mut journal) = journal(sample_inventory());
            let mut first = MockTransport {
                fail: Some("seal".to_owned()),
                ..MockTransport::default()
            };
            let _ = execute_plan(&inventory, &mut first, &mut journal)
                .expect_err("seal distribution failure must fail stop");
            assert_eq!(journal.state.status, "sealing");
            assert_eq!(journal.state.phase, "seal");
            assert_eq!(
                usize::from(journal.state.next_step),
                FULL_INROU_EXECUTION_STEPS.len() - 2
            );
            assert!(
                first
                    .events
                    .iter()
                    .all(|event| !event.starts_with("rollback:"))
            );
            let _ = begin_rollback_after_preparation_failure(
                &mut journal,
                &eyre!("forward inputs vanished after proof"),
            )
            .expect_err("deployment-proven sealing state must reject rollback transition");
            assert_eq!(journal.state.status, "sealing");

            let mut retry = MockTransport::default();
            execute_plan(&inventory, &mut retry, &mut journal).expect("seal retry succeeds");
            assert_eq!(retry.events.first().map(String::as_str), Some("seal"));
            assert_eq!(journal.state.status, "completed");
        }

        #[test]
        fn stage_drift_fails_before_any_mutation() {
            let (inventory, mut journal) = journal(sample_inventory());
            let mut transport = MockTransport {
                fail: Some("preflight:taira-validator-1".to_owned()),
                ..MockTransport::default()
            };
            let _ = execute_plan(&inventory, &mut transport, &mut journal)
                .expect_err("preflight drift");
            assert!(journal.state.touched_validators.is_empty());
            assert!(!journal.state.edge_touched);
            assert!(
                transport
                    .events
                    .iter()
                    .all(|event| !event.starts_with("rollback:"))
            );
        }

        #[test]
        fn partial_stage_failure_rolls_back_recorded_candidate_targets() {
            let (inventory, mut journal) = journal(sample_inventory());
            let mut transport = MockTransport {
                fail: Some("stage:taira-validator-2".to_owned()),
                ..MockTransport::default()
            };
            let _ = execute_plan(&inventory, &mut transport, &mut journal)
                .expect_err("partial staging must roll back exact recorded targets");
            let rollback = transport
                .events
                .iter()
                .filter(|event| event.starts_with("rollback:"))
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(
                rollback,
                ["rollback:taira-validator-2", "rollback:taira-validator-1"]
            );
            assert_eq!(journal.state.status, "rolled_back");
        }

        #[test]
        fn edge_preflight_failure_precedes_every_mutation() {
            let (inventory, mut journal) = journal(sample_inventory());
            let mut transport = MockTransport {
                fail: Some("preflight".to_owned()),
                ..MockTransport::default()
            };
            let _ = execute_plan(&inventory, &mut transport, &mut journal)
                .expect_err("edge preflight drift");
            assert_eq!(
                transport.events,
                [
                    "preflight:taira-validator-1",
                    "preflight:taira-validator-2",
                    "preflight:taira-validator-3",
                    "preflight:taira-validator-4",
                    "preflight",
                ]
            );
            assert!(journal.state.touched_validators.is_empty());
            assert!(!journal.state.edge_touched);
        }

        #[test]
        fn edge_failure_rolls_back_edge_before_validator_cohort() {
            let (inventory, mut journal) = journal(sample_inventory());
            let mut transport = MockTransport {
                fail: Some("edge_verify".to_owned()),
                ..MockTransport::default()
            };
            let _ = execute_plan(&inventory, &mut transport, &mut journal)
                .expect_err("edge verify failure");
            let rollback = transport
                .events
                .iter()
                .position(|event| event == "rollback:edge")
                .expect("edge rollback");
            let validator = transport
                .events
                .iter()
                .position(|event| event == "rollback:taira-validator-4")
                .expect("validator rollback");
            assert!(rollback < validator);
        }

        #[test]
        fn cleanup_failure_stays_durable_and_retryable_without_rollback() {
            let (inventory, mut journal) = journal(sample_inventory());
            let mut transport = MockTransport {
                fail: Some("cleanup".to_owned()),
                ..MockTransport::default()
            };
            let _ = execute_plan(&inventory, &mut transport, &mut journal)
                .expect_err("cleanup failure remains operator-visible");
            assert!(!journal.finished);
            assert_eq!(journal.state.status, "cleanup_pending");
            assert_eq!(journal.state.phase, "cleanup_pending");
            assert_eq!(
                usize::from(journal.state.next_step),
                FULL_INROU_EXECUTION_STEPS.len() - 1
            );
            assert!(
                transport
                    .events
                    .iter()
                    .all(|event| !event.starts_with("rollback:"))
            );

            let mut retry = MockTransport::default();
            execute_plan(&inventory, &mut retry, &mut journal).expect("cleanup retry succeeds");
            assert_eq!(retry.events, ["cleanup"]);
            assert!(journal.finished);
            assert_eq!(journal.state.status, "completed");
        }

        #[test]
        fn deployment_proof_survives_crash_and_cleanup_retries_without_forward_inputs() {
            let admitted = admitted(sample_inventory());
            let directory = private_tempdir();
            let canonical = directory.path().canonicalize().expect("canonical tempdir");
            let mut journal = DurableJournal::open(&canonical, &admitted).expect("journal");
            let mut sealing = journal.state().clone();
            sealing.status = "sealing".to_owned();
            sealing.phase = "seal".to_owned();
            sealing.next_step =
                u16::try_from(FULL_INROU_EXECUTION_STEPS.len() - 2).expect("bounded steps");
            sealing.touched_validators = VALIDATOR_SLUGS
                .iter()
                .map(|slug| (*slug).to_owned())
                .collect();
            sealing.edge_touched = true;
            journal
                .mark_deployment_proven(sealing)
                .expect("persist deployment proof");
            let proof = canonical
                .join("deployment-proven")
                .join(format!("{}.json", admitted.authorization_sha256));
            assert!(proof.exists());

            let mut cleanup_pending = journal.state().clone();
            cleanup_pending.status = "cleanup_pending".to_owned();
            cleanup_pending.phase = "cleanup_pending".to_owned();
            cleanup_pending.next_step =
                u16::try_from(FULL_INROU_EXECUTION_STEPS.len() - 1).expect("bounded steps");
            journal
                .replace(cleanup_pending)
                .expect("persist host-sealed cleanup boundary");
            drop(journal);

            let mut resumed = match DurableJournal::classify(&canonical, &admitted)
                .expect("resume cleanup-pending journal")
            {
                JournalOpen::Fresh(_) => panic!("cleanup-pending journal must be resumable"),
                JournalOpen::Resumable(journal) => journal,
            };
            assert_eq!(
                resumed.resume_disposition(),
                ResumeDisposition::CleanupPending
            );
            assert!(!Path::new(&admitted.inventory.revision.source_root).exists());
            let mut failed_cleanup = MockTransport {
                fail: Some("cleanup".to_owned()),
                ..MockTransport::default()
            };
            let _ = execute_plan(&admitted.inventory, &mut failed_cleanup, &mut resumed)
                .expect_err("cleanup failure remains durable");
            assert_eq!(resumed.state().status, "cleanup_pending");
            drop(resumed);

            let current =
                canonical.join(format!("{}.journal.json", admitted.inventory.deployment_id));
            assert!(current.exists());
            let mut resumed = match DurableJournal::classify(&canonical, &admitted)
                .expect("retry cleanup-pending journal")
            {
                JournalOpen::Fresh(_) => panic!("cleanup-pending journal must be resumable"),
                JournalOpen::Resumable(journal) => journal,
            };
            let mut cleanup = MockTransport::default();
            execute_plan(&admitted.inventory, &mut cleanup, &mut resumed)
                .expect("cleanup retry succeeds");
            drop(resumed);
            assert!(!current.exists());
            assert!(DurableJournal::classify(&canonical, &admitted).is_err());
        }

        #[test]
        fn receipt_next_recovers_create_partial_full_and_post_rename_crashes() {
            let admitted = admitted(sample_inventory());
            let state = initial_journal(&admitted);
            let mut expected = json::to_json(&state).expect("journal JSON").into_bytes();
            expected.push(b'\n');
            let directory = private_tempdir();
            let canonical = directory.path().canonicalize().expect("canonical tempdir");

            for (name, prefix_len) in [
                ("created.json", 0),
                ("partial.json", expected.len() / 2),
                ("full.json", expected.len()),
            ] {
                let destination = canonical.join(name);
                let staging = canonical.join(format!(".{name}.next"));
                let mut file = create_private_new(&staging).expect("create staged receipt");
                file.write_all(&expected[..prefix_len])
                    .expect("write simulated crash prefix");
                drop(file);
                publish_json_no_replace(&destination, &state).expect("recover staged receipt");
                assert_eq!(fs::read(&destination).expect("receipt"), expected);
                assert!(!staging.exists());
            }

            let destination = canonical.join("renamed.json");
            let mut receipt = create_private_new(&destination).expect("create renamed receipt");
            receipt
                .write_all(&expected)
                .expect("write renamed receipt bytes");
            drop(receipt);
            publish_json_no_replace(&destination, &state).expect("recover post-rename crash");
            assert_eq!(fs::read(&destination).expect("receipt"), expected);
            assert!(!canonical.join(".renamed.json.next").exists());
        }

        #[test]
        fn receipt_next_and_terminal_conflicts_fail_closed() {
            let admitted = admitted(sample_inventory());
            let state = initial_journal(&admitted);
            let directory = private_tempdir();
            let canonical = directory.path().canonicalize().expect("canonical tempdir");
            let destination = canonical.join("staged-conflict.json");
            let staging = canonical.join(".staged-conflict.json.next");
            let mut file = create_private_new(&staging).expect("create staged conflict");
            file.write_all(b"not-a-prefix")
                .expect("write staged conflict");
            drop(file);
            let _ = publish_json_no_replace(&destination, &state)
                .expect_err("non-prefix staging must fail closed");
            assert!(!destination.exists());
            assert!(staging.exists());

            let destination = canonical.join("terminal-conflict.json");
            let mut file = create_private_new(&destination).expect("create terminal conflict");
            file.write_all(b"{}\n").expect("write terminal conflict");
            drop(file);
            let _ = publish_json_no_replace(&destination, &state)
                .expect_err("different immutable terminal receipt must fail closed");
            assert_eq!(fs::read(destination).expect("terminal conflict"), b"{}\n");
        }

        #[test]
        fn conflicting_aborted_replay_cannot_remove_active_journal() {
            let admitted = admitted(sample_inventory());
            let directory = private_tempdir();
            let canonical = directory.path().canonicalize().expect("canonical tempdir");
            let journal = DurableJournal::open(&canonical, &admitted).expect("journal");
            let mut conflicting = journal.state().clone();
            conflicting.status = "aborted_before_mutation".to_owned();
            conflicting.phase = "aborted_before_mutation".to_owned();
            let receipt = canonical
                .join("aborted-before-mutation")
                .join(format!("{}.json", admitted.authorization_sha256));
            publish_json_no_replace(&receipt, &conflicting).expect("conflicting replay receipt");
            drop(journal);

            assert!(
                DurableJournal::classify(&canonical, &admitted).is_err(),
                "conflicting replay receipt must fail closed"
            );
            assert!(
                canonical
                    .join(format!("{}.journal.json", admitted.inventory.deployment_id))
                    .exists(),
                "active journal must survive a conflicting terminal receipt"
            );
        }

        #[test]
        fn partial_journal_next_is_discarded_to_resume_durable_predecessor() {
            let admitted = admitted(sample_inventory());
            let directory = private_tempdir();
            let canonical = directory.path().canonicalize().expect("canonical tempdir");
            let journal = DurableJournal::open(&canonical, &admitted).expect("journal");
            let current =
                canonical.join(format!("{}.journal.json", admitted.inventory.deployment_id));
            let name = current.file_name().expect("journal name").to_string_lossy();
            let staging = canonical.join(format!(".{name}.next"));
            let mut partial = create_private_new(&staging).expect("partial journal staging");
            partial
                .write_all(b"{\"schema\":")
                .expect("partial journal bytes");
            drop(partial);
            drop(journal);

            let resumed = match DurableJournal::classify(&canonical, &admitted)
                .expect("partial staging recovery")
            {
                JournalOpen::Fresh(_) => panic!("durable predecessor must remain resumable"),
                JournalOpen::Resumable(journal) => journal,
            };
            assert_eq!(resumed.state(), &initial_journal(&admitted));
            assert!(!staging.exists());
        }

        #[test]
        fn journal_successors_reject_phase_drift_and_progress_jumps() {
            let admitted = admitted(sample_inventory());
            let initial = initial_journal(&admitted);
            let mut phase_drift = initial.clone();
            phase_drift.phase = "reset".to_owned();
            let _ = validate_resumable_journal(&phase_drift, &initial)
                .expect_err("phase cannot jump independently of next_step");

            let mut completed_phase = initial.clone();
            completed_phase.next_step = 1;
            completed_phase.phase = ExecutionStep::Preflight.label().to_owned();
            let _ = validate_resumable_journal(&completed_phase, &initial)
                .expect_err("advanced cursor cannot retain the completed-step phase");

            let mut jumped = initial.clone();
            jumped.next_step = 2;
            jumped.phase = "stop".to_owned();
            validate_resumable_journal(&jumped, &initial).expect("state is independently valid");
            assert!(
                !valid_journal_successor(&initial, &jumped),
                "a staged journal may advance at most one execution step"
            );
        }

        fn sample_claims(inventory: &InventoryV1, inventory_sha256: &str) -> AuthorizationClaimsV1 {
            AuthorizationClaimsV1 {
                action: "reset_and_deploy".to_owned(),
                qualification_scope: inventory.qualification_scope,
                deployment_id: inventory.deployment_id.clone(),
                inventory_sha256: inventory_sha256.to_owned(),
                artifact_closure_sha256: inventory.artifact_closure_sha256.clone(),
                runtime_client_config_sha256: inventory.runtime_client_config_sha256.clone(),
                onboarding_token_sha256: inventory.onboarding_token_sha256.clone(),
                validator_client_configs_sha256: inventory.validator_client_configs_sha256.clone(),
                inrou_stage_tree_sha256: inventory.inrou_stage_tree_sha256.clone(),
                faucet_policy: inventory.faucet_policy.clone(),
                fee_intent: inventory.fee_intent.clone(),
                authorization_nonce: inventory.authorization_nonce.clone(),
                issued_at_unix_ms: 990_000,
                not_before_unix_ms: 990_000,
                expires_at_unix_ms: 1_010_000,
                execution_expires_at_unix_ms: 990_000
                    + execution_lifetime_ms(inventory).expect("execution lifetime"),
            }
        }

        #[test]
        fn inventory_requires_four_guest_roles_and_independently_bound_native_mac() {
            for vacant in [false, true] {
                let original = if vacant {
                    vacant_execution_fixture()
                } else {
                    sample_inventory()
                };
                validate_inventory_structure(&original)
                    .expect("complete admitted MacStadium host pair");
                for mask in 0_u8..15 {
                    let mut inventory = original.clone();
                    for (index, validator) in inventory.validators.iter_mut().enumerate() {
                        if mask & (1 << index) == 0 {
                            validator.endpoint.host_identity_sha256 =
                                hex::encode([index as u8 + 1; 32]);
                        }
                    }
                    assert!(
                        validate_inventory_structure(&inventory).is_err(),
                        "every guest role must retain the exact admitted route (vacant={vacant}, mask={mask})"
                    );
                }
            }
        }

        #[test]
        fn host_pair_inventory_preserves_each_native_endpoint_and_root_boundary() {
            for target in 0..5 {
                for field in [
                    "user",
                    "port",
                    "remote_cli",
                    "service_root",
                    "state_root",
                    "reset_guard",
                ] {
                    let mut inventory = sample_inventory();
                    let (endpoint, service_root, state_root, reset_guard) = if target < 4 {
                        let validator = &mut inventory.validators[target];
                        (
                            &mut validator.endpoint,
                            &mut validator.service_root,
                            &mut validator.state_root,
                            &mut validator.reset_guard,
                        )
                    } else {
                        let edge = &mut inventory.edge;
                        (
                            &mut edge.endpoint,
                            &mut edge.service_root,
                            &mut edge.state_root,
                            &mut edge.reset_guard,
                        )
                    };
                    match field {
                        "user" => endpoint.user = "operator".to_owned(),
                        "port" => endpoint.port = 2222,
                        "remote_cli" => endpoint.remote_cli.push_str(".other"),
                        "service_root" => service_root.push_str(".other"),
                        "state_root" => state_root.push_str(".other"),
                        "reset_guard" => reset_guard.push_str(".other"),
                        _ => unreachable!(),
                    }
                    assert!(
                        validate_inventory_structure(&inventory).is_err(),
                        "target={target} field={field}"
                    );
                }
            }
        }

        #[test]
        fn unsupported_placement_is_rejected_before_private_inputs_are_opened() {
            let directory = private_tempdir();
            let root = directory
                .path()
                .canonicalize()
                .expect("canonical fixture root");
            let path = root.join("inventory.json");
            let mut inventory = sample_inventory();
            inventory.edge.endpoint.host_identity_sha256 = "f".repeat(64);
            assert!(validate_inventory_structure(&inventory).is_err());
            let mut file = create_private_new(&path).expect("private inventory fixture");
            file.write_all(&canonical_inventory_bytes(&inventory).expect("inventory JSON"))
                .expect("write inventory");
            drop(file);
            let absent = root.join("must-not-open");
            let error = admit_signed_inputs(&path, &absent, &absent, &absent, &absent)
                .err()
                .expect("unsupported placement fails before any private input");
            assert_compiled_admission_error(&error, "independently guarded native Mac");
            assert!(!absent.exists());
            assert_eq!(fs::read_dir(&root).expect("fixture directory").count(), 1);
        }

        #[test]
        fn host_pair_known_hosts_binds_two_independent_actual_native_keys() {
            use base64::Engine as _;
            let directory = private_tempdir();
            let root = directory
                .path()
                .canonicalize()
                .expect("canonical fixture root");
            let mut inventory = sample_inventory();
            let public_identity = |byte| {
                let mut wire = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
                wire.extend_from_slice(&[byte; 32]);
                format!(
                    "ssh-ed25519 {}",
                    base64::engine::general_purpose::STANDARD.encode(wire)
                )
            };
            let guest_identity = public_identity(1);
            let native_identity = public_identity(2);
            let guest_line = format!(
                "{} {guest_identity}",
                inventory.hosts.validator_guest.endpoint.hostname
            );
            let native_line = format!(
                "{} {native_identity}",
                inventory.hosts.native_edge.endpoint.hostname
            );
            inventory
                .hosts
                .validator_guest
                .endpoint
                .host_identity_sha256 = sha256_hex(guest_identity.as_bytes());
            inventory
                .hosts
                .validator_guest
                .endpoint
                .known_host_line_sha256 = sha256_hex(guest_line.as_bytes());
            inventory.hosts.native_edge.endpoint.host_identity_sha256 =
                sha256_hex(native_identity.as_bytes());
            inventory.hosts.native_edge.endpoint.known_host_line_sha256 =
                sha256_hex(native_line.as_bytes());
            for validator in &mut inventory.validators {
                validator.endpoint = endpoint(
                    &inventory.hosts.validator_guest,
                    &validator.service_root,
                    &inventory.revision,
                );
            }
            inventory.edge.endpoint = endpoint(
                &inventory.hosts.native_edge,
                &inventory.edge.service_root,
                &inventory.revision,
            );
            inventory.edge.native_capability = native_edge_protocol::fixture_capability(
                &inventory.hosts,
                inventory.edge.admitted_release().unwrap().clone(),
                &inventory.authorization_nonce,
                &inventory.previous_genesis_hash,
            );
            let path = root.join("known-hosts");
            let mut file = create_private_new(&path).expect("private known-host fixture");
            file.write_all(format!("{guest_line}\n{native_line}\n").as_bytes())
                .expect("write known-hosts");
            drop(file);
            validate_inventory_structure(&inventory)
                .expect("canonical two-host structural inventory");
            drop(
                validate_known_hosts(&inventory, &path)
                    .expect("each native physical host pins its own key"),
            );
            let mut disagreement = inventory.clone();
            disagreement.validators[1].endpoint.known_host_line_sha256 = "f".repeat(64);
            assert!(
                validate_known_hosts(&disagreement, &path).is_err(),
                "roles sharing one physical route cannot disagree on its pin"
            );

            let foreign_identity = public_identity(3);
            let foreign_line = format!("{} {foreign_identity}", inventory.edge.endpoint.hostname);
            inventory.edge.endpoint.known_host_line_sha256 = sha256_hex(foreign_line.as_bytes());
            fs::write(&path, format!("{guest_line}\n{foreign_line}\n"))
                .expect("substitute native edge key");
            assert!(
                validate_known_hosts(&inventory, &path).is_err(),
                "a line digest cannot authenticate another native host key"
            );
            inventory.edge.endpoint.host_identity_sha256 = sha256_hex(foreign_identity.as_bytes());
            drop(
                validate_known_hosts(&inventory, &path)
                    .expect("transport can measure the substituted public key"),
            );
            assert!(
                validate_inventory_structure(&inventory).is_err(),
                "transport observation cannot replace the independently admitted native host pair"
            );
        }

        #[test]
        fn canonical_admitted_fixture_passes_positive_inventory_admission() {
            let inventory = sample_inventory();
            validate_inventory_structure(&inventory)
                .expect("positive structural inventory admission");
            if test_compiled_release_commit().is_some() {
                validate_inventory(&inventory).expect("exact compiled release admission");
            } else {
                let error = validate_inventory(&inventory)
                    .expect_err("a structural fixture never grants development release authority");
                assert_compiled_admission_error(&error, "unused on development builds");
            }
            validate_shared_validator_closure(&inventory).expect("same-revision shared artifacts");
        }

        #[test]
        fn initial_state_wire_format_is_canonical_and_roundtrips() {
            fn check<T: JsonSerialize + JsonDeserialize>(state: &T, expected: &str) {
                let encoded = json::to_json(state).expect("canonical initial state");
                assert_eq!(encoded, expected);
                let decoded: T =
                    json::from_slice(encoded.as_bytes()).expect("initial state roundtrip");
                assert_eq!(json::to_json(&decoded).expect("reencoded state"), expected);
            }

            let vacant = r#"{"state":"vacant","value":null}"#;
            check(&ValidatorInitialStateV1::Vacant, vacant);
            check(&EdgeInitialStateV1::Vacant, vacant);
            let inventory = sample_inventory();
            let encoded =
                canonical_inventory_bytes(&inventory).expect("canonical admitted inventory");
            let (decoded, _inventory_guard) =
                decode_inventory(&encoded, "inventory").expect("admitted inventory roundtrip");
            validate_inventory_structure(&decoded)
                .expect("roundtripped admitted inventory is admissible");
            assert_eq!(
                canonical_inventory_bytes(&decoded).expect("reencoded inventory"),
                encoded
            );
            let validator_payload = json::to_json(
                inventory.validators[0]
                    .admitted_release()
                    .expect("prior validator"),
            )
            .expect("validator release JSON");
            check(
                &inventory.validators[0].initial_state,
                &format!(r#"{{"state":"admitted_release","value":{validator_payload}}}"#),
            );
            let edge_payload =
                json::to_json(inventory.edge.admitted_release().expect("prior edge"))
                    .expect("edge release JSON");
            check(
                &inventory.edge.initial_state,
                &format!(r#"{{"state":"admitted_release","value":{edge_payload}}}"#),
            );
        }

        #[test]
        fn occupied_service_state_is_explicit_strict_and_signed() {
            let inventory = sample_inventory();
            let prior = inventory.validators[0].admitted_release().unwrap();
            let mut encoded = json::to_value(prior).unwrap();
            encoded.as_object_mut().unwrap().remove("service_state");
            assert!(json::from_value::<ValidatorAdmittedReleaseV1>(encoded).is_err());
            for invalid in [
                r#"{}"#,
                r#"{"state":"running"}"#,
                r#"{"state":"running","value":{}}"#,
                r#"{"state":"stopped","value":null}"#,
                r#"{"state":"stopped","value":{"device":1}}"#,
                r#"{"state":"stopped","value":{"device":1,"inode":2,"extra":0}}"#,
                r#"{"state":"vacant","value":null}"#,
                r#"{"state":"running","state":"stopped","value":null}"#,
            ] {
                assert!(
                    json::from_str::<PriorValidatorServiceStateV1>(invalid).is_err(),
                    "{invalid}"
                );
            }
            let invalid: PriorValidatorServiceStateV1 =
                json::from_str(r#"{"state":"stopped","value":{"device":1,"inode":0}}"#).unwrap();
            assert!(invalid.validate().is_err());
            let before = canonical_inventory_bytes(&inventory).unwrap();
            let mut stopped = inventory.clone();
            let ValidatorInitialStateV1::AdmittedRelease(prior) =
                &mut stopped.validators[0].initial_state
            else {
                unreachable!()
            };
            prior.service_state = PriorValidatorServiceStateV1::Stopped(StoppedValidatorStateV1 {
                device: 7,
                inode: 11,
            });
            let expected_service_state = prior.service_state.clone();
            let after = canonical_inventory_bytes(&stopped).unwrap();
            assert_ne!(sha256_hex(&before), sha256_hex(&after));
            let (decoded, _guard) = decode_inventory(&after, "stopped fixture").unwrap();
            validate_inventory_structure(&decoded).unwrap();
            assert_eq!(canonical_inventory_bytes(&decoded).unwrap(), after);
            assert!(!decoded.validators[0].is_vacant());
            assert_eq!(
                decoded.validators[0]
                    .admitted_release()
                    .unwrap()
                    .service_state,
                expected_service_state
            );
        }

        #[test]
        fn stopped_state_identity_survives_archive_restore_and_rejects_substitution() {
            let root = tempfile::tempdir().unwrap();
            let state = root.path().join("state");
            let retained = root.path().join("retained");
            fs::create_dir(&state).unwrap();
            fs::write(state.join("retained-ledger"), b"existing durable bytes").unwrap();
            let metadata = fs::symlink_metadata(&state).unwrap();
            let bound = PriorValidatorServiceStateV1::Stopped(StoppedValidatorStateV1 {
                device: metadata.dev(),
                inode: metadata.ino(),
            });
            fs::rename(&state, &retained).unwrap();
            fs::create_dir(&state).unwrap();
            let replacement = fs::symlink_metadata(&state).unwrap();
            assert!(
                bound
                    .validate_state_identity(replacement.dev(), replacement.ino())
                    .is_err()
            );
            let archived = fs::symlink_metadata(&retained).unwrap();
            bound
                .validate_state_identity(archived.dev(), archived.ino())
                .unwrap();
            assert!(
                bound
                    .validate_state_identity(archived.dev() ^ 1, archived.ino())
                    .is_err()
            );
            fs::remove_dir(&state).unwrap();
            fs::rename(&retained, &state).unwrap();
            let restored = fs::symlink_metadata(&state).unwrap();
            bound
                .validate_state_identity(restored.dev(), restored.ino())
                .unwrap();
            assert_eq!(
                fs::read(state.join("retained-ledger")).unwrap(),
                b"existing durable bytes"
            );
        }

        #[test]
        fn initial_state_discriminator_and_fields_are_strict() {
            for invalid in [
                r#"{}"#,
                r#"{"value":null}"#,
                r#"{"state":"vacant"}"#,
                r#"{"state":null,"value":null}"#,
                r#"{"state":"unknown","value":null}"#,
                r#"{"state":"Vacant","value":null}"#,
                r#"{"state":"vacant","value":{},"extra":null}"#,
                r#"{"state":"vacant","value":null,"extra":null}"#,
                r#"{"state":"vacant","state":"admitted_release","value":null}"#,
                r#"{"state":"vacant","value":null,"value":{}}"#,
                r#"{"state":"vacant","value":{}}"#,
                r#"{"state":"vacant","value":false}"#,
                r#"{"state":"admitted_release","value":null}"#,
                r#"{"Vacant":null}"#,
                r#"{"AdmittedRelease":{}}"#,
                r#"{"rollback":{}}"#,
                r#"{"rollback_release_root":"/srv/taira/releases/prior"}"#,
            ] {
                assert!(
                    json::from_slice::<ValidatorInitialStateV1>(invalid.as_bytes()).is_err(),
                    "validator accepted {invalid}"
                );
                assert!(
                    json::from_slice::<EdgeInitialStateV1>(invalid.as_bytes()).is_err(),
                    "edge accepted {invalid}"
                );
            }
        }

        #[test]
        fn initial_state_admitted_release_rejects_unknown_payload_fields() {
            let inventory = sample_inventory();
            let mut validator = json::to_value(&inventory.validators[0].initial_state)
                .expect("admitted validator state");
            validator
                .as_object_mut()
                .expect("state object")
                .get_mut("value")
                .expect("release content")
                .as_object_mut()
                .expect("release object")
                .insert("rollback".to_owned(), json::Value::Null);
            assert!(json::from_value::<ValidatorInitialStateV1>(validator).is_err());

            let mut edge =
                json::to_value(&inventory.edge.initial_state).expect("admitted edge state");
            edge.as_object_mut()
                .expect("state object")
                .get_mut("value")
                .expect("release content")
                .as_object_mut()
                .expect("release object")
                .insert("rollback_release_root".to_owned(), json::Value::Null);
            assert!(json::from_value::<EdgeInitialStateV1>(edge).is_err());
        }

        #[test]
        fn vacant_inventory_rejects_hidden_admitted_release_contents_at_decode() {
            let directory = private_tempdir();
            let root = directory
                .path()
                .canonicalize()
                .expect("canonical inventory fixture root");
            let canonical = vacant_execution_fixture();
            let path = root.join("vacant.json");
            let mut file = create_private_new(&path).expect("private vacant fixture");
            file.write_all(&canonical_inventory_bytes(&canonical).expect("vacant JSON"))
                .expect("write vacant inventory");
            drop(file);
            let (decoded, _, _inventory_guard) = read_inventory(&path, "inventory")
                .expect("canonical vacant inventory decodes at admission boundary");
            validate_inventory_structure(&decoded)
                .expect("canonical vacant inventory is admissible");
            assert!(decoded.validators.iter().all(ValidatorV1::is_vacant));
            assert!(!decoded.edge.is_vacant());
            assert_eq!(
                decoded
                    .edge
                    .native_capability
                    .incumbent
                    .claims
                    .owned_publication
                    .operation_id,
                canonical
                    .edge
                    .native_capability
                    .incumbent
                    .claims
                    .owned_publication
                    .operation_id
            );

            for edge in [false, true] {
                let mut invalid: Value = json::from_slice(
                    &canonical_inventory_bytes(&sample_inventory()).expect("admitted bytes"),
                )
                .expect("admitted inventory");
                let inventory = invalid.as_object_mut().expect("inventory object");
                let target = if edge {
                    inventory.get_mut("edge").expect("edge")
                } else {
                    inventory
                        .get_mut("validators")
                        .expect("validators")
                        .as_array_mut()
                        .expect("validator array")
                        .first_mut()
                        .expect("validator")
                };
                let state = target
                    .as_object_mut()
                    .expect("target object")
                    .get_mut("initial_state")
                    .expect("initial state")
                    .as_object_mut()
                    .expect("state object");
                assert!(
                    state
                        .get("value")
                        .expect("actual prior release")
                        .is_object()
                );
                state.insert("state".to_owned(), json::Value::String("vacant".to_owned()));
                let path = root.join(format!("hidden-release-{edge}.json"));
                let mut file = create_private_new(&path).expect("private malformed fixture");
                file.write_all(json::to_json(&invalid).expect("malformed JSON").as_bytes())
                    .expect("write malformed inventory");
                drop(file);
                assert!(
                    read_inventory(&path, "inventory").is_err(),
                    "vacant target cannot discard admitted release content (edge={edge})"
                );
            }
        }

        #[test]
        fn explicit_initial_state_is_required_and_retired_rollback_fields_reject() {
            let inventory = sample_inventory();
            let mut validator = inventory.validators[0].clone();
            validator.initial_state = ValidatorInitialStateV1::Vacant;
            let canonical = json::to_value(&validator).expect("canonical vacant validator");
            let roundtrip: ValidatorV1 =
                json::from_value(canonical.clone()).expect("vacant roundtrip");
            assert!(roundtrip.is_vacant());
            assert!(roundtrip.admitted_release().is_err());
            for null_slot in [false, true] {
                let mut invalid = canonical.clone();
                let object = invalid.as_object_mut().expect("validator object");
                if null_slot {
                    object.insert("initial_state".to_owned(), norito::json::Value::Null);
                } else {
                    object.remove("initial_state");
                }
                assert!(json::from_value::<ValidatorV1>(invalid).is_err());
            }
            let mut retired = canonical;
            retired
                .as_object_mut()
                .expect("validator object")
                .insert("rollback".to_owned(), norito::json::Value::Null);
            assert!(json::from_value::<ValidatorV1>(retired).is_err());

            let mut edge = inventory.edge.clone();
            edge.initial_state = EdgeInitialStateV1::Vacant;
            let canonical = json::to_value(&edge).expect("canonical vacant edge");
            let roundtrip: EdgeV1 =
                json::from_value(canonical.clone()).expect("vacant edge roundtrip");
            assert!(roundtrip.is_vacant());
            assert!(roundtrip.admitted_release().is_err());
            for field in ["initial_state", "native_capability"] {
                let mut missing = canonical.clone();
                missing.as_object_mut().expect("edge object").remove(field);
                assert!(
                    json::from_value::<EdgeV1>(missing).is_err(),
                    "missing {field}"
                );
            }
            for field in [
                "systemd_unit_sha256",
                "rollback_release_root",
                "rollback_cli_sha256",
                "rollback_edge_config_sha256",
            ] {
                let mut retired = canonical.clone();
                retired
                    .as_object_mut()
                    .expect("edge object")
                    .insert(field.to_owned(), norito::json::Value::Null);
                assert!(
                    json::from_value::<EdgeV1>(retired).is_err(),
                    "retired {field}"
                );
            }
        }

        // The prior network genesis remains an explicit reset anchor even when these
        // Linux target namespaces have never hosted the chain.
        fn vacant_execution_fixture() -> InventoryV1 {
            let mut inventory = sample_inventory();
            for validator in &mut inventory.validators {
                validator.initial_state = ValidatorInitialStateV1::Vacant;
            }
            // Mac publication remains independently owned even before guest lanes exist.
            inventory.artifact_closure_sha256 = artifact_closure_sha256(&inventory);
            inventory
        }

        #[test]
        fn required_bootstrap_and_readiness_complete_before_public_cutover() {
            let (inventory, mut journal) = journal(vacant_execution_fixture());
            let mut transport = MockTransport::default();
            execute_plan(&inventory, &mut transport, &mut journal).expect("vacant model completes");
            let at = |event: &str| {
                transport
                    .events
                    .iter()
                    .position(|value| value == event)
                    .expect(event)
            };
            assert!(at("start:taira-validator-4") < at("canary"));
            assert!(at("canary") < at("convergence"));
            assert!(at("convergence") < at("edge_stage"));
            assert!(
                !transport
                    .events
                    .iter()
                    .any(|event| event == "restart_proof")
            );
            assert!(
                transport
                    .mutation_dispatches
                    .iter()
                    .all(|(step, _)| *step == ExecutionStep::Canary),
                "edge verification performs no diagnostic write mutations"
            );
            assert!(at("edge_stage") < at("edge_cutover"));
            assert!(at("edge_cutover") < at("edge_verify"));
            assert!(journal.finished);
        }

        #[test]
        fn candidate_failure_never_exposes_the_public_edge() {
            for phase in ["convergence", "canary"] {
                let (inventory, mut journal) = journal(vacant_execution_fixture());
                let mut transport = MockTransport {
                    fail: Some(phase.to_owned()),
                    ..MockTransport::default()
                };
                let _ = execute_plan(&inventory, &mut transport, &mut journal)
                    .expect_err("candidate fails");
                assert!(!journal.state.edge_touched, "{phase}");
                assert!(
                    !transport
                        .events
                        .iter()
                        .any(|event| event.starts_with("edge_") || event == "rollback:edge"),
                    "{phase}"
                );
                assert_eq!(journal.state.status, "rolled_back", "{phase}");
            }
        }

        #[test]
        fn public_verification_failure_rolls_back_edge_before_validators() {
            let (inventory, mut journal) = journal(vacant_execution_fixture());
            let mut transport = MockTransport {
                fail: Some("edge_verify".to_owned()),
                ..MockTransport::default()
            };
            let _ = execute_plan(&inventory, &mut transport, &mut journal)
                .expect_err("public verification fails");
            assert_eq!(
                transport
                    .events
                    .iter()
                    .filter(|event| event.starts_with("rollback:"))
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                [
                    "rollback:edge",
                    "rollback:taira-validator-4",
                    "rollback:taira-validator-3",
                    "rollback:taira-validator-2",
                    "rollback:taira-validator-1"
                ]
            );
            assert!(journal.state.edge_touched);
            assert!(journal.state.edge_rollback_complete);
            assert_eq!(journal.state.status, "rolled_back");
        }

        #[test]
        fn validator_public_origins_require_distinct_canonical_https_roots() {
            let mut inventory = sample_inventory();
            validate_inventory_structure(&inventory).expect("existing canonical HTTPS roots");
            for (index, client) in inventory.validator_clients.iter_mut().enumerate() {
                client.torii_origin = format!("https://test.example.org:{}/", 8443 + index);
            }
            validate_inventory_structure(&inventory)
                .expect("four authenticated peers on distinct HTTPS ports");
            let mut duplicate = inventory.clone();
            duplicate.validator_clients[1].torii_origin =
                duplicate.validator_clients[0].torii_origin.clone();
            assert!(
                validate_inventory_structure(&duplicate)
                    .unwrap_err()
                    .to_string()
                    .contains("origins must be distinct")
            );
            for field in ["account", "peer"] {
                let mut duplicate = inventory.clone();
                if field == "account" {
                    duplicate.validator_clients[1].account_id =
                        duplicate.validator_clients[0].account_id.clone();
                } else {
                    duplicate.validator_clients[1].peer_id =
                        duplicate.validator_clients[0].peer_id.clone();
                }
                assert!(validate_inventory_structure(&duplicate).is_err(), "{field}");
            }
            for origin in [
                "http://test.example.org:8443/",
                "https://test.example.org:0/",
                "https://test.example.org:443/",
                "https://test.example.org:8443",
                "https://TEST.example.org:8443/",
                "https://user@test.example.org:8443/",
                "https://user:secret@test.example.org:8443/",
                "https://test.example.org:8443/?query=1",
                "https://test.example.org:8443/#fragment",
                "https://test.example.org:8443/validator-1/",
                "https://test.example.org:8443/%2f",
                "https://127.0.0.1:8443/",
                "https://[::1]:8443/",
                "https://localhost:8443/",
                "https://test.local:8443/",
                "https://test..example.org:8443/",
                "https://-test.example.org:8443/",
            ] {
                assert!(
                    validate_validator_public_origin(origin).is_err(),
                    "{origin}"
                );
                let mut invalid = inventory.clone();
                invalid.validator_clients[0].torii_origin = origin.to_owned();
                assert!(validate_inventory_structure(&invalid).is_err(), "{origin}");
            }
        }

        #[test]
        fn candidate_probe_origins_reject_cross_host_or_substituted_sockets() {
            for origin in [
                "https://127.0.0.1:8080/",
                "http://localhost:8080/",
                "http://192.0.2.1:8080/",
                "http://127.0.0.1:8080/path",
                "http://user@127.0.0.1:8080/",
                "http://127.0.0.1:8080/?redirect=1",
            ] {
                assert!(validate_candidate_probe_origin(origin).is_err(), "{origin}");
            }
            let origin = "http://127.0.0.1:8080/";
            validate_candidate_probe_bind(origin, &"127.0.0.1:8080".parse().unwrap())
                .expect("exact loopback");
            validate_candidate_probe_bind(origin, &"0.0.0.0:8080".parse().unwrap())
                .expect("same wildcard socket");
            assert!(
                validate_candidate_probe_bind(origin, &"127.0.0.1:8081".parse().unwrap()).is_err()
            );
            assert!(
                validate_candidate_probe_bind(origin, &"192.0.2.1:8080".parse().unwrap()).is_err()
            );
            let mut inventory = sample_inventory();
            inventory.validator_clients[1].probe_origin =
                inventory.validator_clients[0].probe_origin.clone();
            assert!(validate_inventory_structure(&inventory).is_err());
        }

        #[test]
        fn revision_admission_requires_the_compiled_executable_identity() {
            let mut revision = sample_inventory().revision;
            let Some(compiled) = test_compiled_release_commit() else {
                let error = validate_revision(&revision)
                    .expect_err("development identity cannot authorize a release revision");
                assert_compiled_admission_error(&error, "unused on development builds");
                return;
            };
            assert_eq!(revision.commit, compiled);
            validate_revision(&revision).expect("the exact compiled revision is admissible");
            revision.commit = if revision.commit == "ffffffffffffffffffffffffffffffffffffffff" {
                "0000000000000000000000000000000000000000".to_owned()
            } else {
                "ffffffffffffffffffffffffffffffffffffffff".to_owned()
            };
            revision.build_id.clone_from(&revision.commit);
            assert!(
                validate_revision(&revision)
                    .expect_err("reject another valid source revision")
                    .to_string()
                    .contains("compiled CLI SHA")
            );
        }

        #[test]
        fn vacant_inventory_preserves_all_other_admission_requirements() {
            let inventory = vacant_execution_fixture();
            validate_inventory_structure(&inventory)
                .expect("vacant targets with a real prior network anchor");
            let mut wrong = inventory.clone();
            wrong.validators[0].platform.kvm_api_version = 0;
            assert!(validate_inventory_structure(&wrong).is_err());
            let mut wrong = inventory.clone();
            wrong.validators[0].artifacts[0]
                .remote_path
                .push_str(".other");
            wrong.artifact_closure_sha256 = artifact_closure_sha256(&wrong);
            assert!(validate_inventory_structure(&wrong).is_err());
            let mut wrong = inventory;
            wrong
                .edge
                .native_capability
                .helper_source_closure_sha256
                .clear();
            assert!(validate_inventory_structure(&wrong).is_err());
        }

        #[test]
        fn reset_execution_preserves_beacon_and_service_order_without_epoch_writer() {
            for scope in [
                QualificationScopeV1::CoreTestnet,
                QualificationScopeV1::FullInrou,
            ] {
                let steps = execution_steps(scope);
                assert_eq!(
                    &steps[..3],
                    &[
                        ExecutionStep::Preflight,
                        ExecutionStep::Stage,
                        ExecutionStep::Stop
                    ]
                );
                assert!(ExecutionStep::Canary.supports_recovery());
                assert!(!ExecutionStep::EdgeVerify.supports_recovery());
                assert!(ExecutionStep::EdgeVerify.is_edge_step());
                assert!(!steps.contains(&ExecutionStep::RestartProof));
                let kinds = scope.canary_kinds();
                assert_eq!(
                    &kinds[..8],
                    &[
                        "onboarding",
                        "faucet",
                        "write_canary",
                        "beacon_install",
                        "beacon_provider_1",
                        "beacon_provider_2",
                        "beacon_provider_3",
                        "beacon_provider_4"
                    ]
                );
                assert_eq!(kinds.len(), 8);
                assert!(!kinds.iter().any(|kind| kind.contains("epoch_supervisor")));
            }
        }

        #[test]
        fn retired_epoch_supervisor_commands_and_inputs_are_rejected() {
            let command = <PublicReset as clap::Args>::augment_args(clap::Command::new("reset"));
            for retired in [
                "prepare-epoch-supervisor-plan",
                "prepare-epoch-update",
                "epoch-supervisor-host",
            ] {
                let error = command
                    .clone()
                    .try_get_matches_from(["reset", retired])
                    .unwrap_err();
                assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
            }
            for selected in ["assemble", "authorize", "apply"] {
                let subcommand = command.find_subcommand(selected).unwrap();
                for retired in [
                    "maintenance-admin-config",
                    "epoch-seed-source",
                    "epoch-seed-sources",
                    "epoch-supervisor-plan",
                ] {
                    assert!(
                        !subcommand
                            .get_arguments()
                            .any(|arg| arg.get_long() == Some(retired)),
                        "{selected}: {retired}"
                    );
                }
            }
        }

        #[test]
        fn retired_inventory_fields_and_seven_artifact_closure_are_rejected() {
            let inventory = sample_inventory();
            validate_inventory_structure(&inventory).expect("complete current role fixture");
            let canonical = json::to_value(&inventory).unwrap();
            for field in [
                "epoch_supervisor",
                "maintenance_admin_identity",
                "maintenance_admin_config_sha256",
            ] {
                assert!(canonical.get(field).is_none());
                let mut value = canonical.clone();
                value
                    .as_object_mut()
                    .unwrap()
                    .insert(field.into(), json::Value::Null);
                assert!(json::from_value::<InventoryV1>(value).is_err(), "{field}");
            }
            let canonical_timeouts = json::to_value(&inventory.timeouts).unwrap();
            for field in ["epoch_supervisor_pause_secs", "epoch_supervisor_start_secs"] {
                let mut value = canonical_timeouts.clone();
                value
                    .as_object_mut()
                    .unwrap()
                    .insert(field.into(), json::Value::from(60_u64));
                assert!(json::from_value::<TimeoutsV1>(value).is_err(), "{field}");
            }
            let mut wrong = inventory;
            for validator in &mut wrong.validators {
                validator.artifacts.retain(|entry| entry.role != "kagami");
            }
            wrong.artifact_closure_sha256 = artifact_closure_sha256(&wrong);
            assert!(validate_inventory_structure(&wrong).is_err());
            assert_eq!(
                artifact_role_policy("kagami").unwrap(),
                (0o755, 512 * 1024 * 1024)
            );
        }

        pub(in super::super) fn sample_inventory() -> InventoryV1 {
            let _chain_guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
            let canary_key_pair =
                iroha_crypto::KeyPair::try_from_seed(vec![0x42; 32], Algorithm::Ed25519)
                    .expect("deterministic canary key");
            let faucet_key_pair =
                iroha_crypto::KeyPair::try_from_seed(vec![0x43; 32], Algorithm::Ed25519)
                    .expect("deterministic faucet key");
            let canary_account = AccountId::new(canary_key_pair.public_key().clone());
            let canary_alias = crate::taira::canary_alias(canary_key_pair.public_key());
            let canary_onboarding_request =
                AccountOnboardingPlanRequestV1::try_new(canary_alias, &canary_account, Vec::new())
                    .expect("deterministic canary onboarding request");
            // This placeholder is only a structural fixture, never executable provenance.
            let fixture_commit = test_compiled_release_commit()
                .unwrap_or("1111111111111111111111111111111111111111");
            let revision = RevisionV1 {
                branch: SOURCE_BRANCH.to_owned(),
                commit: fixture_commit.to_owned(),
                tree: "2".repeat(40),
                cargo_lock_sha256: "3".repeat(64),
                source_root: "/private/source".to_owned(),
                source_manifest_path: "/private/source-manifest.json".to_owned(),
                source_manifest_sha256: "6".repeat(64),
                source_closure_sha256: "7".repeat(64),
                target: BUILD_TARGET.to_owned(),
                profile: BUILD_PROFILE.to_owned(),
                build_id: fixture_commit.to_owned(),
            };
            let hosts = host_pair::fixture_pair();
            let validators: Vec<ValidatorV1> = VALIDATOR_SLUGS
                .iter()
                .enumerate()
                .map(|(index, slug)| {
                    let service_root = format!("/srv/taira/{slug}");
                    ValidatorV1 {
                        slug: (*slug).to_owned(),
                        node_fingerprint: iroha_crypto::Hash::new(
                            format!("fixture-node-{index}").as_bytes(),
                        )
                        .to_string(),
                        build_fingerprint: iroha_crypto::Hash::new(b"fixture-build").to_string(),
                        config_fingerprint: iroha_crypto::Hash::new(b"fixture-config").to_string(),
                        endpoint: endpoint(&hosts.validator_guest, &service_root, &revision),
                        platform: PlatformV1 {
                            os: "linux".to_owned(),
                            arch: "aarch64".to_owned(),
                            kvm_api_version: 12,
                        },
                        service_root: service_root.clone(),
                        state_root: format!("/var/lib/taira/{slug}"),
                        reset_guard: format!("/var/lib/taira/.public-reset-control-v1/{slug}"),
                        systemd_unit: format!("iroha3d-{slug}.service"),
                        systemd_unit_sha256: sha256_hex(
                            format!("{slug}-validator_unit").as_bytes(),
                        ),
                        artifacts: artifacts(&service_root, &revision, &VALIDATOR_ARTIFACT_ROLES),
                        initial_state: ValidatorInitialStateV1::AdmittedRelease(
                            ValidatorAdmittedReleaseV1 {
                                service_state: PriorValidatorServiceStateV1::Running,
                                commit: "4".repeat(40),
                                release_root: format!("{service_root}/releases/{}", "4".repeat(40)),
                                argv: vec![
                                    format!("{service_root}/current/bin/iroha3d_taira"),
                                    "--config".to_owned(),
                                    format!("{service_root}/current/config/config.toml"),
                                    "--sora".to_owned(),
                                ],
                                artifacts: OCCUPIED_VALIDATOR_ARTIFACT_ROLES
                                    .iter()
                                    .map(|role| {
                                        let name = match *role {
                                            "iroha3d" => "bin/iroha3d_taira".to_owned(),
                                            "config" => "config/config.toml".to_owned(),
                                            "genesis" => "genesis/genesis.json".to_owned(),
                                            "genesis_hash" => "genesis/genesis.sha256".to_owned(),
                                            "validator_unit" => format!(
                                                "/etc/systemd/system/iroha3d-{slug}.service"
                                            ),
                                            _ => unreachable!(),
                                        };
                                        OccupiedArtifactV1 {
                                            role: (*role).to_owned(),
                                            path: if name.starts_with('/') {
                                                name
                                            } else {
                                                format!(
                                                    "{service_root}/releases/{}/{name}",
                                                    "4".repeat(40)
                                                )
                                            },
                                            sha256: sha256_hex(
                                                format!("occupied-{role}").as_bytes(),
                                            ),
                                            size: 1,
                                            mode: artifact_role_policy(role).unwrap().0,
                                            source_commit: "4".repeat(40),
                                        }
                                    })
                                    .collect(),
                            },
                        ),
                    }
                })
                .collect();
            let validator_clients = VALIDATOR_SLUGS
                .iter()
                .enumerate()
                .map(|(index, slug)| {
                    let account_key = iroha_crypto::KeyPair::try_from_seed(
                        vec![u8::try_from(index + 1).expect("four fixture validators"); 32],
                        Algorithm::Ed25519,
                    )
                    .expect("deterministic validator client key");
                    let peer_key = iroha_crypto::KeyPair::try_from_seed(
                        vec![u8::try_from(index + 17).expect("four fixture peers"); 32],
                        Algorithm::BlsNormal,
                    )
                    .expect("deterministic validator peer key");
                    ValidatorClientV1 {
                        slug: (*slug).to_owned(),
                        torii_origin: format!("https://taira-validator-{}.sora.org/", index + 1),
                        probe_origin: format!("http://127.0.0.1:{}/", 8080 + index),
                        account_id: AccountId::new(account_key.public_key().clone()).to_string(),
                        peer_id: PeerId::from(peer_key.public_key().clone()).to_string(),
                    }
                })
                .collect::<Vec<_>>();
            let placement_targets = validator_clients
                .iter()
                .map(|client| SoraInrouPlacementTargetV1 {
                    validator_account_id: AccountId::parse_encoded(&client.account_id)
                        .expect("canonical fixture validator account"),
                    peer_id: client.peer_id.clone(),
                })
                .collect();
            let edge_root = format!(
                "{}/.local/share/iroha/taira/edge",
                hosts.native_edge.owner_home
            );
            let edge_release = EdgeAdmittedReleaseV1 {
                commit: "4".repeat(40),
                release_root: format!("{edge_root}/releases/{}", "4".repeat(40)),
                cli_sha256: "a".repeat(64),
                config_sha256: "b".repeat(64),
            };
            let mut native_artifacts = artifacts(&edge_root, &revision, &EDGE_ARTIFACT_ROLES);
            for artifact in &mut native_artifacts {
                artifact.target = host_pair::NATIVE_EDGE_TARGET.into();
                if artifact.role == "iroha_cli" {
                    artifact.sha256 = hosts.native_edge.dispatcher_sha256.clone();
                    artifact.size = 64;
                }
            }
            let mut inventory = InventoryV1 {
                schema: INVENTORY_SCHEMA_V1.to_owned(),
                qualification_scope: QualificationScopeV1::FullInrou,
                deployment_id: "taira-public".to_owned(),
                chain_id: CHAIN_ID.to_owned(),
                chain_discriminant: CHAIN_DISCRIMINANT,
                previous_genesis_hash: Hash::new(b"fixture previous Taira genesis").to_string(),
                next_genesis_hash: Hash::new(b"fixture next Taira genesis").to_string(),
                authorization_nonce: "abcdefghijklmnopqrstuvwx12345678".to_owned(),
                revision: revision.clone(),
                hosts: hosts.clone(),
                beacon_bootstrap: host::beacon::fixture_plan(
                    &validators,
                    &validator_clients,
                    iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                        iroha_data_model::block::BlockHeader,
                    >::from_untyped_unchecked(
                        Hash::new(b"fixture next Taira genesis"),
                    )),
                ),

                validators,
                validator_clients,
                operator_public_key: iroha_crypto::KeyPair::from_seed(
                    b"fixture dedicated operator".to_vec(),
                    Algorithm::Ed25519,
                )
                .public_key()
                .to_string(),
                edge: EdgeV1 {
                    slug: "taira-edge".to_owned(),
                    endpoint: endpoint(&hosts.native_edge, &edge_root, &revision),
                    platform: PlatformV1 {
                        os: "macos".to_owned(),
                        arch: "aarch64".to_owned(),
                        kvm_api_version: 0,
                    },
                    service_root: edge_root.to_owned(),
                    state_root: format!("{edge_root}/state"),
                    reset_guard: format!("{}/taira-edge", hosts.native_edge.custody_root),
                    nginx_config:
                        "/opt/homebrew/etc/nginx/servers/taira-public-validator-listeners.conf"
                            .into(),
                    artifacts: native_artifacts,
                    native_capability: native_edge_protocol::fixture_capability(
                        &hosts,
                        edge_release.clone(),
                        "abcdefghijklmnopqrstuvwx12345678",
                        &Hash::new(b"fixture previous Taira genesis").to_string(),
                    ),
                    initial_state: EdgeInitialStateV1::AdmittedRelease(edge_release),
                },
                inrou_canary: Some(InrouCanaryV1 {
                    public_root: PUBLIC_ROOT.to_owned(),
                    service_name: "taira_inrou_canary".to_owned(),
                    service_version: format!(
                        "artifact-{}",
                        Hash::new(b"fixture Inrou service revision")
                    ),
                    replicas: 4,
                    route_host: "taira.sora.org".to_owned(),
                    route_path_prefix: "/api/v1/inrou-canary".to_owned(),
                    healthcheck_path: "/health".to_owned(),
                    bundle_hash: iroha_crypto::Hash::new(b"fixture Inrou bundle").to_string(),
                    bundle_content_cid: "sora1bundle".to_owned(),
                    bundle_manifest_digest_hex: "8".repeat(64),
                    guest_content_cid: "sora1guest".to_owned(),
                    guest_manifest_digest_hex: "9".repeat(64),
                    discovery_payload_dir: "payloads/discovery".to_owned(),
                    discovery_manifest_file: "manifests/discovery.to".to_owned(),
                    discovery_document_hash: iroha_crypto::Hash::new(
                        b"fixture Inrou discovery document",
                    )
                    .to_string(),
                    discovery_content_cid: "sora1discovery".to_owned(),
                    discovery_manifest_digest_hex: "7".repeat(64),
                    public_discovery_url:
                        "https://taira.sora.org/sorafs/cid/sora1discovery/index.json".to_owned(),
                    public_discovery_cid_host_url:
                        "https://sora1discovery.sorafs.taira.sora.org/index.json".to_owned(),
                    deployment_bundle_hash: iroha_crypto::Hash::new(
                        b"fixture Inrou deployment bundle",
                    )
                    .to_string(),
                    container_manifest_hash: iroha_crypto::Hash::new(
                        b"fixture Inrou container manifest",
                    )
                    .to_string(),
                    service_manifest_hash: iroha_crypto::Hash::new(
                        b"fixture Inrou service manifest",
                    )
                    .to_string(),
                    placement_targets,
                    stage_tree_sha256: "a".repeat(64),
                    stage_bytes: 6,
                    receipt_sha256: "b".repeat(64),
                    container_sha256: "c".repeat(64),
                    service_sha256: "d".repeat(64),
                    bundle_payload_sha256: "e".repeat(64),
                    bundle_manifest_sha256: "f".repeat(64),
                    guest_manifest_sha256: "0".repeat(64),
                    discovery_document_sha256: "1".repeat(64),
                    discovery_manifest_sha256: "2".repeat(64),
                }),
                canary_onboarding_request,
                faucet_policy: FaucetPolicyV1 {
                    authority: AccountId::new(faucet_key_pair.public_key().clone()).to_string(),
                    asset_definition_id: crate::taira::DEFAULT_GAS_ASSET_ID.to_owned(),
                    amount: Quantity::from(25_000_u32),
                },
                fee_intent: FeeIntentV1 {
                    payer: "authority".to_owned(),
                    sponsor_program: None,
                    sponsor_program_revision: None,
                },
                cleanup: CleanupV1 {
                    policy: "marker_bound_generated_waste_v1".to_owned(),
                    max_reclaim_bytes_per_host: 16 * 1024 * 1024 * 1024,
                    minimum_age_secs: 86_400,
                    retain_successful_releases: 2,
                    delete_only_marker_bound_generated_paths: true,
                    preserve_state: true,
                    preserve_secrets: true,
                    preserve_rollback_release: true,
                },
                timeouts: TimeoutsV1 {
                    stop_secs: 30,
                    install_secs: 60,
                    reset_secs: 60,
                    preseed_secs: 60,
                    start_secs: 60,
                    convergence_secs: 120,
                    canary_secs: 120,
                    restart_secs: 120,
                    edge_secs: 30,
                    cleanup_secs: 60,
                    rollback_secs: 60,
                },
                artifact_closure_sha256: String::new(),
                runtime_client_config_sha256: "1".repeat(64),
                onboarding_token_sha256: "2".repeat(64),
                validator_client_configs_sha256: "3".repeat(64),
                inrou_stage_tree_sha256: Some("a".repeat(64)),
            };
            inventory.artifact_closure_sha256 = artifact_closure_sha256(&inventory);
            inventory
        }

        fn endpoint(
            host: &host_pair::ResetHostV1,
            root: &str,
            revision: &RevisionV1,
        ) -> EndpointV1 {
            EndpointV1 {
                hostname: host.endpoint.hostname.clone(),
                port: host.endpoint.port,
                user: host.endpoint.user.clone(),
                known_host_line_sha256: host.endpoint.known_host_line_sha256.clone(),
                host_identity_sha256: host.endpoint.host_identity_sha256.clone(),
                upload_guard_sha256: host.guard_sha256.clone(),
                remote_cli: format!("{root}/releases/{}/bin/iroha", revision.commit),
            }
        }

        fn artifacts(root: &str, revision: &RevisionV1, roles: &[&str]) -> Vec<ArtifactV1> {
            roles
                .iter()
                .map(|role| {
                    let file_name = match *role {
                        "iroha3d" => "bin/iroha3d_taira",
                        "iroha_cli" => "bin/iroha",
                        "kagami" => "bin/kagami",
                        "sorafs_node" => "bin/sorafs-node",
                        "config" => "config/config.toml",
                        "genesis" => "genesis/genesis.json",
                        "genesis_hash" => "genesis/genesis.sha256",
                        "validator_unit" => "systemd/unit",
                        "edge_config" => "taira.conf",
                        _ => panic!("unknown fixture artifact role"),
                    };
                    let file_name = if *role == "validator_unit" {
                        let slug = Path::new(root).file_name().unwrap().to_str().unwrap();
                        format!("systemd/iroha3d-{slug}.service")
                    } else {
                        file_name.to_owned()
                    };
                    // Use the same content/name projection as materialize_artifact_sources:
                    // binaries/genesis are shared, while each node's config is distinct.
                    let source_name = if matches!(*role, "config" | "validator_unit") {
                        let slug = Path::new(root)
                            .file_name()
                            .and_then(std::ffi::OsStr::to_str)
                            .expect("fixture service slug");
                        format!("{slug}-{role}")
                    } else {
                        (*role).to_owned()
                    };
                    ArtifactV1 {
                        role: (*role).to_owned(),
                        local_path: format!("/private/runtime/{source_name}"),
                        remote_path: format!("{root}/releases/{}/{file_name}", revision.commit),
                        sha256: sha256_hex(source_name.as_bytes()),
                        size: u64::try_from(source_name.len()).expect("small fixture artifact"),
                        mode: artifact_role_policy(role)
                            .expect("canonical fixture artifact role")
                            .0,
                        source_commit: revision.commit.clone(),
                        target: BUILD_TARGET.to_owned(),
                    }
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod operator_admission_tests {
    use super::*;

    #[test]
    fn operator_public_key_is_canonical_ed25519_and_authorization_bound() {
        let mut inventory = sample_inventory_fixture();
        validator_operator_public_key(&inventory.operator_public_key).unwrap();
        let before = canonical_inventory_bytes(&inventory).unwrap();
        inventory.operator_public_key = iroha_crypto::KeyPair::from_seed(
            b"distinct deployment operator".to_vec(),
            Algorithm::Ed25519,
        )
        .public_key()
        .to_string();
        assert_ne!(before, canonical_inventory_bytes(&inventory).unwrap());
        for invalid in [
            String::new(),
            "invalid".to_owned(),
            inventory.operator_public_key.to_uppercase(),
        ] {
            assert!(validator_operator_public_key(&invalid).is_err());
        }
        let other =
            iroha_crypto::KeyPair::from_seed(b"other algorithm".to_vec(), Algorithm::Secp256k1);
        assert!(validator_operator_public_key(&other.public_key().to_string()).is_err());
    }

    #[test]
    fn operator_policy_requires_explicit_enabled_allowlist_and_rejects_inference() {
        let key = sample_inventory_fixture().operator_public_key;
        let policy = format!(
            "[torii.operator_signatures]\nenabled = true\nallowed_public_keys = [{key:?}]\n"
        );
        validate_validator_operator_config(policy.as_bytes(), &key).unwrap();
        for invalid in [
            String::new(),
            policy.replace("true", "false"),
            policy.replace(&format!("[{key:?}]"), "[]"),
            "[torii.operator_signatures]\nenabled = true\nallow_node_key = true\n".to_owned(),
            format!("extends = []\n{policy}"),
        ] {
            assert!(validate_validator_operator_config(invalid.as_bytes(), &key).is_err());
        }
        let foreign =
            iroha_crypto::KeyPair::from_seed(b"foreign operator".to_vec(), Algorithm::Ed25519);
        assert!(
            validate_validator_operator_config(
                policy.as_bytes(),
                &foreign.public_key().to_string()
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod signed_genesis_startup_tests {
    use super::*;

    fn fixture() -> (String, String, PathBuf) {
        let hash = Hash::new(b"ephemeral genesis startup regression");
        let network = iroha::data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(hash),
        );
        let path =
            PathBuf::from("/srv/taira/taira-validator-1/releases/actual/genesis/genesis.json");
        (
            format!(
                "[genesis]\nfile = {:?}\nexpected_hash = {:?}\n",
                path.to_str().unwrap(),
                network.to_string()
            ),
            hash.to_string(),
            path,
        )
    }

    #[test]
    fn signed_genesis_startup_accepts_exact_artifact_and_checked_identity() {
        let (config, hash, path) = fixture();
        validate_validator_genesis_config(config.as_bytes(), &path, &hash).unwrap();
    }

    #[test]
    fn signed_genesis_startup_rejects_unbound_manifest_identity_and_inheritance() {
        let (config, hash, path) = fixture();
        for field in [
            "manifest_json = '/tmp/manifest.json'",
            "expected_hash_file = '/tmp/network-id'",
        ] {
            assert!(
                validate_validator_genesis_config(
                    format!("{config}{field}\n").as_bytes(),
                    &path,
                    &hash
                )
                .is_err()
            );
        }
        for extends in [
            "extends = []",
            "extends = '/tmp/base.toml'",
            "extends = ['/tmp/base.toml']",
        ] {
            assert!(
                validate_validator_genesis_config(
                    format!("{extends}\n{config}").as_bytes(),
                    &path,
                    &hash
                )
                .is_err()
            );
        }
    }

    #[test]
    fn signed_genesis_startup_rejects_foreign_path_and_network() {
        let (config, hash, path) = fixture();
        assert!(
            validate_validator_genesis_config(
                config.as_bytes(),
                Path::new("/tmp/genesis.nrt"),
                &hash
            )
            .is_err()
        );
        assert!(
            validate_validator_genesis_config(
                config.as_bytes(),
                &path,
                &Hash::new(b"other network").to_string()
            )
            .is_err()
        );
        let bare = format!(
            "[genesis]\nfile = {:?}\nexpected_hash = {:?}\n",
            path.to_str().unwrap(),
            hash
        );
        assert!(validate_validator_genesis_config(bare.as_bytes(), &path, &hash).is_err());
        let missing = format!("[genesis]\nfile = {:?}\n", path.to_str().unwrap());
        assert!(validate_validator_genesis_config(missing.as_bytes(), &path, &hash).is_err());
    }
}

#[cfg(test)]
pub(crate) fn validate_inrou_checks_for_test(
    report: &norito::json::Value,
    scope: crate::taira::InrouProbeScope,
) -> Result<()> {
    host::validate_inrou_checks_for_test(report, scope)
}
