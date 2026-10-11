//! Config-free developer commands over shared managed environments and deployment services.

use std::{
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use clap::{Args, Subcommand};
use color_eyre::eyre::{Result, WrapErr as _, ensure, eyre};
use iroha_contract_deploy::{DeploymentPreflight, DeploymentProgress};
use iroha_data_model::{
    account::address::ChainDiscriminantGuard, asset::AssetDefinitionId,
    transaction::FeePaymentIntent,
};
use iroha_deploy::managed::{
    self, DataspaceRequest, InstalledRuntime, ManagedContext, ManagedDataspaceStatus, ManagedPhase,
    ManagedStatus, ManagedStore, default_state_root, workspace_state_root,
};
use iroha_primitives::numeric::Quantity;
use musubi::deployment_runtime::{AliasSelection, ContractInput, DeploymentRuntime};

use crate::{Outcome, RunArgs, localnet, tui};

/// Store selection and output formatting for managed developer commands.
#[derive(Debug, Clone, Args)]
pub struct StoreArgs {
    /// Private runtime store. By default each workspace has its own OS application-state directory.
    #[arg(long)]
    state: Option<PathBuf>,
    /// Workspace whose managed context is selected (defaults to the current directory).
    #[arg(long)]
    workspace: Option<PathBuf>,
    /// Emit one public JSON result; progress remains on stderr.
    #[arg(long)]
    json: bool,
}

impl StoreArgs {
    fn resolve_path(&self, path: &Path) -> Result<PathBuf> {
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }
        let workspace = self
            .workspace
            .clone()
            .map_or_else(std::env::current_dir, Ok)?;
        let workspace = workspace
            .canonicalize()
            .wrap_err("open selected workspace")?;
        ensure!(workspace.is_dir(), "selected workspace must be a directory");
        Ok(workspace.join(path))
    }

    fn open(&self) -> Result<ManagedStore> {
        let root = if let Some(path) = &self.state {
            path.clone()
        } else {
            let workspace = self
                .workspace
                .clone()
                .map_or_else(std::env::current_dir, Ok)?;
            workspace_state_root(&default_state_root()?, &workspace)?
        };
        ManagedStore::open(&root).map_err(Into::into)
    }
}

/// Manage a persistent native four-validator local network.
#[derive(Subcommand)]
pub enum LocalnetCommand {
    /// Generate, start, verify, and select a localnet without supplying configuration.
    Up(UpArgs),
    /// Observe the live supervisor and its retained environment.
    Status(NamedArgs),
    /// Read a bounded retained supervisor or validator log tail.
    Logs(LogsArgs),
    /// Stop the owned validators, preserving their identities and ledger.
    Down(NamedArgs),
    /// Explicitly retire one stopped generation so the next up creates a fresh ledger.
    Reset(ResetArgs),
    /// Generate an operator-owned network bundle without starting validators.
    Generate(localnet::Args),
    /// Validate an isolated native beacon configuration and opaque descriptor handoff.
    ValidateBeaconLaunch(localnet::ValidateBeaconLaunchArgs),
}

#[derive(Debug, Args)]
pub struct NamedArgs {
    /// Managed environment name.
    #[arg(default_value = "local")]
    name: String,
    #[command(flatten)]
    store: StoreArgs,
}

#[derive(Debug, Args)]
pub struct UpArgs {
    #[command(flatten)]
    named: NamedArgs,
    /// Complete generation and readiness budget in seconds.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=600))]
    timeout: u64,
}

#[derive(Debug, Args)]
pub struct LogsArgs {
    #[command(flatten)]
    named: NamedArgs,
    /// Validator index (0..3). Omit to read the supervisor log.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=3))]
    peer: Option<u8>,
    /// Maximum bytes returned from the end of the log.
    #[arg(long, default_value_t = 16384, value_parser = clap::value_parser!(u32).range(1..=1048576))]
    bytes: u32,
}

#[derive(Debug, Args)]
pub struct ResetArgs {
    /// Exact environment to retire; required to make reset deliberate.
    name: String,
    #[command(flatten)]
    store: StoreArgs,
}

/// Run an owner-private local dataspace attached to one independently installed parent.
#[derive(Debug, Subcommand)]
pub(crate) enum DataspaceCommand {
    /// Create, fund, register, and select four private validators without supplying configuration.
    Up(DataspaceUpArgs),
    /// Register a retained inactive AMX instance; explicitly run localnet down first.
    #[command(
        long_about = "Explicit administrative parent AMX registration of one retained private generation. Requires exclusive inactive custody: use `kagami localnet down NAME` before this action, then `kagami localnet up NAME` to restart that same generation. Signing material is selected only by --admin-config; recovery never renews the original fees or UTC deadline."
    )]
    RegisterAmx(DataspaceAmxRegistrationArgs),
    /// Observe local validators and independently verified parent attachment separately.
    Status(ContextShowArgs),
    /// List the independently pinned network profiles supplied by this installation.
    Networks(NetworksArgs),
}

#[derive(Debug, Args)]
pub(crate) struct DataspaceUpArgs {
    /// Canonical private dataspace alias to lease on the parent.
    alias: String,
    /// Exact independently installed parent profile, such as taira.
    #[arg(long)]
    network: String,
    /// Canonical owner label leased on the parent as LABEL@ALIAS; retained across retries.
    #[arg(long, default_value = "admin")]
    account_alias: String,
    /// Store-local context name (defaults to the dataspace alias).
    #[arg(long)]
    name: Option<String>,
    /// Complete parent authentication, local startup, and attachment budget in seconds.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=60))]
    timeout: u64,
    #[command(flatten)]
    store: StoreArgs,
}

#[derive(Debug, Args)]
pub(crate) struct DataspaceAmxRegistrationArgs {
    /// Exact retained private managed context; no new child is prepared.
    name: String,
    /// Explicit parent administrative client configuration, with runtime-only signing custody.
    #[arg(long)]
    admin_config: PathBuf,
    /// Exact parent fee asset; no asset is inferred from the child or SNS owner.
    #[arg(long)]
    fee_asset: AssetDefinitionId,
    /// Positive aggregate fee ceiling for the original transaction.
    #[arg(long)]
    max_fee: Quantity,
    /// Original exclusive Unix millisecond signing authorization; repeat unchanged on recovery.
    #[arg(long)]
    deadline_unix_ms: u64,
    /// Fresh I/O budget only, bounded by the original authorization and release.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=60))]
    timeout: u64,
    #[command(flatten)]
    store: StoreArgs,
}

#[derive(Debug, Args)]
pub(crate) struct NetworksArgs {
    /// Emit the installed profile names as one JSON array.
    #[arg(long)]
    json: bool,
}

/// Select and inspect managed developer identities and endpoints.
#[derive(Debug, Subcommand)]
pub enum ContextCommand {
    /// List retained contexts in this workspace.
    List(StoreArgs),
    /// Show the selected context, or one exact named context.
    Show(ContextShowArgs),
    /// Select an existing context for subsequent developer commands.
    Use(ContextUseArgs),
}

#[derive(Debug, Args)]
pub struct ContextShowArgs {
    name: Option<String>,
    #[command(flatten)]
    store: StoreArgs,
}

#[derive(Debug, Args)]
pub struct ContextUseArgs {
    name: String,
    #[command(flatten)]
    store: StoreArgs,
}

/// Publish a package through the retained generated developer environment.
#[derive(Debug, Subcommand)]
pub enum PackageCommand {
    /// Publish with original generated client/namespace intent and the canonical durable engine.
    Publish(PackagePublishArgs),
}
/// Original managed publication selection and exact begin/recovery action.
#[derive(Debug, Args)]
pub struct PackagePublishArgs {
    /// Package/workspace manifest or directory (defaults to the selected workspace).
    manifest: Option<PathBuf>,
    #[command(flatten)]
    store: StoreArgs,
    /// Use this exact retained environment without changing workspace selection.
    #[arg(long)]
    context: Option<String>,
    /// Exact package when the workspace contains more than one selected member.
    #[arg(long, conflicts_with_all = ["resume", "recover"])]
    package: Option<iroha_data_model::musubi::MusubiPackageSelectorV1>,
    /// Return at the canonical durable seed-ingress boundary.
    #[arg(long, conflicts_with_all = ["resume", "recover"])]
    detach: bool,
    /// Continue one original publication operation; requires an existing selected context.
    #[arg(long, conflicts_with = "recover")]
    resume: Option<musubi::publish::PublicationOperationIdV1>,
    /// Recover pristine package sidecars for one original operation; never creates a new context.
    #[arg(long, conflicts_with = "resume")]
    recover: Option<musubi::publish::PublicationOperationIdV1>,
}

/// Compile and deploy through the canonical native service.
#[derive(Debug, Subcommand)]
pub enum ContractCommand {
    /// Deploy source, bytecode, or a Musubi package; automatically start a default localnet if needed.
    Deploy(DeployArgs),
    /// Read a verified deployed view in the selected managed environment.
    View(ContractViewArgs),
    /// Prepare, execute or resume a finite durable mutable call.
    Call(ContractCallArgs),
}

/// Selected managed deployment view, without caller-supplied configuration or intent files.
#[derive(Debug, Args)]
pub struct ContractViewArgs {
    /// Exact deployed contract alias.
    alias: String,
    #[command(flatten)]
    store: StoreArgs,
    /// Existing managed environment; otherwise use the workspace selection.
    #[arg(long)]
    context: Option<String>,
    /// Read-only public entrypoint.
    #[arg(long)]
    entrypoint: String,
    /// Named arguments validated against the retained deployed interface.
    #[arg(long, default_value = "{}")]
    args: String,
    /// Positive view execution budget.
    #[arg(long, default_value_t = 1_500_000, value_parser = clap::value_parser!(u64).range(1..=10_000_000))]
    gas_limit: u64,
}

/// Finite native call authorization or exact journal recovery.
#[derive(Debug, Args)]
pub struct ContractCallArgs {
    /// Exact deployed alias for a fresh operation.
    #[arg(required_unless_present = "resume", conflicts_with = "resume")]
    alias: Option<String>,
    #[command(flatten)]
    store: StoreArgs,
    /// Existing managed environment; otherwise use the workspace selection.
    #[arg(long)]
    context: Option<String>,
    /// Mutable public selector, including an explicitly requested lifecycle hook.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    entrypoint: Option<String>,
    /// Named arguments validated and encoded natively from the retained deployed interface.
    #[arg(long, default_value = "{}", conflicts_with = "resume")]
    args: String,
    /// Positive aggregate cap across any exact self-grant and the call in the generated fee asset.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    max_fee: Option<Quantity>,
    /// Signature-bound mutable execution budget.
    #[arg(long, default_value_t = 1_500_000, value_parser = clap::value_parser!(u64).range(1..=10_000_000), conflicts_with = "resume")]
    gas_limit: u64,
    /// Original signing interval, retained unchanged when the operation is resumed.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=600), conflicts_with = "resume")]
    timeout: u64,
    /// Persist the exact original authorization without submitting either stage.
    #[arg(long, conflicts_with = "resume")]
    prepare: bool,
    /// Recover this exact managed call without a new authorization or replacement transaction.
    #[arg(long)]
    resume: Option<PathBuf>,
    /// Explicit view to read after Applied; its availability is reported separately.
    #[arg(long)]
    readback: Option<String>,
    /// Named arguments for the explicitly selected readback view.
    #[arg(long, default_value = "{}", requires = "readback")]
    readback_args: String,
    /// Independent positive gas budget for the readback view.
    #[arg(long, default_value_t = 1_500_000, value_parser = clap::value_parser!(u64).range(1..=10_000_000), requires = "readback")]
    readback_gas_limit: u64,
}

#[derive(Debug, Args)]
pub struct DeployArgs {
    /// .ko source, .to artifact, Musubi.toml, or package directory (defaults to the current directory).
    #[arg(conflicts_with = "resume")]
    input: Option<PathBuf>,
    #[command(flatten)]
    store: StoreArgs,
    /// Use an existing managed context without changing the workspace selection.
    #[arg(long)]
    context: Option<String>,
    /// Exact authorized contract alias; otherwise derive the name in the context's dataspace.
    #[arg(long, conflicts_with = "resume")]
    alias: Option<String>,
    /// Exact Musubi package when the input selects a workspace.
    #[arg(long, conflicts_with = "resume")]
    package: Option<String>,
    /// Exact target when a package has more than one contract.
    #[arg(long, conflicts_with = "resume")]
    contract: Option<String>,
    /// Require an unchanged Musubi dependency lock.
    #[arg(long, conflicts_with = "resume")]
    locked: bool,
    /// Recover this exact retained deployment without rebuilding or signing another plan.
    #[arg(long)]
    resume: Option<PathBuf>,
    /// Bound the aggregate quoted fees in their single fee asset before dispatch.
    #[arg(long, conflicts_with = "resume")]
    max_fee: Option<Quantity>,
}

/// Internal entry point for the shared native supervisor.
#[derive(Debug, Args)]
pub struct WorkerArgs {
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    name: String,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=600000))]
    startup_timeout_ms: u64,
    #[arg(long)]
    startup_deadline_ns: u128,
}

impl<T: Write> RunArgs<T> for WorkerArgs {
    fn run(self, _: &mut BufWriter<T>) -> Outcome {
        let store = ManagedStore::open(&self.root)?;
        managed::run_worker(
            &store,
            &self.name,
            Duration::from_millis(self.startup_timeout_ms),
            self.startup_deadline_ns,
        )?;
        Ok(())
    }
}

impl<T: Write> RunArgs<T> for LocalnetCommand {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        match self {
            Self::Generate(args) => args.run(writer),
            Self::ValidateBeaconLaunch(args) => args.run(writer),
            Self::Up(args) => {
                let store = args.named.store.open()?;
                match up(&store, &args.named.name, args.timeout) {
                    Ok(status) if status.phase == ManagedPhase::Ready => {
                        print_status(writer, &status, args.named.store.json)
                    }
                    Ok(status) => localnet_failure(
                        writer,
                        store.root(),
                        &args.named.name,
                        Some(&status),
                        args.named.store.json,
                        eyre!("localnet is not ready"),
                    ),
                    Err(error) => {
                        // Observation cannot replace the original error or create a generation.
                        let retained = store.status(&args.named.name).ok();
                        localnet_failure(
                            writer,
                            store.root(),
                            &args.named.name,
                            retained.as_ref(),
                            args.named.store.json,
                            error,
                        )
                    }
                }
            }
            Self::Status(args) => print_status(
                writer,
                &args.store.open()?.status(&args.name)?,
                args.store.json,
            ),
            Self::Down(args) => print_status(
                writer,
                &args.store.open()?.down(&args.name)?,
                args.store.json,
            ),
            Self::Reset(args) => {
                let store = args.store.open()?;
                store.reset(&args.name)?;
                print_reset(writer, store.root(), &args.name, args.store.json)
            }
            Self::Logs(args) => {
                let logs = args.named.store.open()?.logs(
                    &args.named.name,
                    args.peer.map(usize::from),
                    args.bytes as usize,
                )?;
                if args.named.store.json {
                    write_json(
                        writer,
                        &norito::json!({"name": (args.named.name), "log": logs}),
                    )
                } else {
                    write!(writer, "{logs}")?;
                    Ok(())
                }
            }
        }
    }
}

impl<T: Write> RunArgs<T> for ContextCommand {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        match self {
            Self::List(args) => {
                let contexts = args.open()?.contexts()?;
                if args.json {
                    return write_json(writer, &contexts);
                }
                for context in contexts {
                    print_context(writer, &context, false)?;
                }
                Ok(())
            }
            Self::Show(args) => print_context(
                writer,
                &args.store.open()?.context(args.name.as_deref())?,
                args.store.json,
            ),
            Self::Use(args) => print_context(
                writer,
                &args.store.open()?.select(&args.name)?,
                args.store.json,
            ),
        }
    }
}

impl<T: Write> RunArgs<T> for DataspaceCommand {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        match self {
            Self::Up(args) => {
                let store = args.store.open()?;
                let request = DataspaceRequest {
                    name: args.name.unwrap_or_else(|| args.alias.clone()),
                    network: args.network,
                    alias: args.alias,
                    account_alias: args.account_alias,
                    timeout: Duration::from_secs(args.timeout),
                };
                tui::status("Authenticating the installed parent and preparing private validators");
                match InstalledRuntime::discover()
                    .and_then(|runtime| store.up_dataspace(&runtime, &request))
                {
                    Ok(status) => print_dataspace_status(writer, &status, args.store.json),
                    Err(error) => {
                        let retained = store.dataspace_status(&request.name).ok().flatten();
                        dataspace_failure(
                            writer,
                            store.root(),
                            &request.name,
                            retained.as_ref(),
                            args.store.json,
                            error.into(),
                        )
                    }
                }
            }
            Self::RegisterAmx(args) => {
                let administrator =
                    iroha::config::Config::load_file(args.store.resolve_path(&args.admin_config)?)
                        .wrap_err("open explicitly selected parent administrator")?;
                let options = managed::ManagedAmxRegistrationOptions {
                    fee_asset: args.fee_asset,
                    max_fee: args.max_fee,
                    deadline_unix_ms: args.deadline_unix_ms,
                    timeout: Duration::from_secs(args.timeout),
                };
                let result = args.store.open()?.register_amx_dataspace(
                    &InstalledRuntime::discover()?, &args.name, &administrator, &options,
                ).wrap_err("administrative AMX registration failed; retain the exact original source and operation")?;
                let (finalized, outcome) = match result.finalized {
                    Some(iroha_deploy::attachment::AmxRegistrationFinality::Registered(
                        finality,
                    )) => (Some(finality), "registered"),
                    Some(iroha_deploy::attachment::AmxRegistrationFinality::Rejected(finality)) => {
                        (Some(finality), "rejected")
                    }
                    None => (None, "pending"),
                };
                let receipt = norito::json!({
                    "context": (args.name), "outcome": outcome,
                    "transaction_status": (result.transaction_status.map(|status| status.as_str())),
                    "finality": (finalized.map(|f| norito::json!({
                        "transaction_hash": (f.transaction_hash.to_string()), "height": (f.height),
                        "block_hash": (f.block_hash.to_string()), "block_time_ms": (f.block_time_ms),
                    }))),
                });
                write_json(writer, &receipt)?;
                ensure!(
                    outcome == "registered",
                    "AMX registration is {outcome}; retain the original administrative journal"
                );
                Ok(())
            }
            Self::Status(args) => {
                let store = args.store.open()?;
                let context = store.context(args.name.as_deref())?;
                let status = store.dataspace_status(&context.name)?.ok_or_else(|| {
                    eyre!(
                        "context `{}` has no remote dataspace attachment",
                        context.name
                    )
                })?;
                print_dataspace_status(writer, &status, args.store.json)
            }
            Self::Networks(args) => {
                let profiles = InstalledRuntime::discover()?.network_profiles()?;
                let names: Vec<_> = profiles.names().collect();
                if args.json {
                    write_json(writer, &names)
                } else {
                    for name in names {
                        writeln!(writer, "{name}")?;
                    }
                    Ok(())
                }
            }
        }
    }
}

/// An already-rendered canonical publication outcome; main preserves its exact exit status.
#[derive(Debug)]
pub(crate) struct PublicationExit(pub(crate) u8);
impl std::fmt::Display for PublicationExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("package publication did not complete")
    }
}
impl std::error::Error for PublicationExit {}

impl<T: Write> RunArgs<T> for PackageCommand {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let Self::Publish(args) = self;
        let action = if let Some(operation_id) = args.resume {
            musubi::generated_publication::GeneratedPublishAction::Resume { operation_id }
        } else if let Some(operation_id) = args.recover {
            musubi::generated_publication::GeneratedPublishAction::Recover { operation_id }
        } else {
            musubi::generated_publication::GeneratedPublishAction::Begin {
                package: args.package.clone(),
                detach: args.detach,
            }
        };
        let manifest = args
            .store
            .resolve_path(args.manifest.as_deref().unwrap_or_else(|| Path::new(".")))?;
        let action =
            musubi::generated_publication::prepare_generated_publish_action(&manifest, action)?;
        let store = args.store.open()?;
        if !matches!(
            &action,
            musubi::generated_publication::GeneratedPublishAction::Begin { .. }
        ) {
            store.context(args.context.as_deref())?;
        }
        let runtime = InstalledRuntime::discover()?;
        let selected = store
            .ensure_selected(&runtime, args.context.as_deref(), Duration::from_secs(30))?
            .context;
        let prepared = store.prepared(&selected.name)?;
        ensure!(
            prepared.context == selected,
            "selected publication generation changed"
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        let original = prepared
            .publication_client_config()?
            .ok_or_else(|| eyre!("selected generation has no generated publication intent"))?;
        let context =
            musubi::publication_runtime::GeneratedPublicationContextV1::from_original_image(
                original.client_config_path(),
                original.client_config_image(),
                original.publication_transport()?,
                musubi::publication_runtime::GeneratedPublicationNamespaceIntentV1 {
                    publisher: original.publisher().clone(),
                    binding: original.namespace_binding().clone(),
                    policy: original.registry_policy().clone(),
                    fee_payment: original.namespace_fee_payment(),
                    journal_root: original.namespace_journal_root().to_path_buf(),
                },
            )?;
        let (registry, archive_transport) = store
            .build_registry(&runtime, &selected.name, deadline)?
            .ok_or_else(|| eyre!("selected generation has no authenticated build registry"))?;
        ensure!(
            registry.account == *original.publisher()
                && registry.network_id == original.service_plan().network_id()
                && registry.chain.as_str() == original.service_plan().chain_id()
                && registry.torii_api_url.as_str() == prepared.context.torii_url
                && store.prepared(&selected.name)? == prepared,
            "generated publication registry or generation changed"
        );
        let request = musubi::generated_publication::GeneratedPublishRequest {
            manifest_path: manifest,
            state_root: original.publication_state_root(),
            cache_root: original.publication_cache_root(),
            archive_transport,
            action,
        };
        let outcome = musubi::generated_publication::publish_generated(&context, &request);
        let format = if args.store.json {
            musubi::generated_publication::OutputFormat::Json
        } else {
            musubi::generated_publication::OutputFormat::Human
        };
        outcome
            .render(format)?
            .write_to(writer, &mut std::io::stderr().lock())?;
        if outcome.exit_code() != 0 {
            return Err(PublicationExit(u8::try_from(outcome.exit_code())?).into());
        }
        Ok(())
    }
}

impl<T: Write> RunArgs<T> for ContractCommand {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        match self {
            Self::Deploy(args) => args.run(writer),
            Self::View(args) => args.run(writer),
            Self::Call(args) => args.run(writer),
        }
    }
}

impl<T: Write> RunArgs<T> for DeployArgs {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let args = self;
        // Reject local input mistakes before provisioning a network or selecting an identity.
        let resume = args
            .resume
            .as_ref()
            .map(|path| args.store.resolve_path(path))
            .transpose()?;
        let input = if resume.is_none() {
            let path = args
                .store
                .resolve_path(args.input.as_deref().unwrap_or_else(|| Path::new(".")))?;
            Some(ContractInput::from_path(
                &path,
                args.package,
                args.contract,
                args.locked,
            )?)
        } else {
            None
        };
        let exact_alias = args
            .alias
            .map(|alias| alias.parse().wrap_err("invalid contract alias"))
            .transpose()?;
        let store = args.store.open()?;
        let runtime = InstalledRuntime::discover()?;
        // Recovery must retain an explicit or previously selected identity. It never creates
        // another default environment merely because its original selection disappeared.
        if resume.is_some() {
            store.context(args.context.as_deref())?;
        }
        let context = store
            .ensure_selected(&runtime, args.context.as_deref(), Duration::from_secs(30))?
            .context;
        let target = store.capture_deployment(&context)?;
        let config = context.load_client_config()?;
        let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
        let journal_root = store.root().join("deployments").join(&context.name);
        let prepared = store.prepared(&context.name)?;
        ensure!(
            prepared.context == context,
            "deployment generation changed before cache selection"
        );
        let cache_root = prepared.build_cache_root();
        let registry_root = store.root().to_path_buf();
        let registry_context = context.name.clone();
        let runtime = DeploymentRuntime::new(config, journal_root, cache_root)
            .with_build_registry_resolver(Arc::new(move || {
                // The canonical package service calls this only when a graph needs its exact
                // registry identity. Source, bytecode and local packages never enter it.
                let deadline = Instant::now() + Duration::from_secs(60);
                let store = ManagedStore::open(&registry_root)?;
                Ok(store.build_registry(&runtime, &registry_context, deadline)?)
            }));
        let mut progress = deployment_progress;
        let mut review = |preflight: &DeploymentPreflight| {
            ensure!(
                preflight.dataspace_id.as_u64() == context.dataspace_id,
                "deployment resolved outside the selected dataspace"
            );
            check_fee_budget(
                preflight
                    .fee_quotes
                    .iter()
                    .flat_map(|quote| &quote.components)
                    .map(|component| (&component.asset_definition_id, &component.max_amount)),
                args.max_fee.as_ref(),
            )
        };
        let deployed = if let Some(journal) = resume {
            runtime.resume(&journal, &mut review, &mut progress)?
        } else {
            let input = input.ok_or_else(|| eyre!("deployment input is missing"))?;
            let alias = match exact_alias {
                Some(alias) => AliasSelection::Exact(alias),
                None => AliasSelection::Scope {
                    domain: None,
                    dataspace: context.dataspace_alias.clone(),
                },
            };
            runtime.deploy(
                &input,
                &alias,
                FeePaymentIntent::authority(Vec::new(), None),
                &mut review,
                &mut progress,
            )?
        };
        let mut report = target.finish(&store, deployed.receipt, deployed.journal)?;
        report.lifecycle = deployed.lifecycle;
        if args.store.json {
            write_json(writer, &report.to_json()?)
        } else {
            writeln!(
                writer,
                "{}: {}",
                report.execution_summary(),
                report.receipt.contract_alias
            )?;
            writeln!(writer, "address: {}", report.receipt.contract_address)?;
            writeln!(writer, "code_hash: {}", report.receipt.code_hash)?;
            writeln!(writer, "journal: {}", report.journal.display())?;
            if let Some(lifecycle) = &report.lifecycle {
                writeln!(writer, "{}", lifecycle.summary())?;
            }
            if let Some(parent) = report.parent_summary() {
                writeln!(writer, "{parent}")?;
            }
            Ok(())
        }
    }
}

fn managed_contract_context(
    store: &ManagedStore,
    requested: Option<&str>,
) -> Result<ManagedContext> {
    // Calls and views select an existing identity. They never create another default ledger.
    store.context(requested)?;
    Ok(store
        .ensure_selected(
            &InstalledRuntime::discover()?,
            requested,
            Duration::from_secs(30),
        )?
        .context)
}

fn view_request(
    entrypoint: String,
    arguments: &str,
    gas_limit: u64,
) -> Result<managed::ManagedContractViewRequest> {
    ensure!(
        !entrypoint.is_empty() && entrypoint.trim() == entrypoint,
        "entrypoint must use its exact public selector"
    );
    ensure!(
        arguments.len() <= 64 * 1024,
        "contract arguments exceed the 64 KiB bound"
    );
    let arguments = iroha_contract_deploy::call::parse_contract_arguments(arguments)?;
    Ok(managed::ManagedContractViewRequest {
        entrypoint,
        arguments,
        gas_limit: std::num::NonZeroU64::new(gas_limit)
            .ok_or_else(|| eyre!("gas limit must be positive"))?,
    })
}

impl<T: Write> RunArgs<T> for ContractViewArgs {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let alias = self.alias.parse().wrap_err("invalid contract alias")?;
        let request = view_request(self.entrypoint, &self.args, self.gas_limit)?;
        let store = self.store.open()?;
        let context = managed_contract_context(&store, self.context.as_deref())?;
        let config = context.load_client_config()?;
        let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
        let prepared = store.prepared(&context.name)?;
        ensure!(
            prepared.context == context,
            "deployment generation changed before cache selection"
        );
        let deployed = DeploymentRuntime::new(
            config,
            store.root().join("deployments").join(&context.name),
            prepared.build_cache_root(),
        )
        .current_deployment(&alias)?;
        let result = store.view_contract(&context, &deployed.contract, request)?;
        if self.store.json {
            write_json(writer, &result)
        } else {
            write_json(writer, &result.result)
        }
    }
}

impl<T: Write> RunArgs<T> for ContractCallArgs {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let readback = self
            .readback
            .map(|entrypoint| {
                view_request(entrypoint, &self.readback_args, self.readback_gas_limit)
            })
            .transpose()?;
        let resumed = self
            .resume
            .as_ref()
            .map(|path| self.store.resolve_path(path))
            .transpose()?;
        let requested = if resumed.is_none() {
            let alias = self
                .alias
                .as_ref()
                .ok_or_else(|| eyre!("call requires a contract alias"))?
                .parse()
                .wrap_err("invalid contract alias")?;
            let request = view_request(
                self.entrypoint
                    .clone()
                    .ok_or_else(|| eyre!("call requires --entrypoint"))?,
                &self.args,
                self.gas_limit,
            )?;
            let max_fee = self
                .max_fee
                .clone()
                .ok_or_else(|| eyre!("call requires --max-fee"))?;
            ensure!(!max_fee.is_zero(), "--max-fee must be positive");
            Some((alias, request, max_fee))
        } else {
            None
        };
        let store = self.store.open()?;
        let context = managed_contract_context(&store, self.context.as_deref())?;
        let config = context.load_client_config()?;
        let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
        let report = if let Some(journal) = resumed {
            store.resume_contract_call(&context, &journal, readback)?
        } else {
            let (alias, request, max_fee) =
                requested.ok_or_else(|| eyre!("call request is missing"))?;
            let prepared = store.prepared(&context.name)?;
            ensure!(
                prepared.context == context,
                "deployment generation changed before cache selection"
            );
            let deployed = DeploymentRuntime::new(
                config,
                store.root().join("deployments").join(&context.name),
                prepared.build_cache_root(),
            )
            .current_deployment(&alias)?;
            let now = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis(),
            )?;
            let deadline = now
                .checked_add(
                    self.timeout
                        .checked_mul(1000)
                        .ok_or_else(|| eyre!("call interval overflow"))?,
                )
                .ok_or_else(|| eyre!("call deadline overflow"))?;
            store.call_contract(
                &context,
                &deployed.contract,
                &request.entrypoint,
                request.arguments,
                managed::ManagedContractCallOptions {
                    max_fee,
                    signing_deadline_unix_ms: deadline,
                    gas_limit: request.gas_limit,
                    prepare_only: self.prepare,
                    readback,
                },
            )?
        };
        if self.store.json {
            write_json(writer, &report)
        } else {
            writeln!(writer, "{} on {}", report.status, report.context)?;
            writeln!(writer, "journal: {}", report.journal.display())?;
            if let Some(receipt) = &report.receipt {
                writeln!(writer, "call hash: {}", receipt.call.hash)?;
            }
            if let Some(readback) = &report.readback {
                write_json(writer, &readback.result)?;
            }
            if let Some(reason) = &report.readback_failure {
                writeln!(writer, "{reason}")?;
            }
            if let Some(parent) = &report.parent {
                writeln!(writer, "{}", parent.summary())?;
            }
            Ok(())
        }
    }
}

fn up(store: &ManagedStore, name: &str, timeout: u64) -> Result<ManagedStatus> {
    let runtime = InstalledRuntime::discover()?;
    let mut request = runtime.localnet_request(name, Duration::from_secs(timeout));
    match store.prepared(name) {
        Ok(prepared) => {
            request.service_profile = prepared.service_profile;
            store
                .up_retained(&request, &prepared.context)
                .map_err(Into::into)
        }
        Err(iroha_deploy::managed::Error::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            store.up(&request).map_err(Into::into)
        }
        Err(error) => Err(error.into()),
    }
}

fn check_fee_budget<'a>(
    components: impl Iterator<Item = (&'a AssetDefinitionId, &'a Quantity)>,
    limit: Option<&Quantity>,
) -> Result<()> {
    let Some(limit) = limit else {
        return Ok(());
    };
    let mut asset = None;
    let mut total = Quantity::zero();
    for (asset_definition_id, max_amount) in components {
        if let Some(previous) = asset {
            ensure!(
                previous == asset_definition_id,
                "--max-fee cannot combine different fee assets"
            );
        }
        asset = Some(asset_definition_id);
        total = total
            .checked_add(max_amount)
            .map_err(|_| eyre!("aggregate fee overflow"))?;
    }
    ensure!(
        &total <= limit,
        "aggregate quoted fees {total} exceed --max-fee {limit}"
    );
    Ok(())
}

fn deployment_progress(progress: DeploymentProgress) {
    match progress {
        DeploymentProgress::Prepared(_) => tui::status("Deployment prepared with exact fee quotes"),
        DeploymentProgress::Submitting(stage) => tui::status(format!(
            "Submitting {} ({}/{})",
            stage.name, stage.number, stage.total
        )),
        DeploymentProgress::Recovering(stage) => {
            tui::status(format!("Recovering {} by its retained hash", stage.name))
        }
        DeploymentProgress::Applied { stage, .. } => tui::status(format!("{} applied", stage.name)),
        DeploymentProgress::ReadingBack { .. } => tui::status("Verifying deployed code and alias"),
    }
}

fn print_status(writer: &mut impl Write, status: &ManagedStatus, json: bool) -> Outcome {
    if json {
        return write_json(writer, status);
    }
    writeln!(
        writer,
        "{}: {:?} ({} validators)",
        status.context.name, status.phase, status.running_peers
    )?;
    print_context(writer, &status.context, false)?;
    if let Some(reason) = &status.failure {
        writeln!(writer, "reason: {reason}")?;
    }
    Ok(())
}

fn managed_action(
    root: &Path,
    name: &str,
    command: &str,
    action: &str,
    json: bool,
) -> norito::json::Value {
    // The opened canonical store already binds --workspace and any relative --state input.
    // Never turn a non-UTF-8 native path into different executable arguments through lossiness.
    let argv = root.to_str().map(|root| {
        let mut args = vec![
            "kagami".to_owned(),
            command.to_owned(),
            action.to_owned(),
            name.to_owned(),
            "--state".to_owned(),
            root.to_owned(),
        ];
        if json {
            args.push("--json".to_owned());
        }
        args
    });
    norito::json!({
        "action": action,
        "name": name,
        "argv": argv,
        "argv_unavailable": (root.to_str().is_none().then_some("state_path_not_utf8")),
    })
}

fn print_managed_action(
    writer: &mut impl Write,
    root: &Path,
    name: &str,
    command: &str,
    action: &str,
) -> Outcome {
    // Separate fields are portable across shells and cannot disguise spaces as extra argv.
    writeln!(writer, "action: kagami {command} {action}")?;
    writeln!(writer, "  name: {name}")?;
    writeln!(writer, "  --state (quoted path): {root:?}")?;
    Ok(())
}

fn localnet_failure(
    writer: &mut impl Write,
    root: &Path,
    name: &str,
    status: Option<&ManagedStatus>,
    json: bool,
    original: color_eyre::Report,
) -> Outcome {
    // Even a failed writer must not replace the startup failure with a presentation error.
    let _ = (|| -> Outcome {
        if json {
            return write_json(
                writer,
                &norito::json!({
                    "status": status,
                    "recovery": [
                        (managed_action(root, name, "localnet", "status", true)),
                        (managed_action(root, name, "localnet", "logs", true)),
                    ],
                }),
            );
        }
        if let Some(status) = status {
            print_status(writer, status, false)?;
        }
        writeln!(
            writer,
            "Inspect the requested environment with these action fields:"
        )?;
        print_managed_action(writer, root, name, "localnet", "status")?;
        print_managed_action(writer, root, name, "localnet", "logs")
    })();
    Err(original)
}

fn dataspace_failure(
    writer: &mut impl Write,
    root: &Path,
    name: &str,
    status: Option<&ManagedDataspaceStatus>,
    json: bool,
    original: color_eyre::Report,
) -> Outcome {
    // Parent work keeps its original journals. Observation and output are best-effort;
    // neither may replace the actual attachment failure or suggest a new operation.
    let _ = (|| -> Outcome {
        if json {
            return write_json(
                writer,
                &norito::json!({
                    "status": status,
                    "recovery": [
                        (managed_action(root, name, "dataspace", "status", true)),
                        (managed_action(root, name, "localnet", "logs", true)),
                    ],
                }),
            );
        }
        if let Some(status) = status {
            print_dataspace_status(writer, status, false)?;
        }
        writeln!(
            writer,
            "Inspect the requested dataspace with these action fields:"
        )?;
        print_managed_action(writer, root, name, "dataspace", "status")?;
        print_managed_action(writer, root, name, "localnet", "logs")
    })();
    Err(original)
}

fn print_reset(writer: &mut impl Write, root: &Path, name: &str, json: bool) -> Outcome {
    if json {
        return write_json(
            writer,
            &norito::json!({
                "name": name,
                "state": "reset",
                "next": (managed_action(root, name, "localnet", "up", true)),
            }),
        );
    }
    writeln!(writer, "{name} reset; the next up creates a fresh ledger.")?;
    print_managed_action(writer, root, name, "localnet", "up")
}

fn print_dataspace_status(
    writer: &mut impl Write,
    status: &ManagedDataspaceStatus,
    json: bool,
) -> Outcome {
    if json {
        return write_json(writer, status);
    }
    print_status(writer, &status.local, false)?;
    writeln!(
        writer,
        "parent {}: {}",
        status.attachment.network,
        status.attachment.stage.as_str()
    )?;
    if let Some(wallet) = &status.attachment.wallet_status {
        writeln!(writer, "parent operation: {wallet}")?;
    }
    if let Some(confirmed) = &status.attachment.parent_confirmed {
        writeln!(
            writer,
            "last verified parent receipt: height {}",
            confirmed.parent_height
        )?;
    }
    if let Some(reason) = &status.attachment.failure {
        writeln!(writer, "attachment: {reason}")?;
    }
    Ok(())
}

fn print_context(writer: &mut impl Write, context: &ManagedContext, json: bool) -> Outcome {
    if json {
        return write_json(writer, context);
    }
    writeln!(writer, "{}  {}", context.name, context.torii_url)?;
    writeln!(writer, "network: {}", context.network_id)?;
    writeln!(writer, "account: {}", context.account_id)?;
    Ok(())
}

fn write_json(writer: &mut impl Write, value: &impl norito::json::JsonSerialize) -> Outcome {
    writeln!(writer, "{}", norito::json::to_json(value)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn administrative_amx_cli_requires_explicit_parent_signer_and_original_finite_terms() {
        let common = ["kagami", "dataspace", "register-amx", "private"];
        let arguments = [
            "--admin-config",
            "parent-admin.toml",
            "--fee-asset",
            iroha_deploy::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
            "--max-fee",
            "1",
            "--deadline-unix-ms",
            "1234567890000",
        ];
        let parsed = crate::Cli::try_parse_from(common.into_iter().chain(arguments)).unwrap();
        let crate::Command::Dataspace(DataspaceCommand::RegisterAmx(args)) = parsed.command else {
            panic!("wrong administrative action");
        };
        assert_eq!(args.name, "private");
        assert_eq!(args.admin_config, Path::new("parent-admin.toml"));
        assert_eq!(args.deadline_unix_ms, 1234567890000);
        assert_eq!(args.timeout, 60);
        assert_eq!(args.max_fee, Quantity::from(1_u32));
        assert!(crate::Cli::try_parse_from(common).is_err());
        let help = crate::Cli::try_parse_from(common.into_iter().chain(["--help"]))
            .err()
            .expect("help must exit through Clap's display result")
            .to_string();
        assert!(help.contains("localnet down NAME") && help.contains("localnet up NAME"));
        for index in [0, 2, 4, 6] {
            assert!(
                crate::Cli::try_parse_from(
                    common.into_iter().chain(
                        arguments
                            .iter()
                            .enumerate()
                            .filter_map(|(i, a)| (!(index..index + 2).contains(&i)).then_some(*a))
                    )
                )
                .is_err()
            );
        }
        for timeout in ["0", "61"] {
            assert!(
                crate::Cli::try_parse_from(
                    common
                        .into_iter()
                        .chain(arguments)
                        .chain(["--timeout", timeout])
                )
                .is_err()
            );
        }
    }

    #[test]
    fn internal_worker_requires_the_absolute_deadline_and_keeps_bounded_milliseconds() {
        let base = [
            "kagami",
            "_managed-worker",
            "--root",
            "state",
            "--name",
            "local",
        ];
        assert!(
            crate::Cli::try_parse_from(base.into_iter().chain(["--startup-timeout-ms", "30000"]))
                .is_err()
        );
        for milliseconds in ["1", "30000", "600000"] {
            let parsed = crate::Cli::try_parse_from(base.into_iter().chain([
                "--startup-timeout-ms",
                milliseconds,
                "--startup-deadline-ns",
                "18446744073709551616",
            ]))
            .unwrap();
            let crate::Command::ManagedWorker(worker) = parsed.command else {
                panic!("wrong command");
            };
            assert_eq!(
                worker.startup_timeout_ms,
                milliseconds.parse::<u64>().unwrap()
            );
            assert_eq!(worker.startup_deadline_ns, 18_446_744_073_709_551_616_u128);
        }
        for milliseconds in ["0", "600001", "-1"] {
            assert!(
                crate::Cli::try_parse_from(base.into_iter().chain([
                    "--startup-timeout-ms",
                    milliseconds,
                    "--startup-deadline-ns",
                    "1"
                ]))
                .is_err()
            );
        }
        for deadline in [
            "-1",
            "not-an-integer",
            "340282366920938463463374607431768211456",
        ] {
            assert!(
                crate::Cli::try_parse_from(base.into_iter().chain([
                    "--startup-timeout-ms",
                    "30000",
                    "--startup-deadline-ns",
                    deadline
                ]))
                .is_err()
            );
        }
    }

    #[test]
    fn relative_inputs_and_journals_use_the_selected_workspace() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("project");
        std::fs::create_dir(&workspace).unwrap();
        let args = StoreArgs {
            workspace: Some(workspace.clone()),
            state: None,
            json: false,
        };
        for relative in ["hello.ko", "Musubi.toml", "journals/original"] {
            assert_eq!(
                args.resolve_path(Path::new(relative)).unwrap(),
                workspace.canonicalize().unwrap().join(relative)
            );
        }
        let absolute = temporary.path().join("elsewhere.to");
        assert_eq!(args.resolve_path(&absolute).unwrap(), absolute);
        let missing = StoreArgs {
            workspace: Some(workspace.join("missing")),
            ..args
        };
        assert!(missing.resolve_path(Path::new("hello.ko")).is_err());
    }

    #[test]
    fn localnet_up_needs_no_configuration() {
        let cli = crate::Cli::try_parse_from(["kagami", "localnet", "up"]).unwrap();
        assert!(matches!(
            cli.command,
            crate::Command::Localnet(LocalnetCommand::Up(_))
        ));
        assert!(crate::Cli::try_parse_from(["kagami", "localnet", "reset"]).is_err());
        assert!(crate::Cli::try_parse_from(["kagami", "localnet-wizard"]).is_err());
    }

    #[test]
    fn failed_start_reports_exact_store_actions_and_retains_the_original_error() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("workspace with spaces");
        let state = temporary.path().join("state with spaces and 'quotes'");
        std::fs::create_dir(&workspace).unwrap();
        let cli = crate::Cli::try_parse_from([
            "kagami",
            "localnet",
            "up",
            "acme-dev",
            "--workspace",
            workspace.to_str().unwrap(),
            "--state",
            state.to_str().unwrap(),
            "--json",
        ])
        .unwrap();
        let crate::Command::Localnet(LocalnetCommand::Up(args)) = cli.command else {
            panic!("expected localnet startup");
        };
        let store = args.named.store.open().unwrap();
        let status = ManagedStatus {
            context: ManagedContext {
                name: args.named.name.clone(),
                chain_id: "public-fixture".into(),
                network_id: "public-network".into(),
                account_id: "public-account".into(),
                dataspace_id: 0,
                dataspace_alias: "universal".into(),
                torii_url: "http://127.0.0.1:8080/".into(),
                client_config: store.root().join("private-client.toml"),
            },
            phase: ManagedPhase::Failed,
            running_peers: 0,
            failure: Some("startup readiness deadline expired".into()),
        };
        for retained in [None, Some(&status)] {
            let original = std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "sensitive upstream detail",
            );
            let mut output = Vec::new();
            let error = localnet_failure(
                &mut output,
                store.root(),
                &args.named.name,
                retained,
                true,
                original.into(),
            )
            .unwrap_err();
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            let text = std::str::from_utf8(&output).unwrap();
            assert_eq!(text.lines().count(), 1);
            assert!(!text.contains("sensitive upstream detail"));
            let value: norito::json::Value = norito::json::from_slice(&output).unwrap();
            assert_eq!(
                value.get("status").unwrap(),
                &norito::json::to_value(&retained).unwrap()
            );
            let recovery = value.get("recovery").unwrap().as_array().unwrap();
            assert_eq!(recovery.len(), 2);
            for (action, expected) in recovery.iter().zip(["status", "logs"]) {
                let argv = action.get("argv").unwrap().as_array().unwrap();
                let argv: Vec<_> = argv.iter().map(|arg| arg.as_str().unwrap()).collect();
                assert_eq!(argv[2], expected);
                let parsed = crate::Cli::try_parse_from(argv).unwrap();
                let named = match parsed.command {
                    crate::Command::Localnet(LocalnetCommand::Status(named)) => named,
                    crate::Command::Localnet(LocalnetCommand::Logs(logs)) => logs.named,
                    _ => panic!("expected exact recovery action"),
                };
                assert_eq!(named.name, args.named.name);
                assert_eq!(named.store.state.as_deref(), Some(store.root()));
                assert!(named.store.json);
            }
        }
        let mut human = Vec::new();
        assert!(
            localnet_failure(
                &mut human,
                store.root(),
                &args.named.name,
                Some(&status),
                false,
                eyre!("original failure"),
            )
            .is_err()
        );
        let human = String::from_utf8(human).unwrap();
        assert!(human.contains("acme-dev: Failed"));
        assert!(human.contains("action: kagami localnet status"));
        assert!(human.contains("action: kagami localnet logs"));
        assert!(human.contains(&format!("--state (quoted path): {:?}", store.root())));
        assert!(!human.contains("original failure"));
    }

    #[test]
    fn failed_recovery_output_never_replaces_the_startup_cause() {
        struct BrokenWriter;
        impl Write for BrokenWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for (json, dataspace) in [(false, false), (true, false), (false, true), (true, true)] {
            let original = iroha_deploy::managed::Error::Timeout(Duration::from_secs(9));
            let error = if dataspace {
                dataspace_failure(
                    &mut BrokenWriter,
                    Path::new("state"),
                    "named",
                    None,
                    json,
                    original.into(),
                )
            } else {
                localnet_failure(
                    &mut BrokenWriter,
                    Path::new("state"),
                    "named",
                    None,
                    json,
                    original.into(),
                )
            }
            .unwrap_err();
            assert!(matches!(
                error.downcast_ref::<iroha_deploy::managed::Error>(),
                Some(iroha_deploy::managed::Error::Timeout(duration))
                    if *duration == Duration::from_secs(9)
            ));
        }
    }

    #[test]
    fn reset_next_action_preserves_custom_name_and_space_containing_state() {
        let root = Path::new("/a workspace/private state");
        let mut output = Vec::new();
        print_reset(&mut output, root, "acme-dev", true).unwrap();
        let value: norito::json::Value = norito::json::from_slice(&output).unwrap();
        assert_eq!(value.get("state").and_then(|v| v.as_str()), Some("reset"));
        let argv = value
            .get("next")
            .unwrap()
            .get("argv")
            .unwrap()
            .as_array()
            .unwrap();
        let cli = crate::Cli::try_parse_from(argv.iter().map(|arg| arg.as_str().unwrap())).unwrap();
        let crate::Command::Localnet(LocalnetCommand::Up(args)) = cli.command else {
            panic!("reset must suggest an explicit startup");
        };
        assert_eq!(args.named.name, "acme-dev");
        assert_eq!(args.named.store.state.as_deref(), Some(root));
        assert!(args.named.store.json);
        let mut human = Vec::new();
        print_reset(&mut human, root, "acme-dev", false).unwrap();
        let human = String::from_utf8(human).unwrap();
        assert!(human.contains("acme-dev reset; the next up creates a fresh ledger."));
        assert!(human.contains("action: kagami localnet up"));
        assert!(human.contains("  name: acme-dev"));
        assert!(human.contains(&format!("--state (quoted path): {root:?}")));
    }

    #[test]
    fn managed_contract_view_and_call_use_aliases_and_exact_recovery() {
        for arguments in [
            vec![
                "kagami",
                "contract",
                "view",
                "Counter::dpn",
                "--entrypoint",
                "current",
            ],
            vec![
                "kagami",
                "contract",
                "call",
                "Counter::dpn",
                "--entrypoint",
                "set",
                "--args",
                "{\"next\":\"7\"}",
                "--max-fee",
                "1000",
                "--prepare",
                "--readback",
                "current",
            ],
            vec![
                "kagami",
                "contract",
                "call",
                "--resume",
                "/private/calls/original",
                "--readback",
                "current",
            ],
        ] {
            crate::Cli::try_parse_from(arguments).unwrap();
        }
        for arguments in [
            vec![
                "kagami",
                "contract",
                "call",
                "Counter::dpn",
                "--entrypoint",
                "set",
            ],
            vec![
                "kagami",
                "contract",
                "call",
                "--resume",
                "/private/call",
                "--max-fee",
                "1000",
            ],
            vec![
                "kagami",
                "contract",
                "call",
                "--resume",
                "/private/call",
                "Counter::dpn",
            ],
            vec![
                "kagami",
                "contract",
                "view",
                "Counter::dpn",
                "--entrypoint",
                "current",
                "--gas-limit",
                "0",
            ],
        ] {
            assert!(crate::Cli::try_parse_from(arguments).is_err());
        }
    }

    #[test]
    fn managed_contract_argument_admission_precedes_network_selection() {
        assert!(view_request("current".into(), "{}", 1).is_ok());
        assert!(view_request(" current ".into(), "{}", 1).is_err());
        assert!(
            view_request(
                "current".into(),
                &format!("\"{}\"", "x".repeat(64 * 1024)),
                1
            )
            .is_err()
        );
        assert!(
            view_request(
                "current".into(),
                &format!("{}0{}", "[".repeat(129), "]".repeat(129)),
                1
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn recovery_does_not_emit_lossy_arguments_for_non_utf8_state_paths() {
        use std::os::unix::ffi::OsStringExt as _;
        let root = PathBuf::from(std::ffi::OsString::from_vec(b"/state/\xff".to_vec()));
        for command in ["localnet", "dataspace"] {
            let action = managed_action(&root, "named", command, "status", true);
            assert_eq!(action.get("argv"), Some(&norito::json::Value::Null));
            assert_eq!(
                action.get("argv_unavailable").and_then(|v| v.as_str()),
                Some("state_path_not_utf8")
            );
        }
    }

    #[test]
    fn dataspace_up_needs_only_alias_and_explicit_installed_parent() {
        let cli = crate::Cli::try_parse_from([
            "kagami",
            "dataspace",
            "up",
            "privateapp",
            "--network",
            "taira",
        ])
        .unwrap();
        let crate::Command::Dataspace(DataspaceCommand::Up(args)) = cli.command else {
            panic!("expected private dataspace startup");
        };
        assert_eq!(args.alias, "privateapp");
        assert_eq!(args.network, "taira");
        assert_eq!(args.account_alias, "admin");
        assert!(args.name.is_none());
        assert_eq!(args.timeout, 60);
        assert!(args.store.state.is_none());
        assert!(crate::Cli::try_parse_from(["kagami", "dataspace", "up", "privateapp"]).is_err());
        for timeout in ["0", "61"] {
            assert!(
                crate::Cli::try_parse_from([
                    "kagami",
                    "dataspace",
                    "up",
                    "privateapp",
                    "--network",
                    "taira",
                    "--timeout",
                    timeout,
                ])
                .is_err()
            );
        }
        assert!(crate::Cli::try_parse_from(["kagami", "dataspace", "status", "--json"]).is_ok());
        assert!(crate::Cli::try_parse_from(["kagami", "dataspace", "networks", "--json"]).is_ok());
    }

    #[test]
    fn full_length_dataspace_cli_inputs_preserve_alias_and_explicit_context() {
        for length in [48, 49, 63] {
            let alias = "a".repeat(length);
            for explicit in [None, Some("chosen-context")] {
                let mut argv = vec!["kagami", "dataspace", "up", &alias, "--network", "taira"];
                if let Some(name) = explicit {
                    argv.extend(["--name", name]);
                }
                let crate::Command::Dataspace(DataspaceCommand::Up(args)) =
                    crate::Cli::try_parse_from(argv).unwrap().command
                else {
                    panic!("expected private dataspace startup");
                };
                assert_eq!(args.alias, alias);
                assert_eq!(args.name.as_deref(), explicit);
                assert_eq!(args.network, "taira");
                assert_eq!(args.account_alias, "admin");
                assert_eq!(args.timeout, 60);
            }
        }
    }

    #[test]
    fn dataspace_up_retains_an_explicit_owner_alias_label() {
        let cli = crate::Cli::try_parse_from([
            "kagami",
            "dataspace",
            "up",
            "dpn",
            "--network",
            "taira",
            "--account-alias",
            "treasury",
        ])
        .unwrap();
        let crate::Command::Dataspace(DataspaceCommand::Up(args)) = cli.command else {
            panic!("expected private dataspace startup");
        };
        assert_eq!(args.alias, "dpn");
        assert_eq!(args.account_alias, "treasury");
    }

    #[test]
    fn dataspace_output_separates_local_readiness_from_parent_evidence() {
        use iroha_deploy::managed::{
            ManagedAttachmentFailure, ManagedAttachmentPhase, ManagedAttachmentStatus,
        };
        let status = ManagedDataspaceStatus {
            local: ManagedStatus {
                context: ManagedContext {
                    name: "privateapp".into(),
                    chain_id: "fixture".into(),
                    network_id: "fixture-network".into(),
                    account_id: "fixture-account".into(),
                    dataspace_id: 42,
                    dataspace_alias: "privateapp".into(),
                    torii_url: "http://127.0.0.1:8080/".into(),
                    client_config: PathBuf::from("/private/fixture"),
                },
                phase: ManagedPhase::Ready,
                running_peers: 4,
                failure: None,
            },
            attachment: ManagedAttachmentStatus {
                network: "taira".into(),
                stage: ManagedAttachmentPhase::Funding,
                wallet_status: None,
                local_successor: None,
                parent_confirmed: None,
                failure: Some(ManagedAttachmentFailure::PreparationFailed),
            },
        };
        let mut text = Vec::new();
        print_dataspace_status(&mut text, &status, false).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("Ready (4 validators)"));
        assert!(text.contains("parent taira: funding"));
        assert!(text.contains("attachment: operation preparation failed"));
        assert!(!text.contains("last verified parent receipt"));
        let mut json = Vec::new();
        print_dataspace_status(&mut json, &status, true).unwrap();
        assert_eq!(
            norito::json::from_slice::<ManagedDataspaceStatus>(&json).unwrap(),
            status
        );
        // A ready child must remain distinguishable from the failed parent attachment in
        // recovery output, including when no retained attachment was published at all.
        let root = Path::new("/workspace with spaces/state 'quoted'");
        for retained in [None, Some(&status)] {
            let mut output = Vec::new();
            let error = dataspace_failure(
                &mut output,
                root,
                "custom-local-name",
                retained,
                true,
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "original detail").into(),
            )
            .unwrap_err();
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            let text = std::str::from_utf8(&output).unwrap();
            assert_eq!(text.lines().count(), 1);
            assert!(!text.contains("original detail"));
            let value: norito::json::Value = norito::json::from_slice(&output).unwrap();
            assert_eq!(
                value.get("status").unwrap(),
                &norito::json::to_value(&retained).unwrap()
            );
            let recovery = value.get("recovery").unwrap().as_array().unwrap();
            assert_eq!(recovery.len(), 2);
            for (action, expected) in recovery.iter().zip(["dataspace", "localnet"]) {
                let argv = action.get("argv").unwrap().as_array().unwrap();
                let argv: Vec<_> = argv.iter().map(|arg| arg.as_str().unwrap()).collect();
                assert_eq!(argv[1], expected);
                let parsed = crate::Cli::try_parse_from(argv).unwrap();
                let (name, store) = match parsed.command {
                    crate::Command::Dataspace(DataspaceCommand::Status(args)) => {
                        (args.name.unwrap(), args.store)
                    }
                    crate::Command::Localnet(LocalnetCommand::Logs(args)) => {
                        (args.named.name, args.named.store)
                    }
                    _ => panic!("expected read-only dataspace recovery action"),
                };
                assert_eq!(name, "custom-local-name");
                assert_eq!(store.state.as_deref(), Some(root));
                assert!(store.json);
            }
        }
        let mut output = Vec::new();
        assert!(
            dataspace_failure(
                &mut output,
                root,
                "custom-local-name",
                Some(&status),
                false,
                eyre!("original detail"),
            )
            .is_err()
        );
        let human = String::from_utf8(output).unwrap();
        assert!(human.contains("Ready (4 validators)"));
        assert!(human.contains("parent taira: funding"));
        assert!(human.contains("action: kagami dataspace status"));
        assert!(human.contains("action: kagami localnet logs"));
        assert!(human.contains("  name: custom-local-name"));
        assert!(human.contains(&format!("--state (quoted path): {root:?}")));
        assert!(!human.contains("original detail"));
    }

    #[test]
    fn deployment_source_needs_no_manifest_or_config() {
        for source in ["hello.ko", "hello.to", "."] {
            let cli = crate::Cli::try_parse_from(["kagami", "contract", "deploy", source]).unwrap();
            assert!(matches!(
                cli.command,
                crate::Command::Contract(ContractCommand::Deploy(_))
            ));
        }
        assert!(
            crate::Cli::try_parse_from([
                "kagami", "contract", "deploy", "hello.ko", "--resume", "journal"
            ])
            .is_err()
        );
    }

    #[test]
    fn invalid_local_inputs_do_not_provision_or_select_a_network() {
        let temporary = tempfile::tempdir().unwrap();
        let state = temporary.path().join("state");
        let unsupported = temporary.path().join("contract.txt");
        std::fs::write(&unsupported, "unsupported input").unwrap();
        let source = temporary.path().join("contract.ko");
        std::fs::write(&source, "seiyaku Test {}").unwrap();
        let bytecode = temporary.path().join("invalid.to");
        std::fs::write(&bytecode, b"not an IVM artifact").unwrap();
        let package = temporary.path().join("package");
        std::fs::create_dir(&package).unwrap();
        let manifest = package.join("Musubi.toml");
        std::fs::write(&manifest, "[broken").unwrap();
        for (path, alias) in [
            (&unsupported, None),
            (&source, Some("not an alias")),
            (&bytecode, None),
            (&manifest, None),
            (&package, None),
        ] {
            let mut args = vec![
                "kagami",
                "contract",
                "deploy",
                path.to_str().unwrap(),
                "--state",
                state.to_str().unwrap(),
            ];
            if let Some(alias) = alias {
                args.extend(["--alias", alias]);
            }
            let cli = crate::Cli::try_parse_from(args).unwrap();
            let mut output = BufWriter::new(Vec::new());
            assert!(cli.command.run(&mut output).is_err());
            assert!(!state.exists());
        }
    }

    #[test]
    fn package_publication_grammar_keeps_explicit_recovery_and_contract_deployment_distinct() {
        let begin = crate::Cli::try_parse_from([
            "kagami",
            "package",
            "publish",
            ".",
            "--package",
            "dev.universal/demo",
            "--detach",
            "--json",
        ])
        .unwrap();
        let crate::Command::Package(PackageCommand::Publish(args)) = begin.command else {
            panic!("publication command");
        };
        assert!(args.detach && args.store.json);
        assert_eq!(args.package.unwrap().to_string(), "dev.universal/demo");
        assert!(args.resume.is_none() && args.recover.is_none());
        let id = "12".repeat(32);
        for flag in ["--resume", "--recover"] {
            let cli = crate::Cli::try_parse_from([
                "kagami",
                "package",
                "publish",
                "Musubi.toml",
                flag,
                &id,
                "--context",
                "retained",
            ])
            .unwrap();
            let crate::Command::Package(PackageCommand::Publish(args)) = cli.command else {
                panic!("publication recovery");
            };
            assert_eq!(args.context.as_deref(), Some("retained"));
            assert!(args.resume.is_some() != args.recover.is_some());
            assert!(
                crate::Cli::try_parse_from(["kagami", "package", "publish", flag, &id, "--detach"])
                    .is_err()
            );
            assert!(
                crate::Cli::try_parse_from([
                    "kagami",
                    "package",
                    "publish",
                    flag,
                    &id,
                    "--package",
                    "dev.universal/demo"
                ])
                .is_err()
            );
        }
        assert!(
            crate::Cli::try_parse_from([
                "kagami",
                "package",
                "publish",
                "--resume",
                &id,
                "--recover",
                &id
            ])
            .is_err()
        );
        assert!(
            crate::Cli::try_parse_from(["kagami", "package", "publish", "--resume", "invalid"])
                .is_err()
        );
        assert!(
            crate::Cli::try_parse_from(["kagami", "package", "publish", "--config", "client.toml"])
                .is_err()
        );
        assert!(matches!(
            crate::Cli::try_parse_from(["kagami", "contract", "deploy", "contract.ko"])
                .unwrap()
                .command,
            crate::Command::Contract(ContractCommand::Deploy(_))
        ));
    }

    #[test]
    fn invalid_publication_manifest_never_provisions_or_selects_a_network() {
        let temporary = tempfile::tempdir().unwrap();
        let manifest = temporary.path().join("Musubi.toml");
        let state = temporary.path().join("state");
        std::fs::write(&manifest, "invalid manifest").unwrap();
        let cli = crate::Cli::try_parse_from([
            "kagami",
            "package",
            "publish",
            manifest.to_str().unwrap(),
            "--state",
            state.to_str().unwrap(),
        ])
        .unwrap();
        assert!(cli.command.run(&mut BufWriter::new(Vec::new())).is_err());
        assert!(!state.exists());
    }

    #[test]
    fn publication_recovery_requires_retained_selection_before_runtime_discovery() {
        let temporary = tempfile::tempdir().unwrap();
        let manifest = temporary.path().join("Musubi.toml");
        let state = temporary.path().join("state");
        std::fs::write(&manifest, "manifest-version = 1\n[package]\nnamespace = \"dev.universal\"\nname = \"demo\"\nversion = \"1.0.0\"\nedition = \"1\"\nabi-version = 1\n[lib]\nexports = []\n").unwrap();
        let id = "34".repeat(32);
        for flag in ["--resume", "--recover"] {
            let cli = crate::Cli::try_parse_from([
                "kagami",
                "package",
                "publish",
                manifest.to_str().unwrap(),
                flag,
                &id,
                "--state",
                state.to_str().unwrap(),
            ])
            .unwrap();
            let mut writer = BufWriter::new(Vec::new());
            let error = cli.command.run(&mut writer).unwrap_err();
            assert!(matches!(
                error.downcast_ref::<managed::Error>(),
                Some(managed::Error::NoSelection)
            ));
            assert!(writer.into_inner().unwrap().is_empty());
            assert!(
                ManagedStore::open(&state)
                    .unwrap()
                    .contexts()
                    .unwrap()
                    .is_empty()
            );
        }
        for missing in [false, true] {
            if missing {
                std::fs::remove_file(&manifest).unwrap();
            } else {
                std::fs::write(&manifest, "invalid changed source").unwrap();
            }
            let cli = crate::Cli::try_parse_from([
                "kagami",
                "package",
                "publish",
                manifest.to_str().unwrap(),
                "--resume",
                &id,
                "--state",
                state.to_str().unwrap(),
            ])
            .unwrap();
            let error = cli
                .command
                .run(&mut BufWriter::new(Vec::new()))
                .unwrap_err();
            assert!(
                matches!(
                    error.downcast_ref::<managed::Error>(),
                    Some(managed::Error::NoSelection)
                ),
                "resume must reach original context without reopening source: {error}"
            );
            assert!(
                ManagedStore::open(&state)
                    .unwrap()
                    .contexts()
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn already_rendered_publication_error_preserves_canonical_process_status() {
        let error: color_eyre::eyre::Report = PublicationExit(42).into();
        assert_eq!(error.downcast_ref::<PublicationExit>().unwrap().0, 42);
        assert_eq!(error.to_string(), "package publication did not complete");
        assert!(
            eyre!("ordinary failure")
                .downcast_ref::<PublicationExit>()
                .is_none()
        );
    }

    #[test]
    fn fee_budget_bounds_the_whole_deployment_and_rejects_mixed_assets() {
        let mut bytes = [0; 16];
        bytes[6] = 0x40;
        bytes[8] = 0x80;
        let xor = AssetDefinitionId::from_uuid_bytes(bytes).unwrap();
        bytes[0] = 1;
        let other = AssetDefinitionId::from_uuid_bytes(bytes).unwrap();
        let first = Quantity::from(7_u32);
        let second = Quantity::from(5_u32);
        let exact = Quantity::from(12_u32);
        assert!(
            check_fee_budget([(&xor, &first), (&xor, &second)].into_iter(), Some(&exact)).is_ok()
        );
        assert!(
            check_fee_budget(
                [(&xor, &first), (&xor, &second)].into_iter(),
                Some(&Quantity::from(11_u32))
            )
            .is_err()
        );
        assert!(
            check_fee_budget(
                [(&xor, &first), (&other, &second)].into_iter(),
                Some(&exact)
            )
            .is_err()
        );
        assert!(check_fee_budget(std::iter::empty(), Some(&Quantity::zero())).is_ok());
        assert!(check_fee_budget([(&xor, &first)].into_iter(), None).is_ok());
    }

    #[test]
    fn member_publication_refuses_another_package_before_creating_managed_state() {
        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        let state = temporary.path().join("state");
        std::fs::create_dir_all(project.join("app")).unwrap();
        std::fs::create_dir(project.join("other")).unwrap();
        std::fs::write(project.join("Musubi.toml"), "manifest-version = 1\n[workspace]\nmembers = [\"app\", \"other\"]\ndefault-members = [\"other\"]\n").unwrap();
        for name in ["app", "other"] {
            std::fs::write(project.join(name).join("Musubi.toml"), format!("manifest-version = 1\n[package]\nnamespace = \"dev.universal\"\nname = \"{name}\"\nversion = \"1.0.0\"\nedition = \"1\"\nabi-version = 1\n[lib]\nexports = []\n")).unwrap();
        }
        for input in ["app", "app/Musubi.toml"] {
            let cli = crate::Cli::try_parse_from([
                "kagami",
                "package",
                "publish",
                input,
                "--workspace",
                project.to_str().unwrap(),
                "--package",
                "dev.universal/other",
                "--state",
                state.to_str().unwrap(),
            ])
            .unwrap();
            let mut writer = BufWriter::new(Vec::new());
            let error = cli.command.run(&mut writer).unwrap_err();
            assert_eq!(
                error.to_string(),
                "selected member manifest cannot select another package"
            );
            assert!(writer.into_inner().unwrap().is_empty());
            assert!(!state.exists());
            assert!(!project.join("Musubi.lock").exists());
            assert!(!project.join("target").exists());
        }
    }
}
