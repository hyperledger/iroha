//! Iroha server command-line interface.

use std::{
    env,
    future::Future,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use error_stack::{IntoReportCompat, Report, Result, ResultExt};
use iroha_config::{
    base::{read::ConfigReader, util::Emitter, WithOrigin},
    parameters::{actual::Root as Config, user::Root as UserConfig},
};
use iroha_core::{
    block_sync::{BlockSynchronizer, BlockSynchronizerHandle},
    gossiper::{TransactionGossiper, TransactionGossiperHandle},
    kiso::KisoHandle,
    kura::Kura,
    query::store::LiveQueryStore,
    queue::Queue,
    smartcontracts::isi::Registrable as _,
    snapshot::{try_read_snapshot, SnapshotMaker, TryReadError as TryReadSnapshotError},
    state::{State, StateReadOnly, World},
    sumeragi::{GenesisWithPubKey, SumeragiHandle, SumeragiStartArgs},
    IrohaNetwork,
};
#[cfg(feature = "telemetry")]
use iroha_core::{metrics::MetricsReporter, sumeragi::SumeragiMetrics};
use iroha_data_model::{block::SignedBlock, prelude::*};
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal, Supervisor};
use iroha_genesis::GenesisBlock;
use iroha_logger::{actor::LoggerHandle, InitConfig as LoggerInitConfig};
use iroha_primitives::addr::SocketAddr;
use iroha_torii::Torii;
use iroha_version::scale::DecodeVersioned;
use thiserror::Error;
use tokio::{
    sync::{broadcast, mpsc},
    task,
};

#[allow(missing_docs)]
pub fn is_coloring_supported() -> bool {
    supports_color::on(supports_color::Stream::Stdout).is_some()
}

fn default_terminal_colors_str() -> clap::builder::OsStr {
    is_coloring_supported().to_string().into()
}

/// Iroha server CLI
#[derive(Parser, Debug)]
#[command(
    name = "irohad",
    version = concat!("version=", env!("CARGO_PKG_VERSION"), " git_commit_sha=", env!("VERGEN_GIT_SHA"), " cargo_features=", env!("VERGEN_CARGO_FEATURES")),
    author
)]
pub struct Args {
    /// Path to the configuration file
    #[arg(long, short, value_name("PATH"), value_hint(clap::ValueHint::FilePath))]
    pub config: Option<PathBuf>,
    /// Enables trace logs of configuration reading & parsing.
    ///
    /// Might be useful for configuration troubleshooting.
    #[arg(long, env)]
    pub trace_config: bool,
    /// Whether to enable ANSI-colored output or not
    ///
    /// By default, Iroha determines whether the terminal supports colors or not.
    ///
    /// In order to disable this flag explicitly, pass `--terminal-colors=false`.
    #[arg(
        long,
        env,
        default_missing_value("true"),
        default_value(default_terminal_colors_str()),
        action(clap::ArgAction::Set),
        require_equals(true),
        num_args(0..=1),
    )]
    pub terminal_colors: bool,
}

#[derive(thiserror::Error, Debug)]
enum MainError {
    #[error("Could not set up configuration tracing")]
    TraceConfigSetup,
    #[error("Configuration error")]
    Config,
    #[error("Could not initialize logger")]
    Logger,
    #[error("Failed to start Iroha")]
    IrohaStart,
    #[error("Error occured while running Iroha")]
    IrohaRun,
}

const EVENTS_BUFFER_CAPACITY: usize = 10_000;

/// [Orchestrator](https://en.wikipedia.org/wiki/Orchestration_%28computing%29)
/// of the system. It configures, coordinates and manages transactions
/// and queries processing, work of consensus and storage.
pub struct Iroha {
    /// Kura — block storage
    kura: Arc<Kura>,
    /// State of blockchain
    state: Arc<State>,
}

/// Error(s) that might occur while starting [`Iroha`]
#[derive(thiserror::Error, Debug, Copy, Clone)]
#[allow(missing_docs)]
pub enum StartError {
    #[error("Unable to start peer-to-peer network")]
    StartP2p,
    #[error("Unable to initialize Kura (block storage)")]
    InitKura,
    #[error("Unable to start dev telemetry service")]
    StartDevTelemetry,
    #[error("Unable to start telemetry service")]
    StartTelemetry,
    #[error("Unable to set up listening for OS signals")]
    ListenOsSignal,
    #[error("Unable to start Torii (Iroha HTTP API Gateway)")]
    StartTorii,
}

struct NetworkRelay {
    sumeragi: SumeragiHandle,
    block_sync: BlockSynchronizerHandle,
    tx_gossiper: TransactionGossiperHandle,
    network: IrohaNetwork,
}

impl NetworkRelay {
    async fn run(mut self) {
        let (sender, mut receiver) = mpsc::channel(1);
        self.network.subscribe_to_peers_messages(sender);
        while let Some(msg) = receiver.recv().await {
            self.handle_message(msg).await;
        }
        iroha_logger::debug!("Exiting the network relay");
    }

    async fn handle_message(&mut self, msg: iroha_core::NetworkMessage) {
        use iroha_core::NetworkMessage::*;

        match msg {
            SumeragiBlock(data) => {
                self.sumeragi.incoming_block_message(*data);
            }
            SumeragiControlFlow(data) => {
                self.sumeragi.incoming_control_flow_message(*data);
            }
            BlockSync(data) => self.block_sync.message(*data).await,
            TransactionGossiper(data) => self.tx_gossiper.gossip(*data).await,
            Health => {}
        }
    }
}

impl Iroha {
    /// Starts Iroha with all its subsystems.
    ///
    /// Returns iroha itself and a future of system shutdown.
    ///
    /// # Errors
    /// - Reading telemetry configs
    /// - Telemetry setup
    /// - Initialization of [`Sumeragi`] and [`Kura`]
    #[allow(clippy::too_many_lines)]
    #[iroha_logger::log(name = "start", skip_all)] // This is actually easier to understand as a linear sequence of init statements.
    pub async fn start(
        config: Config,
        genesis: Option<GenesisBlock>,
        logger: LoggerHandle,
        shutdown_signal: ShutdownSignal,
    ) -> Result<
        (
            Self,
            impl Future<Output = std::result::Result<(), iroha_futures::supervisor::Error>>,
        ),
        StartError,
    > {
        let mut supervisor = Supervisor::new();

        let (kura, block_count) = Kura::new(&config.kura).change_context(StartError::InitKura)?;
        let child = Kura::start(kura.clone(), supervisor.shutdown_signal());
        supervisor.monitor(child);

        let (live_query_store, child) =
            LiveQueryStore::from_config(config.live_query_store, supervisor.shutdown_signal())
                .start();
        supervisor.monitor(child);

        let state = match try_read_snapshot(
            config.snapshot.store_dir.resolve_relative_path(),
            &kura,
            || live_query_store.clone(),
            block_count,
        ) {
            Ok(state) => {
                iroha_logger::info!(
                    at_height = state.view().height(),
                    "Successfully loaded the state from a snapshot"
                );
                Some(state)
            }
            Err(TryReadSnapshotError::NotFound) => {
                iroha_logger::info!("Didn't find a state snapshot; creating an empty state");
                None
            }
            Err(error) => {
                iroha_logger::warn!(%error, "Failed to load the state from a snapshot; creating an empty state");
                None
            }
        }.unwrap_or_else(|| {
            let world = World::with(
                [genesis_domain(config.genesis.public_key.clone())],
                [genesis_account(config.genesis.public_key.clone())],
                [],
            );

            State::new(
                world,
                Arc::clone(&kura),
                live_query_store.clone(),
            )
        });
        let state = Arc::new(state);

        let (events_sender, _) = broadcast::channel(EVENTS_BUFFER_CAPACITY);
        let queue = Arc::new(Queue::from_config(config.queue, events_sender.clone()));

        let (network, child) = IrohaNetwork::start(
            config.common.key_pair.clone(),
            config.network.clone(),
            supervisor.shutdown_signal(),
        )
        .await
        .attach_printable_lazy(|| config.network.address.clone().into_attachment())
        .change_context(StartError::StartP2p)?;
        supervisor.monitor(child);

        #[cfg(feature = "telemetry")]
        start_telemetry(&logger, &config, &mut supervisor).await?;

        #[cfg(feature = "telemetry")]
        let metrics_reporter = MetricsReporter::new(
            Arc::clone(&state),
            network.clone(),
            kura.clone(),
            queue.clone(),
        );

        let (sumeragi, child) = SumeragiStartArgs {
            sumeragi_config: config.sumeragi.clone(),
            common_config: config.common.clone(),
            events_sender: events_sender.clone(),
            state: state.clone(),
            queue: queue.clone(),
            kura: kura.clone(),
            network: network.clone(),
            genesis_network: GenesisWithPubKey {
                genesis,
                public_key: config.genesis.public_key.clone(),
            },
            block_count,
            #[cfg(feature = "telemetry")]
            sumeragi_metrics: SumeragiMetrics {
                dropped_messages: metrics_reporter.metrics().dropped_messages.clone(),
                view_changes: metrics_reporter.metrics().view_changes.clone(),
            },
        }
        .start(supervisor.shutdown_signal());
        supervisor.monitor(child);

        let (block_sync, child) = BlockSynchronizer::from_config(
            &config.block_sync,
            sumeragi.clone(),
            kura.clone(),
            config.common.peer.clone(),
            network.clone(),
            Arc::clone(&state),
        )
        .start(supervisor.shutdown_signal());
        supervisor.monitor(child);

        let (tx_gossiper, child) = TransactionGossiper::from_config(
            config.common.chain.clone(),
            config.transaction_gossiper,
            network.clone(),
            Arc::clone(&queue),
            Arc::clone(&state),
        )
        .start(supervisor.shutdown_signal());
        supervisor.monitor(child);

        supervisor.monitor(task::spawn(
            NetworkRelay {
                sumeragi,
                block_sync,
                tx_gossiper,
                network,
            }
            .run(),
        ));

        if let Some(snapshot_maker) =
            SnapshotMaker::from_config(&config.snapshot, Arc::clone(&state))
        {
            supervisor.monitor(snapshot_maker.start(supervisor.shutdown_signal()));
        }

        let (kiso, child) = KisoHandle::start(config.clone());
        supervisor.monitor(child);

        let torii_run = Torii::new(
            config.common.chain.clone(),
            kiso.clone(),
            config.torii,
            queue,
            events_sender,
            live_query_store,
            kura.clone(),
            state.clone(),
            #[cfg(feature = "telemetry")]
            metrics_reporter,
        )
        .start(supervisor.shutdown_signal());
        supervisor.monitor(Child::new(
            tokio::spawn(async move {
                if let Err(err) = torii_run.await {
                    iroha_logger::error!(?err, "Torii failed to terminate gracefully");
                    // TODO: produce non-zero exit code or something
                } else {
                    iroha_logger::debug!("Torii exited normally");
                };
            }),
            OnShutdown::Wait(Duration::from_secs(5)),
        ));

        supervisor.monitor(tokio::task::spawn(config_updates_relay(kiso, logger)));

        supervisor
            .setup_shutdown_on_os_signals()
            .change_context(StartError::ListenOsSignal)?;

        supervisor.shutdown_on_external_signal(shutdown_signal);

        Ok((Self { kura, state }, async move {
            supervisor.start().await?;
            iroha_logger::info!("Iroha shutdown normally");
            Ok(())
        }))
    }

    #[allow(missing_docs)]
    pub fn state(&self) -> &Arc<State> {
        &self.state
    }

    #[allow(missing_docs)]
    pub fn kura(&self) -> &Arc<Kura> {
        &self.kura
    }
}

#[cfg(feature = "telemetry")]
async fn start_telemetry(
    logger: &LoggerHandle,
    config: &Config,
    supervisor: &mut Supervisor,
) -> Result<(), StartError> {
    const MSG_SUBSCRIBE: &str = "unable to subscribe to the channel";
    const MSG_START_TASK: &str = "unable to start the task";

    #[cfg(feature = "dev-telemetry")]
    {
        if let Some(out_file) = &config.dev_telemetry.out_file {
            let receiver = logger
                .subscribe_on_telemetry(iroha_logger::telemetry::Channel::Future)
                .await
                .change_context(StartError::StartDevTelemetry)
                .attach_printable(MSG_SUBSCRIBE)?;
            let handle =
                iroha_telemetry::dev::start_file_output(out_file.resolve_relative_path(), receiver)
                    .await
                    .into_report()
                    .map_err(|report| report.change_context(StartError::StartDevTelemetry))
                    .attach_printable(MSG_START_TASK)?;
            supervisor.monitor(handle);
        }
    }

    if let Some(config) = &config.telemetry {
        let receiver = logger
            .subscribe_on_telemetry(iroha_logger::telemetry::Channel::Regular)
            .await
            .change_context(StartError::StartTelemetry)
            .attach_printable(MSG_SUBSCRIBE)?;
        let handle = iroha_telemetry::ws::start(config.clone(), receiver)
            .await
            .into_report()
            .map_err(|report| report.change_context(StartError::StartTelemetry))
            .attach_printable(MSG_START_TASK)?;
        supervisor.monitor(handle);
        iroha_logger::info!("Telemetry started");
        Ok(())
    } else {
        iroha_logger::info!("Telemetry not started due to absent configuration");
        Ok(())
    }
}

/// Spawns a task which subscribes on updates from the configuration actor
/// and broadcasts them further to interested actors. This way, neither the config actor nor other ones know
/// about each other, achieving loose coupling of code and system.
async fn config_updates_relay(kiso: KisoHandle, logger: LoggerHandle) {
    let mut log_level_update = kiso
        .subscribe_on_log_level()
        .await
        // FIXME: don't like neither the message nor inability to throw Result to the outside
        .expect("Cannot proceed without working subscriptions");

    // See https://github.com/tokio-rs/tokio/issues/5616 and
    // https://github.com/rust-lang/rust-clippy/issues/10636
    #[allow(clippy::redundant_pub_crate)]
    loop {
        tokio::select! {
            Ok(()) = log_level_update.changed() => {
                let value = log_level_update.borrow_and_update().clone();
                if let Err(error) = logger.reload_level(value).await {
                    iroha_logger::error!("Failed to reload log level: {error}");
                };
            }
            else => {
                iroha_logger::debug!("Exiting config updates relay");
                break;
            }
        };
    }
}

fn genesis_account(public_key: PublicKey) -> Account {
    let genesis_account_id = AccountId::new(iroha_genesis::GENESIS_DOMAIN_ID.clone(), public_key);
    Account::new(genesis_account_id.clone()).build(&genesis_account_id)
}

fn genesis_domain(public_key: PublicKey) -> Domain {
    let genesis_account = genesis_account(public_key);
    Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&genesis_account.id)
}

/// Error of [`read_config_and_genesis`]
#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum ConfigError {
    #[error("Error occurred while reading configuration from file(s) and environment")]
    ReadConfig,
    #[error("Error occurred while validating configuration integrity")]
    ParseConfig,
    #[error("Error occurred while reading genesis block")]
    ReadGenesis,
    #[error("The network consists from this one peer only")]
    LonePeer,
    #[cfg(feature = "dev-telemetry")]
    #[error("Telemetry output file path is root or empty")]
    TelemetryOutFileIsRootOrEmpty,
    #[cfg(feature = "dev-telemetry")]
    #[error("Telemetry output file path is a directory")]
    TelemetryOutFileIsDir,
    #[error("Torii and Network addresses are the same, but should be different")]
    SameNetworkAndToriiAddrs,
    #[error("Invalid directory path found")]
    InvalidDirPath,
    #[error("Network error: cannot listen to address `{addr}`")]
    CannotBindAddress { addr: SocketAddr },
}

/// Read the configuration and then a genesis block if specified.
///
/// # Errors
/// - If failed to read the config
/// - If failed to load the genesis block
pub fn read_config_and_genesis(
    args: &Args,
) -> Result<(Config, LoggerInitConfig, Option<GenesisBlock>), ConfigError> {
    let mut config = ConfigReader::new();

    if let Some(path) = &args.config {
        config = config
            .read_toml_with_extends(path)
            .change_context(ConfigError::ReadConfig)?;
    }

    let config = config
        .read_and_complete::<UserConfig>()
        .change_context(ConfigError::ReadConfig)?
        .parse()
        .change_context(ConfigError::ParseConfig)?;

    let genesis = if let Some(signed_file) = &config.genesis.file {
        let genesis = read_genesis(&signed_file.resolve_relative_path())
            .attach_printable(signed_file.clone().into_attachment().display_path())?;
        Some(genesis)
    } else {
        None
    };

    validate_config(&config)?;

    let logger_config = LoggerInitConfig::new(config.logger.clone(), args.terminal_colors);

    Ok((config, logger_config, genesis))
}

fn read_genesis(path: &Path) -> Result<GenesisBlock, ConfigError> {
    let bytes = std::fs::read(path).change_context(ConfigError::ReadGenesis)?;
    let genesis =
        SignedBlock::decode_all_versioned(&bytes).change_context(ConfigError::ReadGenesis)?;
    Ok(GenesisBlock(genesis))
}

fn validate_config(config: &Config) -> Result<(), ConfigError> {
    let mut emitter = Emitter::new();

    // These cause race condition in tests, due to them actually binding TCP listeners
    // Since these validations are primarily for the convenience of the end user,
    // it seems a fine compromise to run it only in release mode
    #[cfg(not(test))]
    {
        validate_try_bind_address(&mut emitter, &config.network.address);
        validate_try_bind_address(&mut emitter, &config.torii.address);
    }
    validate_directory_path(&mut emitter, &config.kura.store_dir);
    // maybe validate only if snapshot mode is enabled
    validate_directory_path(&mut emitter, &config.snapshot.store_dir);

    if config.genesis.file.is_none()
        && !config
            .sumeragi
            .trusted_peers
            .value()
            .contains_other_trusted_peers()
    {
        emitter.emit(Report::new(ConfigError::LonePeer).attach_printable("\
            Reason: the network consists from this one peer only (no `sumeragi.trusted_peers` provided).\n\
            Since `genesis.file` is not set, there is no way to receive the genesis block.\n\
            Either provide the genesis by setting `genesis.file` configuration parameter,\n\
            or increase the number of trusted peers in the network using `sumeragi.trusted_peers` configuration parameter.\
        ").attach_printable(config.sumeragi.trusted_peers.clone().into_attachment().display_as_debug()));
    }

    if config.network.address.value() == config.torii.address.value() {
        emitter.emit(
            Report::new(ConfigError::SameNetworkAndToriiAddrs)
                .attach_printable(config.network.address.clone().into_attachment())
                .attach_printable(config.torii.address.clone().into_attachment()),
        );
    }

    #[cfg(not(feature = "telemetry"))]
    if config.telemetry.is_some() {
        // TODO: use a centralized configuration logging
        //       https://github.com/hyperledger/iroha/issues/4300
        eprintln!("`telemetry` config is specified, but ignored, because Iroha is compiled without `telemetry` feature enabled");
    }

    #[cfg(not(feature = "dev-telemetry"))]
    if config.dev_telemetry.out_file.is_some() {
        // TODO: use a centralized configuration logging
        //       https://github.com/hyperledger/iroha/issues/4300
        eprintln!("`dev_telemetry.out_file` config is specified, but ignored, because Iroha is compiled without `dev-telemetry` feature enabled");
    }

    #[cfg(feature = "dev-telemetry")]
    if let Some(path) = &config.dev_telemetry.out_file {
        if path.value().parent().is_none() {
            emitter.emit(
                Report::new(ConfigError::TelemetryOutFileIsRootOrEmpty)
                    .attach_printable(path.clone().into_attachment().display_path()),
            );
        }
        if path.value().is_dir() {
            emitter.emit(
                Report::new(ConfigError::TelemetryOutFileIsDir)
                    .attach_printable(path.clone().into_attachment().display_path()),
            );
        }
    }

    emitter.into_result()?;

    Ok(())
}

fn validate_directory_path(emitter: &mut Emitter<ConfigError>, path: &WithOrigin<PathBuf>) {
    #[derive(Debug, Error)]
    #[error(
        "expected path to be either non-existing or a directory, but it points to an existing file: {path}"
    )]
    struct InvalidDirPathError {
        path: PathBuf,
    }

    if path.value().is_file() {
        emitter.emit(
            Report::new(InvalidDirPathError {
                path: path.value().clone(),
            })
            .attach_printable(path.clone().into_attachment().display_path())
            .change_context(ConfigError::InvalidDirPath),
        );
    }
}

#[cfg(not(test))]
fn validate_try_bind_address(emitter: &mut Emitter<ConfigError>, value: &WithOrigin<SocketAddr>) {
    use std::net::TcpListener;

    if let Err(err) = TcpListener::bind(value.value()) {
        emitter.emit(
            Report::new(err)
                .attach_printable(value.clone().into_attachment())
                .change_context(ConfigError::CannotBindAddress {
                    addr: value.value().clone(),
                }),
        )
    }
}

/// Configures globals of [`error_stack::Report`]
fn configure_reports(args: &Args) {
    use std::panic::Location;

    use error_stack::{fmt::ColorMode, Report};

    Report::set_color_mode(if args.terminal_colors {
        ColorMode::Color
    } else {
        ColorMode::None
    });

    // neither devs nor users benefit from it
    Report::install_debug_hook::<Location>(|_, _| {});
}

#[tokio::main]
async fn main() -> error_stack::Result<(), MainError> {
    let args = Args::parse();

    configure_reports(&args);

    if args.trace_config {
        iroha_config::enable_tracing()
            .change_context(MainError::TraceConfigSetup)
            .attach_printable("was enabled by `--trace-config` argument")?;
    }

    let (config, logger_config, genesis) =
        read_config_and_genesis(&args).change_context(MainError::Config).attach_printable_lazy(|| {
            args.config.as_ref().map_or_else(
                || "`--config` arg was not set, therefore configuration relies fully on environment variables".to_owned(),
                |path| format!("config path is specified by `--config` arg: {}", path.display()),
            )
        })?;
    let logger = iroha_logger::init_global(logger_config)
        .into_report()
        // https://github.com/hashintel/hash/issues/4295
        .map_err(|report| report.change_context(MainError::Logger))?;

    iroha_logger::info!(
        version = env!("CARGO_PKG_VERSION"),
        git_commit_sha = env!("VERGEN_GIT_SHA"),
        peer = %config.common.peer,
        chain = %config.common.chain,
        listening_on = %config.torii.address.value(),
        "Hyperledgerいろは2にようこそ！(translation) Welcome to Hyperledger Iroha!"
    );

    if genesis.is_some() {
        iroha_logger::debug!("Submitting genesis.");
    }

    let shutdown_on_panic = ShutdownSignal::new();
    let default_hook = std::panic::take_hook();
    let signal_clone = shutdown_on_panic.clone();
    std::panic::set_hook(Box::new(move |info| {
        iroha_logger::error!("Panic occurred, shutting down Iroha gracefully...");
        signal_clone.send();
        default_hook(info);
    }));

    let (_iroha, supervisor_fut) = Iroha::start(config, genesis, logger, shutdown_on_panic)
        .await
        .change_context(MainError::IrohaStart)?;
    supervisor_fut.await.change_context(MainError::IrohaRun)
}

#[cfg(test)]
mod tests {
    use iroha_genesis::GenesisBuilder;

    use super::*;

    mod config_integration {
        use assertables::{assert_contains, assert_contains_as_result};
        use iroha_crypto::{ExposedPrivateKey, KeyPair};
        use iroha_primitives::addr::socket_addr;
        use iroha_version::Encode;
        use path_absolutize::Absolutize as _;

        use super::*;

        fn config_factory(genesis_public_key: &PublicKey) -> toml::Table {
            let (pubkey, privkey) = KeyPair::random().into_parts();

            let mut table = toml::Table::new();
            iroha_config::base::toml::Writer::new(&mut table)
                .write("chain", "0")
                .write("public_key", pubkey)
                .write("private_key", ExposedPrivateKey(privkey))
                .write(["network", "address"], socket_addr!(127.0.0.1:1337))
                .write(["torii", "address"], socket_addr!(127.0.0.1:8080))
                .write(["genesis", "public_key"], genesis_public_key);
            table
        }

        fn dummy_executor() -> Executor {
            Executor::new(WasmSmartContract::from_compiled(vec![1, 2, 3]))
        }

        #[test]
        fn relative_file_paths_resolution() -> eyre::Result<()> {
            // Given

            let genesis_key_pair = KeyPair::random();
            let genesis = GenesisBuilder::default().build_and_sign(
                ChainId::from("00000000-0000-0000-0000-000000000000"),
                dummy_executor(),
                vec![],
                &genesis_key_pair,
            );

            let mut config = config_factory(genesis_key_pair.public_key());
            iroha_config::base::toml::Writer::new(&mut config)
                .write(["genesis", "file"], "./genesis/genesis.signed.scale")
                .write(["kura", "store_dir"], "../storage")
                .write(["snapshot", "store_dir"], "../snapshots")
                .write(["dev_telemetry", "out_file"], "../logs/telemetry");

            let dir = tempfile::tempdir()?;
            let genesis_path = dir.path().join("config/genesis/genesis.signed.scale");
            let executor_path = dir.path().join("config/genesis/executor.wasm");
            let config_path = dir.path().join("config/config.toml");
            std::fs::create_dir(dir.path().join("config"))?;
            std::fs::create_dir(dir.path().join("config/genesis"))?;
            std::fs::write(config_path, toml::to_string(&config)?)?;
            std::fs::write(genesis_path, genesis.0.encode())?;
            std::fs::write(executor_path, "")?;

            let config_path = dir.path().join("config/config.toml");

            // When

            let (config, _logger, genesis) = read_config_and_genesis(&Args {
                config: Some(config_path),
                terminal_colors: false,
                trace_config: false,
            })
            .map_err(|report| eyre::eyre!("{report:?}"))?;

            // Then

            // No need to check whether genesis.file is resolved - if not, genesis wouldn't be read
            assert!(genesis.is_some());

            assert_eq!(
                config.kura.store_dir.resolve_relative_path().absolutize()?,
                dir.path().join("storage")
            );
            assert_eq!(
                config
                    .snapshot
                    .store_dir
                    .resolve_relative_path()
                    .absolutize()?,
                dir.path().join("snapshots")
            );
            assert_eq!(
                config
                    .dev_telemetry
                    .out_file
                    .expect("dev telemetry should be set")
                    .resolve_relative_path()
                    .absolutize()?,
                dir.path().join("logs/telemetry")
            );

            Ok(())
        }

        #[test]
        fn fails_with_no_trusted_peers_and_submit_role() -> eyre::Result<()> {
            // Given

            let genesis_key_pair = KeyPair::random();
            let mut config = config_factory(genesis_key_pair.public_key());
            iroha_config::base::toml::Writer::new(&mut config);

            let dir = tempfile::tempdir()?;
            std::fs::write(dir.path().join("config.toml"), toml::to_string(&config)?)?;
            std::fs::write(dir.path().join("executor.wasm"), "")?;
            let config_path = dir.path().join("config.toml");

            // When & Then

            let report = read_config_and_genesis(&Args {
                config: Some(config_path),
                terminal_colors: false,
                trace_config: false,
            })
            .unwrap_err();

            assert_contains!(
                format!("{report:#}"),
                "The network consists from this one peer only"
            );

            Ok(())
        }
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)] // for expressiveness
    fn default_args() {
        let args = Args::try_parse_from(["test"]).unwrap();

        assert_eq!(args.terminal_colors, is_coloring_supported());
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)] // for expressiveness
    fn terminal_colors_works_as_expected() -> eyre::Result<()> {
        fn try_with(arg: &str) -> eyre::Result<bool> {
            Ok(Args::try_parse_from(["test", arg])?.terminal_colors)
        }

        assert_eq!(
            Args::try_parse_from(["test"])?.terminal_colors,
            is_coloring_supported()
        );
        assert_eq!(try_with("--terminal-colors")?, true);
        assert_eq!(try_with("--terminal-colors=false")?, false);
        assert_eq!(try_with("--terminal-colors=true")?, true);
        assert!(try_with("--terminal-colors=random").is_err());

        Ok(())
    }

    #[test]
    fn user_provided_config_path_works() {
        let args = Args::try_parse_from(["test", "--config", "/home/custom/file.json"]).unwrap();

        assert_eq!(args.config, Some(PathBuf::from("/home/custom/file.json")));
    }

    #[test]
    fn user_can_provide_any_extension() {
        let _args = Args::try_parse_from(["test", "--config", "file.toml.but.not"])
            .expect("should allow doing this as well");
    }
}
