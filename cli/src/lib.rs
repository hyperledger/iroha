//! Common primitives for a CLI instance of Iroha. If you're
//! customising it for deployment, use this crate as a reference to
//! add more complex behaviour, TUI, GUI, monitoring, etc.
//!
//! `Iroha` is the main instance of the peer program. `Arguments`
//! should be constructed externally: (see `main.rs`).
#[cfg(debug_assertions)]
use core::sync::atomic::{AtomicBool, Ordering};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Parser;
use error_stack::{IntoReportCompat, Report, Result, ResultExt};
use iroha_config::{
    base::{read::ConfigReader, util::Emitter, WithOrigin},
    parameters::{actual::Root as Config, user::Root as UserConfig},
};
#[cfg(feature = "telemetry")]
use iroha_core::metrics::MetricsReporter;
use iroha_core::{
    block_sync::{BlockSynchronizer, BlockSynchronizerHandle},
    gossiper::{TransactionGossiper, TransactionGossiperHandle},
    handler::ThreadHandler,
    kiso::KisoHandle,
    kura::Kura,
    query::store::LiveQueryStore,
    queue::Queue,
    smartcontracts::isi::Registrable as _,
    snapshot::{
        try_read_snapshot, SnapshotMaker, SnapshotMakerHandle, TryReadError as TryReadSnapshotError,
    },
    state::{State, StateReadOnly, World},
    sumeragi::{GenesisWithPubKey, SumeragiHandle, SumeragiMetrics, SumeragiStartArgs},
    IrohaNetwork,
};
use iroha_data_model::{block::SignedBlock, prelude::*};
use iroha_genesis::GenesisBlock;
use iroha_logger::{actor::LoggerHandle, InitConfig as LoggerInitConfig};
use iroha_primitives::addr::SocketAddr;
use iroha_torii::Torii;
use iroha_version::scale::DecodeVersioned;
use thiserror::Error;
use tokio::{
    signal,
    sync::{broadcast, mpsc, Notify},
    task,
};

// FIXME: move from CLI
pub mod samples;

/// Iroha is an
/// [Orchestrator](https://en.wikipedia.org/wiki/Orchestration_%28computing%29)
/// of the system. It configures, coordinates and manages transactions
/// and queries processing, work of consensus and storage.
pub struct Iroha {
    /// Actor responsible for the configuration
    _kiso: KisoHandle,
    /// Queue of transactions
    _queue: Arc<Queue>,
    /// Sumeragi consensus
    _sumeragi: SumeragiHandle,
    /// Kura — block storage
    kura: Arc<Kura>,
    /// Snapshot service. Might be not started depending on the config.
    _snapshot_maker: Option<SnapshotMakerHandle>,
    /// State of blockchain
    state: Arc<State>,
    /// Shutdown signal
    notify_shutdown: Arc<Notify>,
    /// Thread handlers
    thread_handlers: Vec<ThreadHandler>,
    /// A boolean value indicating whether or not the peers will receive data from the network.
    /// Used in sumeragi testing.
    #[cfg(debug_assertions)]
    pub freeze_status: FreezeStatus,
}

impl Drop for Iroha {
    fn drop(&mut self) {
        iroha_logger::trace!("Iroha instance dropped");
        self.notify_shutdown.notify_waiters();
        let _thread_handles = core::mem::take(&mut self.thread_handlers);
        iroha_logger::debug!(
            "Thread handles dropped. Dependent processes going for a graceful shutdown"
        )
    }
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

/// Handle for freezing and unfreezing the network
#[derive(Clone)]
#[cfg(debug_assertions)]
pub struct FreezeStatus(Arc<AtomicBool>, PeerId);

#[cfg(debug_assertions)]
impl FreezeStatus {
    pub(crate) fn new(peer_id: PeerId) -> Self {
        Self(Arc::new(AtomicBool::new(false)), peer_id)
    }

    /// Stop listening for messages
    pub fn freeze(&self) {
        iroha_logger::warn!(peer_id=%self.1, "NetworkRelay is frozen");
        self.0.store(true, Ordering::SeqCst);
    }
    /// Start listening for messages
    pub fn unfreeze(&self) {
        iroha_logger::warn!(peer_id=%self.1, "NetworkRelay is unfrozen");
        self.0.store(false, Ordering::SeqCst);
    }
}

struct NetworkRelay {
    sumeragi: SumeragiHandle,
    block_sync: BlockSynchronizerHandle,
    gossiper: TransactionGossiperHandle,
    network: IrohaNetwork,
    shutdown_notify: Arc<Notify>,
    #[cfg(debug_assertions)]
    freeze_status: FreezeStatus,
}

impl NetworkRelay {
    fn start(self) {
        tokio::task::spawn(self.run());
    }

    async fn run(mut self) {
        let (sender, mut receiver) = mpsc::channel(1);
        self.network.subscribe_to_peers_messages(sender);
        // NOTE: Triggered by tokio::select
        #[allow(clippy::redundant_pub_crate)]
        loop {
            tokio::select! {
                // Receive message from network
                Some(msg) = receiver.recv() => self.handle_message(msg).await,
                () = self.shutdown_notify.notified() => {
                    iroha_logger::info!("NetworkRelay is being shut down.");
                    break;
                }
                else => break,
            }
            tokio::task::yield_now().await;
        }
    }

    async fn handle_message(&mut self, msg: iroha_core::NetworkMessage) {
        use iroha_core::NetworkMessage::*;

        #[cfg(debug_assertions)]
        if self.freeze_status.0.load(Ordering::SeqCst) {
            return;
        }

        match msg {
            SumeragiBlock(data) => {
                self.sumeragi.incoming_block_message(*data);
            }
            SumeragiControlFlow(data) => {
                self.sumeragi.incoming_control_flow_message(*data);
            }
            BlockSync(data) => self.block_sync.message(*data).await,
            TransactionGossiper(data) => self.gossiper.gossip(*data).await,
            Health => {}
        }
    }
}

impl Iroha {
    fn prepare_panic_hook(notify_shutdown: Arc<Notify>) {
        #[cfg(not(feature = "test-network"))]
        use std::panic::set_hook;

        // This is a hot-fix for tests
        //
        // # Problem
        //
        // When running tests in parallel `std::panic::set_hook()` will be set
        // the same for all threads. That means, that panic in one test can
        // cause another test shutdown, which we don't want.
        //
        // # Downside
        //
        // A downside of this approach is that this panic hook will not work for
        // threads created by Iroha itself (e.g. Sumeragi thread).
        //
        // # TODO
        //
        // Remove this when all Rust integrations tests will be converted to a
        // separate Python tests.
        #[cfg(feature = "test-network")]
        use thread_local_panic_hook::set_hook;

        set_hook(Box::new(move |info| {
            // What clippy suggests is much less readable in this case
            #[allow(clippy::option_if_let_else)]
            let panic_message = if let Some(message) = info.payload().downcast_ref::<&str>() {
                message
            } else if let Some(message) = info.payload().downcast_ref::<String>() {
                message
            } else {
                "unspecified"
            };

            let location = info.location().map_or_else(
                || "unspecified".to_owned(),
                |location| format!("{}:{}", location.file(), location.line()),
            );

            iroha_logger::error!(panic_message, location, "A panic occurred, shutting down");

            // NOTE: shutdown all currently listening waiters
            notify_shutdown.notify_waiters();
        }));
    }

    /// Creates new Iroha instance and starts all internal services.
    ///
    /// Returns iroha itself and future to await for iroha completion.
    ///
    /// # Errors
    /// - Reading telemetry configs
    /// - Telemetry setup
    /// - Initialization of [`Sumeragi`] and [`Kura`]
    ///
    /// # Side Effects
    /// - Sets global panic hook
    #[allow(clippy::too_many_lines)]
    #[iroha_logger::log(name = "init", skip_all)] // This is actually easier to understand as a linear sequence of init statements.
    pub async fn start_network(
        config: Config,
        genesis: Option<GenesisBlock>,
        logger: LoggerHandle,
    ) -> Result<(impl core::future::Future<Output = ()>, Self), StartError> {
        let network = IrohaNetwork::start(config.common.key_pair.clone(), config.network.clone())
            .await
            .change_context(StartError::StartP2p)?;

        let (events_sender, _) = broadcast::channel(10000);
        let world = World::with(
            [genesis_domain(config.genesis.public_key.clone())],
            [genesis_account(config.genesis.public_key.clone())],
            [],
        );

        let notify_shutdown = Arc::new(Notify::new());

        let (kura, block_count) = Kura::new(&config.kura).change_context(StartError::InitKura)?;
        let kura_thread_handler = Kura::start(Arc::clone(&kura));
        let live_query_store_handle =
            LiveQueryStore::from_config(config.live_query_store, Arc::clone(&notify_shutdown))
                .start();

        let state = match try_read_snapshot(
            config.snapshot.store_dir.resolve_relative_path(),
            &kura,
            live_query_store_handle.clone(),
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
            State::new(
                world,
                Arc::clone(&kura),
                live_query_store_handle.clone(),
            )
        });
        let state = Arc::new(state);

        let queue = Arc::new(Queue::from_config(config.queue, events_sender.clone()));

        #[cfg(feature = "telemetry")]
        Self::start_telemetry(&logger, &config).await?;

        #[cfg(feature = "telemetry")]
        let metrics_reporter = MetricsReporter::new(
            Arc::clone(&state),
            network.clone(),
            kura.clone(),
            queue.clone(),
        );

        let start_args = SumeragiStartArgs {
            sumeragi_config: config.sumeragi.clone(),
            common_config: config.common.clone(),
            events_sender: events_sender.clone(),
            state: Arc::clone(&state),
            queue: Arc::clone(&queue),
            kura: Arc::clone(&kura),
            network: network.clone(),
            genesis_network: GenesisWithPubKey {
                genesis,
                public_key: config.genesis.public_key.clone(),
            },
            block_count,
            sumeragi_metrics: SumeragiMetrics {
                dropped_messages: metrics_reporter.metrics().dropped_messages.clone(),
                view_changes: metrics_reporter.metrics().view_changes.clone(),
            },
        };
        // Starting Sumeragi requires no async context enabled
        let sumeragi = task::spawn_blocking(move || SumeragiHandle::start(start_args))
            .await
            .expect("Failed to join task with Sumeragi start");

        let block_sync = BlockSynchronizer::from_config(
            &config.block_sync,
            sumeragi.clone(),
            Arc::clone(&kura),
            config.common.peer.clone(),
            network.clone(),
            Arc::clone(&state),
        )
        .start();

        let gossiper = TransactionGossiper::from_config(
            config.common.chain.clone(),
            config.transaction_gossiper,
            network.clone(),
            Arc::clone(&queue),
            Arc::clone(&state),
        )
        .start();

        #[cfg(debug_assertions)]
        let freeze_status = FreezeStatus::new(config.common.peer.clone());

        NetworkRelay {
            sumeragi: sumeragi.clone(),
            block_sync,
            gossiper,
            network: network.clone(),
            shutdown_notify: Arc::clone(&notify_shutdown),
            #[cfg(debug_assertions)]
            freeze_status: freeze_status.clone(),
        }
        .start();

        let snapshot_maker = SnapshotMaker::from_config(&config.snapshot, Arc::clone(&state))
            .map(SnapshotMaker::start);

        let kiso = KisoHandle::new(config.clone());

        let torii = Torii::new(
            config.common.chain.clone(),
            kiso.clone(),
            config.torii,
            Arc::clone(&queue),
            events_sender,
            Arc::clone(&notify_shutdown),
            live_query_store_handle,
            Arc::clone(&kura),
            Arc::clone(&state),
            #[cfg(feature = "telemetry")]
            metrics_reporter,
        );

        let run_torii = torii
            .start()
            .await
            .map_err(|report| report.change_context(StartError::StartTorii))?;

        tokio::spawn(run_torii);

        Self::spawn_config_updates_broadcasting(kiso.clone(), logger.clone());

        Self::start_listening_signal(Arc::clone(&notify_shutdown))?;

        Self::prepare_panic_hook(Arc::clone(&notify_shutdown));

        // Future to wait for iroha completion
        let wait = {
            let notify_shutdown = Arc::clone(&notify_shutdown);
            async move { notify_shutdown.notified().await }
        };

        let irohad = Self {
            _kiso: kiso,
            _queue: queue,
            _sumeragi: sumeragi,
            kura,
            _snapshot_maker: snapshot_maker,
            state,
            notify_shutdown,
            thread_handlers: vec![kura_thread_handler],
            #[cfg(debug_assertions)]
            freeze_status,
        };

        Ok((wait, irohad))
    }

    #[cfg(feature = "telemetry")]
    async fn start_telemetry(logger: &LoggerHandle, config: &Config) -> Result<(), StartError> {
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
                let _handle = iroha_telemetry::dev::start_file_output(
                    out_file.resolve_relative_path(),
                    receiver,
                )
                .await
                .into_report()
                .map_err(|report| report.change_context(StartError::StartDevTelemetry))
                .attach_printable(MSG_START_TASK)?;
            }
        }

        if let Some(config) = &config.telemetry {
            let receiver = logger
                .subscribe_on_telemetry(iroha_logger::telemetry::Channel::Regular)
                .await
                .change_context(StartError::StartTelemetry)
                .attach_printable(MSG_SUBSCRIBE)?;
            let _handle = iroha_telemetry::ws::start(config.clone(), receiver)
                .await
                .into_report()
                .map_err(|report| report.change_context(StartError::StartTelemetry))
                .attach_printable(MSG_START_TASK)?;
            iroha_logger::info!("Telemetry started");
            Ok(())
        } else {
            iroha_logger::info!("Telemetry not started due to absent configuration");
            Ok(())
        }
    }

    fn start_listening_signal(
        notify_shutdown: Arc<Notify>,
    ) -> Result<task::JoinHandle<()>, StartError> {
        let (mut sigint, mut sigterm) = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .and_then(|sigint| {
                let sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;

                Ok((sigint, sigterm))
            })
            .change_context(StartError::ListenOsSignal)?;

        // NOTE: Triggered by tokio::select
        #[allow(clippy::redundant_pub_crate)]
        let handle = task::spawn(async move {
            tokio::select! {
                _ = sigint.recv() => {
                    iroha_logger::info!("SIGINT received, shutting down...");
                },
                _ = sigterm.recv() => {
                    iroha_logger::info!("SIGTERM received, shutting down...");
                },
            }

            // NOTE: shutdown all currently listening waiters
            notify_shutdown.notify_waiters();
        });

        Ok(handle)
    }

    /// Spawns a task which subscribes on updates from configuration actor
    /// and broadcasts them further to interested actors. This way, neither config actor nor other ones know
    /// about each other, achieving loose coupling of code and system.
    fn spawn_config_updates_broadcasting(
        kiso: KisoHandle,
        logger: LoggerHandle,
    ) -> task::JoinHandle<()> {
        tokio::spawn(async move {
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
                };
            }
        })
    }

    #[allow(missing_docs)]
    #[cfg(debug_assertions)]
    pub fn freeze_status(&self) -> &FreezeStatus {
        &self.freeze_status
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
    let mut reader = ConfigReader::new();

    if let Some(path) = &args.config {
        reader = reader
            .read_toml_with_extends(path)
            .change_context(ConfigError::ReadConfig)?;
    }

    let config = reader
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
    #[cfg(release)]
    {
        validate_try_bind_address(&mut emitter, &config.network.address);
        validate_try_bind_address(&mut emitter, &config.torii.address);
    }
    validate_directory_path(&mut emitter, &config.kura.store_dir);
    // maybe validate only if snapshot mode is enabled
    validate_directory_path(&mut emitter, &config.snapshot.store_dir);

    if config.genesis.file.is_none() && !config.sumeragi.contains_other_trusted_peers() {
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

#[cfg(release)]
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
    /// Whether to enable ANSI colored output or not
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

#[cfg(test)]
mod tests {
    use iroha_genesis::GenesisBuilder;

    use super::*;

    #[cfg(not(feature = "test-network"))]
    mod no_test_network {
        use std::{iter::repeat, panic, thread};

        use futures::future::join_all;
        use serial_test::serial;

        use super::*;

        #[tokio::test]
        #[serial]
        async fn iroha_should_notify_on_panic() {
            let notify = Arc::new(Notify::new());
            let hook = panic::take_hook();
            crate::Iroha::prepare_panic_hook(Arc::clone(&notify));
            let waiters: Vec<_> = repeat(()).take(10).map(|_| Arc::clone(&notify)).collect();
            let handles: Vec<_> = waiters.iter().map(|waiter| waiter.notified()).collect();
            thread::spawn(move || {
                panic!("Test panic");
            });
            join_all(handles).await;
            panic::set_hook(hook);
        }
    }

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
