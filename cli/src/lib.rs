//! Common primitives for a CLI instance of Iroha. If you're
//! customising it for deployment, use this crate as a reference to
//! add more complex behaviour, TUI, GUI, monitoring, etc.
//!
//! `Iroha` is the main instance of the peer program. `Arguments`
//! should be constructed externally: (see `main.rs`).
#[cfg(debug_assertions)]
use core::sync::atomic::{AtomicBool, Ordering};
use std::{path::PathBuf, sync::Arc};

use clap::Parser;
use color_eyre::eyre::{eyre, Result, WrapErr};
use iroha_config::parameters::{actual::Root as Config, user::CliContext};
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
use iroha_data_model::prelude::*;
use iroha_genesis::{GenesisNetwork, RawGenesisBlock};
use iroha_logger::{actor::LoggerHandle, InitConfig as LoggerInitConfig};
use iroha_torii::Torii;
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
///
/// # Usage
/// Construct and then use [`Iroha::start()`] or [`Iroha::start_as_task()`]. If you experience
/// an immediate shutdown after constructing Iroha, then you probably forgot this step.
#[must_use = "run `.start().await?` to not immediately stop Iroha"]
pub struct Iroha {
    /// Actor responsible for the configuration
    pub kiso: KisoHandle,
    /// Queue of transactions
    pub queue: Arc<Queue>,
    /// Sumeragi consensus
    pub sumeragi: SumeragiHandle,
    /// Kura — block storage
    pub kura: Arc<Kura>,
    /// Torii web server
    pub torii: Option<Torii>,
    /// Snapshot service. Might be not started depending on the config.
    pub snapshot_maker: Option<SnapshotMakerHandle>,
    /// State of blockchain
    pub state: Arc<State>,
    /// Thread handlers
    thread_handlers: Vec<ThreadHandler>,

    /// A boolean value indicating whether or not the peers will receive data from the network.
    /// Used in sumeragi testing.
    #[cfg(debug_assertions)]
    pub freeze_status: Arc<AtomicBool>,
}

impl Drop for Iroha {
    fn drop(&mut self) {
        iroha_logger::trace!("Iroha instance dropped");
        let _thread_handles = core::mem::take(&mut self.thread_handlers);
        iroha_logger::debug!(
            "Thread handles dropped. Dependent processes going for a graceful shutdown"
        )
    }
}

struct NetworkRelay {
    sumeragi: SumeragiHandle,
    block_sync: BlockSynchronizerHandle,
    gossiper: TransactionGossiperHandle,
    network: IrohaNetwork,
    shutdown_notify: Arc<Notify>,
    #[cfg(debug_assertions)]
    freeze_status: Arc<AtomicBool>,
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
        if self.freeze_status.load(Ordering::SeqCst) {
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

    /// Create new Iroha instance.
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
    pub async fn new(
        config: Config,
        genesis: Option<GenesisNetwork>,
        logger: LoggerHandle,
    ) -> Result<Self> {
        let network = IrohaNetwork::start(config.common.key_pair.clone(), config.network.clone())
            .await
            .wrap_err("Unable to start P2P-network")?;

        let (events_sender, _) = broadcast::channel(10000);
        let world = World::with(
            [genesis_domain(config.genesis.public_key().clone())],
            config.sumeragi.trusted_peers.clone(),
        );

        let kura = Kura::new(&config.kura)?;
        let kura_thread_handler = Kura::start(Arc::clone(&kura));
        let live_query_store_handle = LiveQueryStore::from_config(config.live_query_store).start();

        let block_count = kura.init()?;

        let state = match try_read_snapshot(
            &config.snapshot.store_dir,
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
            State::from_config(
                config.chain_wide,
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
                public_key: config.genesis.public_key().clone(),
            },
            block_count,
            sumeragi_metrics: SumeragiMetrics {
                dropped_messages: metrics_reporter.metrics().dropped_messages.clone(),
                view_changes: metrics_reporter.metrics().view_changes.clone(),
            },
        };
        // Starting Sumeragi requires no async context enabled
        let sumeragi = tokio::task::spawn_blocking(move || SumeragiHandle::start(start_args))
            .await
            .expect("Failed to join task with Sumeragi start");

        let block_sync = BlockSynchronizer::from_config(
            &config.block_sync,
            sumeragi.clone(),
            Arc::clone(&kura),
            config.common.peer_id(),
            network.clone(),
            Arc::clone(&state),
        )
        .start();

        let gossiper = TransactionGossiper::from_config(
            config.common.chain_id.clone(),
            config.transaction_gossiper,
            network.clone(),
            Arc::clone(&queue),
            Arc::clone(&state),
        )
        .start();

        #[cfg(debug_assertions)]
        let freeze_status = Arc::new(AtomicBool::new(false));

        let notify_shutdown = Arc::new(Notify::new());

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
            config.common.chain_id.clone(),
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

        Self::spawn_config_updates_broadcasting(kiso.clone(), logger.clone());

        Self::start_listening_signal(Arc::clone(&notify_shutdown))?;

        Self::prepare_panic_hook(notify_shutdown);

        let torii = Some(torii);
        Ok(Self {
            kiso,
            queue,
            sumeragi,
            kura,
            torii,
            snapshot_maker,
            state,
            thread_handlers: vec![kura_thread_handler],
            #[cfg(debug_assertions)]
            freeze_status,
        })
    }

    /// To make `Iroha` peer work it should be started first. After
    /// that moment it will listen for incoming requests and messages.
    ///
    /// # Errors
    /// - Forwards initialisation error.
    #[iroha_futures::telemetry_future]
    pub async fn start(&mut self) -> Result<()> {
        iroha_logger::info!("Starting Iroha");
        self.torii
            .take()
            .ok_or_else(|| eyre!("Torii is unavailable. Ensure nothing `take`s the Torii instance before this line"))?
            .start()
            .await
            .wrap_err("Failed to start Torii")
    }

    /// Starts iroha in separate tokio task.
    ///
    /// # Errors
    /// - Forwards initialisation error.
    #[cfg(feature = "test-network")]
    pub fn start_as_task(&mut self) -> Result<tokio::task::JoinHandle<eyre::Result<()>>> {
        iroha_logger::info!("Starting Iroha as task");
        let torii = self
            .torii
            .take()
            .ok_or_else(|| eyre!("Peer already started in a different task"))?;
        Ok(tokio::spawn(async move {
            torii.start().await.wrap_err("Failed to start Torii")
        }))
    }

    #[cfg(feature = "telemetry")]
    async fn start_telemetry(logger: &LoggerHandle, config: &Config) -> Result<()> {
        #[cfg(feature = "dev-telemetry")]
        {
            if let Some(out_file) = &config.dev_telemetry.out_file {
                let receiver = logger
                    .subscribe_on_telemetry(iroha_logger::telemetry::Channel::Future)
                    .await
                    .wrap_err("Failed to subscribe on telemetry")?;
                let _handle = iroha_telemetry::dev::start_file_output(out_file.clone(), receiver)
                    .await
                    .wrap_err("Failed to setup telemetry for futures")?;
            }
        }

        if let Some(config) = &config.telemetry {
            let receiver = logger
                .subscribe_on_telemetry(iroha_logger::telemetry::Channel::Regular)
                .await
                .wrap_err("Failed to subscribe on telemetry")?;
            let _handle = iroha_telemetry::ws::start(config.clone(), receiver)
                .await
                .wrap_err("Failed to setup telemetry for websocket communication")?;
            iroha_logger::info!("Telemetry started");
            Ok(())
        } else {
            iroha_logger::info!("Telemetry not started due to absent configuration");
            Ok(())
        }
    }

    fn start_listening_signal(notify_shutdown: Arc<Notify>) -> Result<task::JoinHandle<()>> {
        let (mut sigint, mut sigterm) = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .and_then(|sigint| {
                let sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;

                Ok((sigint, sigterm))
            })
            .wrap_err("Failed to start listening for OS signals")?;

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
                        let value = *log_level_update.borrow_and_update();
                        if let Err(error) = logger.reload_level(value).await {
                            iroha_logger::error!("Failed to reload log level: {error}");
                        };
                    }
                };
            }
        })
    }
}

fn genesis_account(public_key: PublicKey) -> Account {
    let genesis_account_id = AccountId::new(iroha_genesis::GENESIS_DOMAIN_ID.clone(), public_key);
    Account::new(genesis_account_id.clone()).build(&genesis_account_id)
}

fn genesis_domain(public_key: PublicKey) -> Domain {
    let genesis_account = genesis_account(public_key);
    let mut domain =
        Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&genesis_account.id);

    domain
        .accounts
        .insert(genesis_account.id.clone(), genesis_account);

    domain
}

/// Read the configuration and then a genesis block if specified.
///
/// # Errors
/// - If failed to read the config
/// - If failed to load the genesis block
/// - If failed to build a genesis network
pub fn read_config_and_genesis(
    args: &Args,
) -> Result<(Config, LoggerInitConfig, Option<GenesisNetwork>)> {
    use iroha_config::parameters::actual::Genesis;

    let config = Config::load(
        args.config.as_ref(),
        CliContext {
            submit_genesis: args.submit_genesis,
        },
    )
    .wrap_err("failed to load configuration")?;

    let genesis = if let Genesis::Full { key_pair, file } = &config.genesis {
        let raw_block = RawGenesisBlock::from_path(file)?;

        Some(GenesisNetwork::new(
            raw_block,
            &config.common.chain_id,
            key_pair,
        ))
    } else {
        None
    };

    let logger_config = LoggerInitConfig::new(config.logger, args.terminal_colors);

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

    Ok((config, logger_config, genesis))
}

#[allow(missing_docs)]
pub fn is_colouring_supported() -> bool {
    supports_color::on(supports_color::Stream::Stdout).is_some()
}

fn default_terminal_colors_str() -> clap::builder::OsStr {
    is_colouring_supported().to_string().into()
}

/// Iroha peer Command-Line Interface.
#[derive(Parser, Debug)]
#[command(
    name = "iroha",
    version = concat!("version=", env!("CARGO_PKG_VERSION"), " git_commit_sha=", env!("VERGEN_GIT_SHA"), " cargo_features=", env!("VERGEN_CARGO_FEATURES")),
    author
)]
pub struct Args {
    /// Path to the configuration file
    #[arg(long, short, value_name("PATH"), value_hint(clap::ValueHint::FilePath))]
    pub config: Option<PathBuf>,
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
    /// Whether the current peer should submit the genesis block or not
    ///
    /// Only one peer in the network should submit the genesis block.
    ///
    /// This argument must be set alongside with `genesis.file` and `genesis.private_key`
    /// configuration options. If not, Iroha will exit with an error.
    ///
    /// In case when the network consists only of this one peer, i.e. the amount of trusted
    /// peers in the configuration (`sumeragi.trusted_peers`) is less than 2, this peer must
    /// submit the genesis, since there are no other peers who can provide it. In this case, Iroha
    /// will exit with an error if `--submit-genesis` is not set.
    #[arg(long)]
    pub submit_genesis: bool,
}

#[cfg(test)]
mod tests {
    use iroha_genesis::RawGenesisBlockBuilder;

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
            <crate::Iroha>::prepare_panic_hook(Arc::clone(&notify));
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
        use std::path::PathBuf;

        use assertables::{assert_contains, assert_contains_as_result};
        use iroha_config::parameters::user::RootPartial as PartialUserConfig;
        use iroha_crypto::KeyPair;
        use iroha_primitives::addr::socket_addr;
        use path_absolutize::Absolutize as _;

        use super::*;

        fn config_factory() -> PartialUserConfig {
            let (pubkey, privkey) = KeyPair::random().into_parts();

            let mut base = PartialUserConfig::default();

            base.chain_id.set(ChainId::from("0"));
            base.public_key.set(pubkey.clone());
            base.private_key.set(privkey.clone());
            base.network.address.set(socket_addr!(127.0.0.1:1337));

            base.genesis.public_key.set(pubkey);
            base.genesis.private_key.set(privkey);

            base.torii.address.set(socket_addr!(127.0.0.1:8080));

            base
        }

        fn config_to_toml_value(config: PartialUserConfig) -> Result<toml::Value> {
            use iroha_crypto::ExposedPrivateKey;
            let private_key = config.private_key.as_ref().unwrap().clone();
            let genesis_private_key = config.genesis.private_key.as_ref().unwrap().clone();
            let mut result = toml::Value::try_from(config)?;

            // private key will be serialized as "[REDACTED PrivateKey]" so need to restore it
            result["private_key"] = toml::Value::try_from(ExposedPrivateKey(private_key))?;
            result["genesis"]["private_key"] =
                toml::Value::try_from(ExposedPrivateKey(genesis_private_key))?;

            Ok(result)
        }

        #[test]
        fn relative_file_paths_resolution() -> Result<()> {
            // Given

            let genesis = RawGenesisBlockBuilder::default()
                .executor_file(PathBuf::from("./executor.wasm"))
                .build();

            let config = {
                let mut cfg = config_factory();
                cfg.genesis.file.set("./genesis/gen.json".into());
                cfg.kura.store_dir.set("../storage".into());
                cfg.snapshot.store_dir.set("../snapshots".into());
                cfg.dev_telemetry.out_file.set("../logs/telemetry".into());
                config_to_toml_value(cfg)?
            };

            let dir = tempfile::tempdir()?;
            let genesis_path = dir.path().join("config/genesis/gen.json");
            let executor_path = dir.path().join("config/genesis/executor.wasm");
            let config_path = dir.path().join("config/config.toml");
            std::fs::create_dir(dir.path().join("config"))?;
            std::fs::create_dir(dir.path().join("config/genesis"))?;
            std::fs::write(config_path, toml::to_string(&config)?)?;
            std::fs::write(genesis_path, json5::to_string(&genesis)?)?;
            std::fs::write(executor_path, "")?;

            let config_path = dir.path().join("config/config.toml");

            // When

            let (config, _logger, genesis) = read_config_and_genesis(&Args {
                config: Some(config_path),
                submit_genesis: true,
                terminal_colors: false,
            })?;

            // Then

            // No need to check whether genesis.file is resolved - if not, genesis wouldn't be read
            assert!(genesis.is_some());

            assert_eq!(
                config.kura.store_dir.absolutize()?,
                dir.path().join("storage")
            );
            assert_eq!(
                config.snapshot.store_dir.absolutize()?,
                dir.path().join("snapshots")
            );
            assert_eq!(
                config
                    .dev_telemetry
                    .out_file
                    .expect("dev telemetry should be set")
                    .absolutize()?,
                dir.path().join("logs/telemetry")
            );

            Ok(())
        }

        #[test]
        fn fails_with_no_trusted_peers_and_submit_role() -> Result<()> {
            // Given

            let genesis = RawGenesisBlockBuilder::default()
                .executor_file(PathBuf::from("./executor.wasm"))
                .build();

            let config = {
                let mut cfg = config_factory();
                cfg.genesis.file.set("./genesis.json".into());
                config_to_toml_value(cfg)?
            };

            let dir = tempfile::tempdir()?;
            std::fs::write(dir.path().join("config.toml"), toml::to_string(&config)?)?;
            std::fs::write(dir.path().join("genesis.json"), json5::to_string(&genesis)?)?;
            std::fs::write(dir.path().join("executor.wasm"), "")?;
            let config_path = dir.path().join("config.toml");

            // When & Then

            let report = read_config_and_genesis(&Args {
                config: Some(config_path),
                submit_genesis: false,
                terminal_colors: false,
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
    fn default_args() -> Result<()> {
        let args = Args::try_parse_from(["test"])?;

        assert_eq!(args.terminal_colors, is_colouring_supported());
        assert_eq!(args.submit_genesis, false);

        Ok(())
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)] // for expressiveness
    fn terminal_colors_works_as_expected() -> Result<()> {
        fn try_with(arg: &str) -> Result<bool> {
            Ok(Args::try_parse_from(["test", arg])?.terminal_colors)
        }

        assert_eq!(
            Args::try_parse_from(["test"])?.terminal_colors,
            is_colouring_supported()
        );
        assert_eq!(try_with("--terminal-colors")?, true);
        assert_eq!(try_with("--terminal-colors=false")?, false);
        assert_eq!(try_with("--terminal-colors=true")?, true);
        assert!(try_with("--terminal-colors=random").is_err());

        Ok(())
    }

    #[test]
    fn user_provided_config_path_works() -> Result<()> {
        let args = Args::try_parse_from(["test", "--config", "/home/custom/file.json"])?;

        assert_eq!(args.config, Some(PathBuf::from("/home/custom/file.json")));

        Ok(())
    }

    #[test]
    fn user_can_provide_any_extension() {
        let _args = Args::try_parse_from(["test", "--config", "file.toml.but.not"])
            .expect("should allow doing this as well");
    }
}
