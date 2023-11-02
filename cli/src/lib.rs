//! Common primitives for a CLI instance of Iroha. If you're
//! customising it for deployment, use this crate as a reference to
//! add more complex behaviour, TUI, GUI, monitoring, etc.
//!
//! `Iroha` is the main instance of the peer program. `Arguments`
//! should be constructed externally: (see `main.rs`).
#[cfg(debug_assertions)]
use core::sync::atomic::{AtomicBool, Ordering};
use std::{path::Path, sync::Arc};

use color_eyre::eyre::{eyre, Result, WrapErr};
use iroha_config::parameters::{actual::Root as Config, user::CliContext};
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
    state::{State, World},
    sumeragi::{SumeragiHandle, SumeragiStartArgs},
    IrohaNetwork,
};
use iroha_data_model::prelude::*;
use iroha_genesis::{GenesisNetwork, RawGenesisBlock};
use iroha_logger::actor::LoggerHandle;
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
        let network = IrohaNetwork::start(
            config.common.p2p_address.clone(),
            config.common.key_pair.clone(),
        )
        .await
        .wrap_err("Unable to start P2P-network")?;

        let (events_sender, _) = broadcast::channel(10000);
        let world = World::with(
            [genesis_domain(config.genesis.public_key().clone())],
            config.sumeragi.trusted_peers.clone(),
        );

        let kura = Kura::new(&config.kura)?;
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
                    "Successfully loaded state from a snapshot"
                );
                Some(state)
            }
            Err(TryReadSnapshotError::NotFound) => {
                iroha_logger::info!("Didn't find a snapshot of state, creating an empty one");
                None
            }
            Err(error) => {
                iroha_logger::warn!(%error, "Failed to load state from a snapshot, creating an empty one");
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

        let queue = Arc::new(Queue::from_config(config.queue));
        match Self::start_telemetry(&logger, &config).await? {
            TelemetryStartStatus::Started => iroha_logger::info!("Telemetry started"),
            TelemetryStartStatus::NotStarted => iroha_logger::warn!("Telemetry not started"),
        };

        let kura_thread_handler = Kura::start(Arc::clone(&kura));

        let start_args = SumeragiStartArgs {
            sumeragi_config: config.sumeragi.clone(),
            common_config: config.common.clone(),
            events_sender: events_sender.clone(),
            state: Arc::clone(&state),
            queue: Arc::clone(&queue),
            kura: Arc::clone(&kura),
            network: network.clone(),
            genesis_network: genesis,
            block_count,
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
            sumeragi.clone(),
            live_query_store_handle,
            Arc::clone(&kura),
            Arc::clone(&state),
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
    async fn start_telemetry(
        logger: &LoggerHandle,
        config: &Config,
    ) -> Result<TelemetryStartStatus> {
        #[cfg(feature = "dev-telemetry")]
        {
            if let Some(config) = &config.dev_telemetry {
                let receiver = logger
                    .subscribe_on_telemetry(iroha_logger::telemetry::Channel::Future)
                    .await
                    .wrap_err("Failed to subscribe on telemetry")?;
                let _handle = iroha_telemetry::dev::start(config.clone(), receiver)
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

            Ok(TelemetryStartStatus::Started)
        } else {
            Ok(TelemetryStartStatus::NotStarted)
        }
    }

    #[cfg(not(feature = "telemetry"))]
    async fn start_telemetry(
        _logger: &LoggerHandle,
        _config: &Config,
    ) -> Result<TelemetryStartStatus> {
        Ok(TelemetryStartStatus::NotStarted)
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

enum TelemetryStartStatus {
    Started,
    NotStarted,
}

fn genesis_account(public_key: PublicKey) -> Account {
    Account::new(iroha_genesis::GENESIS_ACCOUNT_ID.clone(), public_key)
        .build(&iroha_genesis::GENESIS_ACCOUNT_ID)
}

fn genesis_domain(public_key: PublicKey) -> Domain {
    let mut domain = Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone())
        .build(&iroha_genesis::GENESIS_ACCOUNT_ID);

    domain.accounts.insert(
        iroha_genesis::GENESIS_ACCOUNT_ID.clone(),
        genesis_account(public_key),
    );

    domain
}

/// Read configuration and then a genesis block if specified.
///
/// # Errors
/// - If failed to read the config
/// - If failed to load the genesis block
/// - If failed to build a genesis network
pub fn read_config_and_genesis<P: AsRef<Path>>(
    path: Option<P>,
    submit_genesis: bool,
) -> Result<(Config, Option<GenesisNetwork>)> {
    use iroha_config::parameters::actual::Genesis;

    let config = Config::load(path, CliContext { submit_genesis })
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

    Ok((config, genesis))
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
                cfg.telemetry.dev.out_file.set("../logs/telemetry".into());
                toml::Value::try_from(cfg)?
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

            let (config, genesis) = read_config_and_genesis(Some(config_path), true)?;

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
                    .expect("dev telemetry should be set")
                    .out_file
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
                toml::Value::try_from(cfg)?
            };

            let dir = tempfile::tempdir()?;
            std::fs::write(dir.path().join("config.toml"), toml::to_string(&config)?)?;
            std::fs::write(dir.path().join("genesis.json"), json5::to_string(&genesis)?)?;
            std::fs::write(dir.path().join("executor.wasm"), "")?;
            let config_path = dir.path().join("config.toml");

            // When & Then

            let report = read_config_and_genesis(Some(config_path), false).unwrap_err();

            assert_contains!(
                format!("{report:#}"),
                "The network consists from this one peer only"
            );

            Ok(())
        }
    }
}
