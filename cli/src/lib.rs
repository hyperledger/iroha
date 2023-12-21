//! Common primitives for a CLI instance of Iroha. If you're
//! customising it for deployment, use this crate as a reference to
//! add more complex behaviour, TUI, GUI, monitoring, etc.
//!
//! `Iroha` is the main instance of the peer program. `Arguments`
//! should be constructed externally: (see `main.rs`).
#[cfg(debug_assertions)]
use core::sync::atomic::{AtomicBool, Ordering};
use std::{path::PathBuf, sync::Arc};

use color_eyre::eyre::{eyre, Result, WrapErr};
use iroha_config::{
    base::proxy::{LoadFromDisk, LoadFromEnv, Override},
    genesis::ParsedConfiguration as ParsedGenesisConfiguration,
    iroha::{Configuration, ConfigurationProxy},
    path::Path,
    telemetry::Configuration as TelemetryConfiguration,
};
use iroha_core::{
    block_sync::{BlockSynchronizer, BlockSynchronizerHandle},
    gossiper::{TransactionGossiper, TransactionGossiperHandle},
    handler::ThreadHandler,
    kiso::KisoHandle,
    kura::Kura,
    prelude::{World, WorldStateView},
    query::store::LiveQueryStore,
    queue::Queue,
    smartcontracts::isi::Registrable as _,
    snapshot::{try_read_snapshot, SnapshotMaker, SnapshotMakerHandle},
    sumeragi::{SumeragiHandle, SumeragiStartArgs},
    tx::PeerId,
    IrohaNetwork,
};
use iroha_data_model::prelude::*;
use iroha_genesis::GenesisNetwork;
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
    /// Snapshot service
    pub snapshot_maker: SnapshotMakerHandle,
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
            SumeragiPacket(data) => {
                self.sumeragi.incoming_message(*data);
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
        config: Configuration,
        genesis: Option<GenesisNetwork>,
        logger: LoggerHandle,
    ) -> Result<Self> {
        let listen_addr = config.torii.p2p_addr.clone();
        let network = IrohaNetwork::start(listen_addr, config.sumeragi.key_pair.clone())
            .await
            .wrap_err("Unable to start P2P-network")?;

        let (events_sender, _) = broadcast::channel(10000);
        let world = World::with(
            [genesis_domain(config.genesis.public_key.clone())],
            config.sumeragi.trusted_peers.peers.clone(),
        );

        let kura = Kura::new(&config.kura)?;
        let live_query_store_handle =
            LiveQueryStore::from_configuration(config.live_query_store).start();

        let block_count = kura.init()?;
        let wsv = try_read_snapshot(
            &config.snapshot.dir_path,
            &kura,
            live_query_store_handle.clone(),
            block_count,
        )
        .map_or_else(
            |error| {
                iroha_logger::warn!(%error, "Failed to load wsv from snapshot, creating empty wsv");
                WorldStateView::from_configuration(
                    *config.wsv,
                    world,
                    Arc::clone(&kura),
                    live_query_store_handle.clone(),
                )
            },
            |wsv| {
                iroha_logger::info!(
                    at_height = wsv.height(),
                    "Successfully loaded wsv from snapshot"
                );
                wsv
            },
        );

        let queue = Arc::new(Queue::from_configuration(&config.queue));
        match Self::start_telemetry(&logger, &config.telemetry).await? {
            TelemetryStartStatus::Started => iroha_logger::info!("Telemetry started"),
            TelemetryStartStatus::NotStarted => iroha_logger::warn!("Telemetry not started"),
        };

        let kura_thread_handler = Kura::start(Arc::clone(&kura));

        let sumeragi = SumeragiHandle::start(SumeragiStartArgs {
            configuration: &config.sumeragi,
            events_sender: events_sender.clone(),
            wsv,
            queue: Arc::clone(&queue),
            kura: Arc::clone(&kura),
            network: network.clone(),
            genesis_network: genesis,
            block_count,
        });

        let block_sync = BlockSynchronizer::from_configuration(
            &config.block_sync,
            sumeragi.clone(),
            Arc::clone(&kura),
            PeerId::new(&config.torii.p2p_addr, &config.public_key),
            network.clone(),
        )
        .start();

        let gossiper = TransactionGossiper::from_configuration(
            &config.sumeragi,
            network.clone(),
            Arc::clone(&queue),
            sumeragi.clone(),
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

        let snapshot_maker =
            SnapshotMaker::from_configuration(&config.snapshot, sumeragi.clone()).start();

        let kiso = KisoHandle::new(config.clone());

        let torii = Torii::new(
            kiso.clone(),
            &config.torii,
            Arc::clone(&queue),
            events_sender,
            Arc::clone(&notify_shutdown),
            sumeragi.clone(),
            live_query_store_handle,
            Arc::clone(&kura),
        );

        Self::spawn_configuration_updates_broadcasting(kiso.clone(), logger.clone());

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
        config: &TelemetryConfiguration,
    ) -> Result<TelemetryStartStatus> {
        #[allow(unused)]
        let (config_for_regular, config_for_dev) = config.parse();

        #[cfg(feature = "dev-telemetry")]
        {
            if let Some(config) = config_for_dev {
                let receiver = logger
                    .subscribe_on_telemetry(iroha_logger::telemetry::Channel::Future)
                    .await
                    .wrap_err("Failed to subscribe on telemetry")?;
                let _handle = iroha_telemetry::dev::start(config, receiver)
                    .await
                    .wrap_err("Failed to setup telemetry for futures")?;
            }
        }

        if let Some(config) = config_for_regular {
            let receiver = logger
                .subscribe_on_telemetry(iroha_logger::telemetry::Channel::Regular)
                .await
                .wrap_err("Failed to subscribe on telemetry")?;
            let _handle = iroha_telemetry::ws::start(config, receiver)
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
        _config: &TelemetryConfiguration,
    ) -> Result<TelemetryStartStatus> {
        Ok(TelemetryStartStatus::NotStarted)
    }

    #[allow(clippy::redundant_pub_crate)]
    fn start_listening_signal(notify_shutdown: Arc<Notify>) -> Result<task::JoinHandle<()>> {
        let (mut sigint, mut sigterm) = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .and_then(|sigint| {
                let sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;

                Ok((sigint, sigterm))
            })
            .wrap_err("Failed to start listening for OS signals")?;

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
    fn spawn_configuration_updates_broadcasting(
        kiso: KisoHandle,
        logger: LoggerHandle,
    ) -> task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut log_level_update = kiso
                .subscribe_on_log_level()
                .await
                // FIXME: don't like neither the message nor inability to throw Result to the outside
                .expect("Cannot proceed without working subscriptions");

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
    Account::new(iroha_genesis::GENESIS_ACCOUNT_ID.clone(), [public_key])
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

macro_rules! mutate_nested_option {
    ($obj:expr, self, $func:expr) => {
        $obj.as_mut().map($func)
    };
    ($obj:expr, $field:ident, $func:expr) => {
        $obj.$field.as_mut().map($func)
    };
    ($obj:expr, [$field:ident, $($rest:tt)+], $func:expr) => {
        $obj.$field.as_mut().map(|x| {
            mutate_nested_option!(x, [$($rest)+], $func)
        })
    };
    ($obj:tt, [$field:tt], $func:expr) => {
        mutate_nested_option!($obj, $field, $func)
    };

}

/// Reads configuration from the specified path and validates it.
///
/// # Errors
/// - If config fails to build
/// - If genesis config is invalid
pub fn read_config(
    path: &Path,
    submit_genesis: bool,
) -> Result<(Configuration, Option<GenesisNetwork>)> {
    let config = ConfigurationProxy::default();

    let config = if let Some(actual_config_path) = path
        .try_resolve()
        .wrap_err("Failed to resolve configuration file")?
    {
        let mut cfg = config.override_with(ConfigurationProxy::from_path(&*actual_config_path));
        let config_dir = actual_config_path
            .parent()
            .expect("If config file was read, than it should has a parent. It is a bug.");

        // careful here: `genesis.file` might be a path relative to the config file.
        // we need to resolve it before proceeding
        // TODO: move this logic into `iroha_config`
        let join_to_config_dir = |x: &mut PathBuf| {
            *x = config_dir.join(&x);
        };
        mutate_nested_option!(cfg, [genesis, file, self], join_to_config_dir);
        mutate_nested_option!(cfg, [snapshot, dir_path], join_to_config_dir);
        mutate_nested_option!(cfg, [kura, block_store_path], join_to_config_dir);
        mutate_nested_option!(cfg, [telemetry, file, self], join_to_config_dir);

        cfg
    } else {
        config
    };

    // it is not chained to the previous expressions so that config proxy from env is evaluated
    // after reading a file
    let config = config.override_with(
        ConfigurationProxy::from_std_env().wrap_err("Failed to build configuration from env")?,
    );

    let config = config
        .build()
        .wrap_err("Failed to finalize configuration")?;

    // TODO: move validation logic below to `iroha_config`

    if !submit_genesis && config.sumeragi.trusted_peers.peers.len() < 2 {
        return Err(eyre!("\
            The network consists from this one peer only (`sumeragi.trusted_peers` is less than 2). \
            Since `--submit-genesis` is not set, there is no way to receive the genesis block. \
            Either provide the genesis by setting `--submit-genesis` argument, `genesis.private_key`, \
            and `genesis.file` configuration parameters, or increase the number of trusted peers in \
            the network using `sumeragi.trusted_peers` configuration parameter.
        "));
    }

    let genesis = if let ParsedGenesisConfiguration::Full {
        key_pair,
        raw_block,
    } = config
        .genesis
        .clone()
        .parse(submit_genesis)
        .wrap_err("Invalid genesis configuration")?
    {
        Some(
            GenesisNetwork::new(raw_block, &key_pair)
                .wrap_err("Failed to construct the genesis")?,
        )
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
        use iroha_crypto::KeyPair;
        use iroha_genesis::{ExecutorMode, ExecutorPath};
        use iroha_primitives::addr::socket_addr;
        use path_absolutize::Absolutize as _;

        use super::*;

        fn config_factory() -> Result<ConfigurationProxy> {
            let mut base = ConfigurationProxy::default();

            let key_pair = KeyPair::generate()?;

            base.public_key = Some(key_pair.public_key().clone());
            base.private_key = Some(key_pair.private_key().clone());

            let torii = base.torii.as_mut().unwrap();
            torii.p2p_addr = Some(socket_addr!(127.0.0.1:1337));
            torii.api_url = Some(socket_addr!(127.0.0.1:1337));

            let genesis = base.genesis.as_mut().unwrap();
            genesis.private_key = Some(Some(key_pair.private_key().clone()));
            genesis.public_key = Some(key_pair.public_key().clone());

            Ok(base)
        }

        #[test]
        fn relative_file_paths_resolution() -> Result<()> {
            // Given

            let genesis = RawGenesisBlockBuilder::default()
                .executor(ExecutorMode::Path(ExecutorPath("./executor.wasm".into())))
                .build();

            let config = {
                let mut cfg = config_factory()?;
                cfg.genesis.as_mut().unwrap().file = Some(Some("./genesis/gen.json".into()));
                cfg.kura.as_mut().unwrap().block_store_path = Some("../storage".into());
                cfg.snapshot.as_mut().unwrap().dir_path = Some("../snapshots".into());
                cfg.telemetry.as_mut().unwrap().file = Some(Some("../logs/telemetry".into()));
                cfg
            };

            let dir = tempfile::tempdir()?;
            let genesis_path = dir.path().join("config/genesis/gen.json");
            let executor_path = dir.path().join("config/genesis/executor.wasm");
            let config_path = dir.path().join("config/config.json5");
            std::fs::create_dir(dir.path().join("config"))?;
            std::fs::create_dir(dir.path().join("config/genesis"))?;
            std::fs::write(config_path, serde_json::to_string(&config)?)?;
            std::fs::write(genesis_path, serde_json::to_string(&genesis)?)?;
            std::fs::write(executor_path, "")?;

            let config_path = Path::default(dir.path().join("config/config"));

            // When

            let (config, genesis) = read_config(&config_path, true)?;

            // Then

            // No need to check whether genesis.file is resolved - if not, genesis wouldn't be read
            assert!(genesis.is_some());

            assert_eq!(
                config.kura.block_store_path.absolutize()?,
                dir.path().join("storage")
            );
            assert_eq!(
                config.snapshot.dir_path.absolutize()?,
                dir.path().join("snapshots")
            );
            assert_eq!(
                config.telemetry.file.expect("Should be set").absolutize()?,
                dir.path().join("logs/telemetry")
            );

            Ok(())
        }

        #[test]
        fn fails_with_no_trusted_peers_and_submit_role() -> Result<()> {
            // Given

            let genesis = RawGenesisBlockBuilder::default()
                .executor(ExecutorMode::Path(ExecutorPath("./executor.wasm".into())))
                .build();

            let config = {
                let mut cfg = config_factory()?;
                cfg.genesis.as_mut().unwrap().file = Some(Some("./genesis.json".into()));
                cfg
            };

            let dir = tempfile::tempdir()?;
            std::fs::write(
                dir.path().join("config.json"),
                serde_json::to_string(&config)?,
            )?;
            std::fs::write(
                dir.path().join("genesis.json"),
                serde_json::to_string(&genesis)?,
            )?;
            std::fs::write(dir.path().join("executor.wasm"), "")?;
            let config_path = Path::user_provided(dir.path().join("config.json"))?;

            // When & Then

            let report = read_config(&config_path, false).unwrap_err();

            assert_eq!(
                format!("{report}"),
                "Only peer in network, yet required to receive genesis topology. This is a configuration error."
            );

            Ok(())
        }
    }
}
