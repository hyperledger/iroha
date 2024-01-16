//! Common primitives for a CLI instance of Iroha. If you're
//! customising it for deployment, use this crate as a reference to
//! add more complex behaviour, TUI, GUI, monitoring, etc.
//!
//! `Iroha` is the main instance of the peer program. `Arguments`
//! should be constructed externally: (see `main.rs`).
#[cfg(debug_assertions)]
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use color_eyre::eyre::{eyre, Result, WrapErr};
use iroha_config::{
    base::proxy::{LoadFromDisk, LoadFromEnv, Override},
    iroha::{Configuration, ConfigurationProxy},
    path::Path as ConfigPath,
};
use iroha_core::{
    block_sync::{BlockSynchronizer, BlockSynchronizerHandle},
    gossiper::{TransactionGossiper, TransactionGossiperHandle},
    handler::ThreadHandler,
    kura::Kura,
    prelude::{World, WorldStateView},
    queue::Queue,
    smartcontracts::isi::Registrable as _,
    snapshot::{try_read_snapshot, SnapshotMaker, SnapshotMakerHandle},
    sumeragi::{SumeragiHandle, SumeragiStartArgs},
    tx::PeerId,
    IrohaNetwork,
};
use iroha_data_model::prelude::*;
use iroha_genesis::GenesisNetwork;
use tokio::{
    signal,
    sync::{broadcast, mpsc, Notify},
    task,
};
use torii::Torii;

mod event;
pub mod samples;
mod stream;
pub mod style;
pub mod torii;

/// Arguments for Iroha2.  Configuration for arguments is parsed from
/// environment variables and then the appropriate object is
/// constructed.
#[derive(Debug)]
pub struct Arguments {
    /// Set this flag on the peer that should submit genesis on the network initial start.
    pub submit_genesis: bool,
    /// Set custom genesis file path. `None` if `submit_genesis` set to `false`.
    pub genesis_path: Option<ConfigPath>,
    /// Set custom config file path.
    pub config_path: ConfigPath,
}

/// Default configuration path
static CONFIGURATION_PATH: once_cell::sync::Lazy<&'static std::path::Path> =
    once_cell::sync::Lazy::new(|| std::path::Path::new("config"));

/// Default genesis path
static GENESIS_PATH: once_cell::sync::Lazy<&'static std::path::Path> =
    once_cell::sync::Lazy::new(|| std::path::Path::new("genesis"));

impl Default for Arguments {
    fn default() -> Self {
        Self {
            submit_genesis: false,
            genesis_path: Some(ConfigPath::default(&GENESIS_PATH)),
            config_path: ConfigPath::default(&CONFIGURATION_PATH),
        }
    }
}

/// Iroha is an
/// [Orchestrator](https://en.wikipedia.org/wiki/Orchestration_%28computing%29)
/// of the system. It configures, coordinates and manages transactions
/// and queries processing, work of consensus and storage.
///
/// # Usage
/// Construct and then `start` or `start_as_task`. If you experience
/// an immediate shutdown after constructing Iroha, then you probably
/// forgot this step.
#[must_use = "run `.start().await?` to not immediately stop Iroha"]
pub struct Iroha {
    /// Queue of transactions
    pub queue: Arc<Queue>,
    /// Sumeragi consensus
    pub sumeragi: SumeragiHandle,
    /// Kura — block storage
    pub kura: Arc<Kura>,
    /// Torii web server
    pub torii: Option<Torii>,
    /// Snapshot service,
    pub snapshot_maker: SnapshotMakerHandle,
    /// Thread handlers
    thread_handlers: Vec<ThreadHandler>,
    /// A boolean value indicating whether or not the peers will recieve data from the network. Used in
    /// sumeragi testing.
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
                _ = self.shutdown_notify.notified() => {
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

    /// Create Iroha with specified broker, config, and genesis.
    ///
    /// # Errors
    /// - Reading telemetry configs
    /// - telemetry setup
    /// - Initialization of [`Sumeragi`]
    #[allow(clippy::too_many_lines)]
    #[iroha_logger::log(name = "init", skip_all)] // This is actually easier to understand as a linear sequence of init statements.
    pub async fn with_genesis(
        genesis: Option<GenesisNetwork>,
        config: Configuration,
        telemetry: Option<iroha_logger::Telemetries>,
    ) -> Result<Self> {
        let listen_addr = config.torii.p2p_addr.clone();
        let network = IrohaNetwork::start(listen_addr, config.sumeragi.key_pair.clone())
            .await
            .wrap_err("Unable to start P2P-network")?;

        let (events_sender, _) = broadcast::channel(10000);
        let world = World::with(
            [genesis_domain(&config)],
            config.sumeragi.trusted_peers.peers.clone(),
        );

        let kura = Kura::new(
            config.kura.init_mode,
            std::path::Path::new(&config.kura.block_store_path),
            config.kura.debug_output_new_blocks,
        )?;

        let notify_shutdown = Arc::new(Notify::new());
        let block_count = kura.init()?;
        let wsv = try_read_snapshot(&config.snapshot.dir_path, &kura, block_count).map_or_else(
            |error| {
                iroha_logger::warn!(%error, "Failed to load wsv from snapshot, creating empty wsv");
                WorldStateView::from_configuration(config.wsv, world, Arc::clone(&kura))
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
        if Self::start_telemetry(telemetry, &config).await? {
            iroha_logger::info!("Telemetry started")
        } else {
            iroha_logger::warn!("Telemetry not started")
        }

        let kura_thread_handler = Kura::start(Arc::clone(&kura));

        let start_args = SumeragiStartArgs {
            configuration: config.sumeragi.clone(),
            events_sender: events_sender.clone(),
            wsv,
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

        let torii = Torii::from_configuration(
            config.clone(),
            Arc::clone(&queue),
            events_sender,
            Arc::clone(&notify_shutdown),
            sumeragi.clone(),
            Arc::clone(&kura),
        );

        Self::start_listening_signal(Arc::clone(&notify_shutdown))?;

        Self::prepare_panic_hook(notify_shutdown);

        let torii = Some(torii);
        Ok(Self {
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
        telemetry: Option<(
            iroha_logger::SubstrateTelemetry,
            iroha_logger::FutureTelemetry,
        )>,
        config: &Configuration,
    ) -> Result<bool> {
        #[allow(unused)]
        if let Some((substrate_telemetry, telemetry_future)) = telemetry {
            #[cfg(feature = "dev-telemetry")]
            {
                iroha_telemetry::dev::start(&config.telemetry, telemetry_future)
                    .await
                    .wrap_err("Failed to setup telemetry for futures")?;
            }
            iroha_telemetry::ws::start(&config.telemetry, substrate_telemetry)
                .await
                .wrap_err("Failed to setup telemetry for websocket communication")
        } else {
            Ok(false)
        }
    }

    #[cfg(not(feature = "telemetry"))]
    async fn start_telemetry(
        _telemetry: Option<(
            iroha_logger::SubstrateTelemetry,
            iroha_logger::FutureTelemetry,
        )>,
        _config: &Configuration,
    ) -> Result<bool> {
        Ok(false)
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
}

fn genesis_account(public_key: iroha_crypto::PublicKey) -> Account {
    Account::new(iroha_genesis::GENESIS_ACCOUNT_ID.clone(), [public_key])
        .build(&iroha_genesis::GENESIS_ACCOUNT_ID)
}

fn genesis_domain(configuration: &Configuration) -> Domain {
    let account_public_key = &configuration.genesis.account_public_key;

    let mut domain = Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone())
        .build(&iroha_genesis::GENESIS_ACCOUNT_ID);

    domain.accounts.insert(
        iroha_genesis::GENESIS_ACCOUNT_ID.clone(),
        genesis_account(account_public_key.clone()),
    );

    domain
}

/// Combine configuration proxies from several locations, preferring `ENV` vars over config file
///
/// # Errors
/// - if config fails to build
pub fn combine_configs(args: &Arguments) -> color_eyre::eyre::Result<Configuration> {
    args.config_path
        .first_existing_path()
        .map_or_else(
            || {
                eprintln!("Configuration file not found. Using environment variables as fallback.");
                ConfigurationProxy::default()
            },
            |path| {
                let path_proxy = ConfigurationProxy::from_path(&path.as_path());
                // Override the default to ensure that the variables
                // not specified in the config file don't have to be
                // explicitly specified in the env.
                ConfigurationProxy::default().override_with(path_proxy)
            },
        )
        .override_with(
            ConfigurationProxy::from_std_env()
                .wrap_err("Failed to build configuration from env")?,
        )
        .build()
        .map_err(Into::into)
}

#[cfg(not(feature = "test-network"))]
#[cfg(test)]
mod tests {
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
