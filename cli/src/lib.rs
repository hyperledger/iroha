//! Common primitives for a CLI instance of Iroha. If you're
//! customising it for deployment, use this crate as a reference to
//! add more complex behaviour, TUI, GUI, monitoring, etc.
//!
//! `Iroha` is the main instance of the peer program. `Arguments`
//! should be constructed externally: (see `main.rs`).
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use color_eyre::eyre::{eyre, Result, WrapErr};
use eyre::ContextCompat as _;
use iroha_actor::{broker::*, prelude::*};
use iroha_config::{
    base::proxy::{LoadFromDisk, LoadFromEnv, Override},
    iroha::{Configuration, ConfigurationProxy},
    path::Path as ConfigPath,
};
use iroha_core::{
    block_sync::BlockSynchronizer,
    handler::ThreadHandler,
    kura::Kura,
    prelude::{World, WorldStateView},
    queue::Queue,
    sumeragi::Sumeragi,
    tx::{PeerId, TransactionValidator},
    IrohaNetwork,
};
use iroha_data_model::prelude::*;
use iroha_genesis::{GenesisNetwork, GenesisNetworkTrait, RawGenesisBlock};
use iroha_p2p::network::NetworkBaseRelayOnlinePeers;
use tokio::{
    signal,
    sync::{broadcast, Notify},
    task,
};
use torii::Torii;

mod event;
pub mod samples;
mod stream;
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

/// Iroha is an [Orchestrator](https://en.wikipedia.org/wiki/Orchestration_%28computing%29) of the
/// system. It configures, coordinates and manages transactions and queries processing, work of consensus and storage.
pub struct Iroha {
    /// Queue of transactions
    pub queue: Arc<Queue>,
    /// Sumeragi consensus
    pub sumeragi: Arc<Sumeragi>,
    /// Kura — block storage
    pub kura: Arc<Kura>,
    /// Block synchronization actor
    pub block_sync: AlwaysAddr<BlockSynchronizer>,
    /// Torii web server
    pub torii: Option<Torii>,
    /// Thread handlers
    thread_handlers: Vec<ThreadHandler>,
    /// Relay that redirects messages from the network subsystem to core subsystems.
    _sumeragi_relay: AlwaysAddr<FromNetworkBaseRelay>, // TODO: figure out if truly unused.
    /// A boolean value indicating whether or not the peers will recieve data from the network. Used in
    /// sumeragi testing.
    #[cfg(debug_assertions)]
    pub freeze_status: Arc<AtomicBool>,
}

impl Drop for Iroha {
    fn drop(&mut self) {
        // Drop thread handles first
        let _thread_handles = core::mem::take(&mut self.thread_handlers);
    }
}

struct FromNetworkBaseRelay {
    sumeragi: Arc<Sumeragi>,
    broker: Broker,
    #[cfg(debug_assertions)]
    freeze_status: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl Actor for FromNetworkBaseRelay {
    async fn on_start(&mut self, ctx: &mut iroha_actor::prelude::Context<Self>) {
        // to start connections
        self.broker.subscribe::<NetworkBaseRelayOnlinePeers, _>(ctx);
        self.broker.subscribe::<iroha_core::NetworkMessage, _>(ctx);
    }
}

#[async_trait::async_trait]
impl Handler<NetworkBaseRelayOnlinePeers> for FromNetworkBaseRelay {
    type Result = ();

    async fn handle(&mut self, msg: NetworkBaseRelayOnlinePeers) {
        self.sumeragi.update_online_peers(msg.online_peers);
    }
}

#[async_trait::async_trait]
impl Handler<iroha_core::NetworkMessage> for FromNetworkBaseRelay {
    type Result = ();

    async fn handle(&mut self, msg: iroha_core::NetworkMessage) -> Self::Result {
        use iroha_core::NetworkMessage::*;

        #[cfg(debug_assertions)]
        if self.freeze_status.load(Ordering::SeqCst) {
            return;
        }

        match msg {
            SumeragiPacket(data) => {
                self.sumeragi.incoming_message(data.into_v1());
            }
            BlockSync(data) => self.broker.issue_send(data.into_v1()).await,
            Health => {}
        }
    }
}

impl Iroha {
    /// To make `Iroha` peer work all actors should be started first.
    /// After that moment it you can start it with listening to torii events.
    ///
    /// # Side effect
    /// - Prints welcome message in the log
    ///
    /// # Errors
    /// - Reading genesis from disk
    /// - Reading telemetry configs
    /// - telemetry setup
    /// - Initialization of [`Sumeragi`]
    #[allow(clippy::non_ascii_literal)]
    pub async fn new(args: &Arguments) -> Result<Self> {
        let mut config = args
            .config_path
            .first_existing_path()
            .map_or_else(
                || {
                    eprintln!(
                        "Configuration file not found. Using environment variables as fallback."
                    );
                    ConfigurationProxy::default()
                },
                |path| ConfigurationProxy::from_path(&path.as_path()),
            )
            .override_with(ConfigurationProxy::from_env())
            .build()?;

        if style::should_disable_color() {
            config.disable_panic_terminal_colors = true;
            // Remove terminal colors to comply with XDG
            // specifications, Rust's conventions as well as remove
            // escape codes from logs redirected from STDOUT. If you
            // need syntax highlighting, use JSON logging instead.
            config.logger.terminal_colors = false;
        }

        let telemetry = iroha_logger::init(&config.logger)?;
        iroha_logger::info!(
            git_commit_sha = env!("VERGEN_GIT_SHA"),
            "Hyperledgerいろは2にようこそ！(translation) Welcome to Hyperledger Iroha {}!",
            env!("CARGO_PKG_VERSION")
        );

        let genesis = if let Some(genesis_path) = &args.genesis_path {
            GenesisNetwork::from_configuration(
                args.submit_genesis,
                RawGenesisBlock::from_path(
                    genesis_path
                        .first_existing_path()
                        .wrap_err_with(|| {
                            format!("Genesis block file {genesis_path:?} doesn't exist")
                        })?
                        .as_ref(),
                )?,
                Some(&config.genesis),
                &config.sumeragi.transaction_limits,
            )
            .wrap_err("Failed to initialize genesis.")?
        } else {
            None
        };

        Self::with_genesis(genesis, config, Broker::new(), telemetry).await
    }

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
    #[allow(clippy::too_many_lines)] // This is actually easier to understand as a linear sequence of init statements.
    pub async fn with_genesis(
        genesis: Option<GenesisNetwork>,
        config: Configuration,
        broker: Broker,
        telemetry: Option<iroha_logger::Telemetries>,
    ) -> Result<Self> {
        if !config.disable_panic_terminal_colors {
            if let Err(e) = color_eyre::install() {
                let error_message = format!("{e:#}");
                iroha_logger::error!(error = %error_message, "Tried to `color_eyre::install()` twice",);
            }
        }
        let listen_addr = config.torii.p2p_addr.clone();
        iroha_logger::info!(%listen_addr, "Starting peer");
        let network = IrohaNetwork::new(
            broker.clone(),
            listen_addr,
            config.public_key.clone(),
            config.network.actor_channel_capacity,
        )
        .await
        .wrap_err("Unable to start P2P-network")?;
        let network_addr = network.start().await;

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
        let queue = Arc::new(Queue::from_configuration(&config.queue));
        let wsv = WorldStateView::from_configuration(
            config.wsv,
            world,
            Arc::clone(&queue),
            Arc::clone(&kura),
        );

        let transaction_validator = TransactionValidator::new(config.sumeragi.transaction_limits);

        // Validate every transaction in genesis block
        if let Some(ref genesis) = genesis {
            let wsv_clone = wsv.clone();

            transaction_validator
                .validate_every(genesis.iter().cloned(), &wsv_clone)
                .wrap_err("Transaction validation failed in genesis block")?;
        }

        let block_hashes = kura.init()?;

        let notify_shutdown = Arc::new(Notify::new());

        if Self::start_telemetry(telemetry, &config).await? {
            iroha_logger::info!("Telemetry started")
        } else {
            iroha_logger::warn!("Telemetry not started")
        }

        let kura_thread_handler = Kura::start(Arc::clone(&kura));

        let sumeragi = Arc::new(
            // TODO: No function needs 10 parameters. It should accept one struct.
            Sumeragi::new(
                &config.sumeragi,
                events_sender.clone(),
                wsv,
                transaction_validator,
                Arc::clone(&queue),
                broker.clone(),
                Arc::clone(&kura),
                network_addr.clone(),
            ),
        );

        let freeze_status = Arc::new(AtomicBool::new(false));

        let sumeragi_relay = FromNetworkBaseRelay {
            sumeragi: Arc::clone(&sumeragi),
            broker: broker.clone(),
            #[cfg(debug_assertions)]
            freeze_status: freeze_status.clone(),
        }
        .start()
        .await
        .expect_running();

        let sumeragi_thread_handler =
            Sumeragi::initialize_and_start_thread(Arc::clone(&sumeragi), genesis, &block_hashes);

        let block_sync = BlockSynchronizer::from_configuration(
            &config.block_sync,
            Arc::clone(&sumeragi),
            Arc::clone(&kura),
            PeerId::new(&config.torii.p2p_addr, &config.public_key),
            broker.clone(),
        )
        .start()
        .await
        .expect_running();

        let torii = Torii::from_configuration(
            config.clone(),
            Arc::clone(&queue),
            events_sender,
            Arc::clone(&notify_shutdown),
            Arc::clone(&sumeragi),
            Arc::clone(&kura),
        );

        Self::start_listening_signal(Arc::clone(&notify_shutdown))?;

        Self::prepare_panic_hook(notify_shutdown);

        let torii = Some(torii);
        Ok(Self {
            queue,
            sumeragi,
            kura,
            block_sync,
            torii,
            thread_handlers: vec![sumeragi_thread_handler, kura_thread_handler],
            _sumeragi_relay: sumeragi_relay,
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
    Account::new(AccountId::genesis(), [public_key]).build()
}

fn genesis_domain(configuration: &Configuration) -> Domain {
    let account_public_key = &configuration.genesis.account_public_key;
    let mut domain = Domain::new(DomainId::genesis()).build();

    domain.accounts.insert(
        <Account as Identifiable>::Id::genesis(),
        genesis_account(account_public_key.clone()),
    );

    domain
}

pub mod style {
    //! Style and colouration of Iroha CLI outputs.
    use owo_colors::{OwoColorize, Style};

    /// Styling information set at run-time for pretty-printing with colour
    #[derive(Clone, Copy, Debug)]
    pub struct Styling {
        /// Positive highlight
        pub positive: Style,
        /// Negative highlight. Usually error message.
        pub negative: Style,
        /// Neutral highlight
        pub highlight: Style,
        /// Minor message
        pub minor: Style,
    }

    impl Default for Styling {
        fn default() -> Self {
            Self {
                positive: Style::new().green().bold(),
                negative: Style::new().red().bold(),
                highlight: Style::new().bold(),
                minor: Style::new().green(),
            }
        }
    }

    /// Determine if message colourisation is to be enabled
    pub fn should_disable_color() -> bool {
        supports_color::on(supports_color::Stream::Stdout).is_none()
            || std::env::var("TERMINAL_COLORS")
                .map(|s| !s.as_str().parse().unwrap_or(true))
                .unwrap_or(false)
    }

    impl Styling {
        #[must_use]
        /// Constructor
        pub fn new() -> Self {
            if should_disable_color() {
                Self::no_color()
            } else {
                Self::default()
            }
        }

        fn no_color() -> Self {
            Self {
                positive: Style::new(),
                negative: Style::new(),
                highlight: Style::new(),
                minor: Style::new(),
            }
        }

        /// Produce documentation for argument group
        pub fn or(&self, arg_group: &[&str; 2]) -> String {
            format!(
                "`{}` (short `{}`)",
                arg_group[0].style(self.positive),
                arg_group[1].style(self.minor)
            )
        }

        /// Convenience method for ".json or .json5" pattern
        pub fn with_json_file_ext(&self, name: &str) -> String {
            let json = format!("{name}.json");
            let json5 = format!("{name}.json5");
            format!(
                "`{}` or `{}`",
                json.style(self.highlight),
                json5.style(self.highlight)
            )
        }
    }
}

#[cfg(not(feature = "test-network"))]
#[cfg(test)]
mod tests {
    use std::{iter::repeat, panic, thread};

    use futures::future::join_all;
    use serial_test::serial;

    use super::*;

    #[allow(clippy::panic, clippy::print_stdout)]
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
