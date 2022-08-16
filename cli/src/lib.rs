//! Common primitives for a CLI instance of Iroha. If you're
//! customising it for deployment, use this crate as a reference to
//! add more complex behaviour, TUI, GUI, monitoring, etc.
//!
//! `Iroha` is the main instance of the peer program. `Arguments`
//! should be constructed externally: (see `main.rs`).
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use std::{panic, path::PathBuf, sync::Arc};

use color_eyre::eyre::{eyre, Result, WrapErr};
use iroha_actor::{broker::*, prelude::*};
use iroha_config::iroha::Configuration;
use iroha_core::{
    block_sync::{BlockSynchronizer, BlockSynchronizerTrait},
    genesis::{GenesisNetwork, GenesisNetworkTrait, RawGenesisBlock},
    handler::ThreadHandler,
    kura::Kura,
    prelude::{World, WorldStateView},
    queue::Queue,
    smartcontracts::permissions::judge::{InstructionJudgeBoxed, QueryJudgeBoxed},
    sumeragi::{Sumeragi, SumeragiTrait},
    tx::{PeerId, TransactionValidator},
    IrohaNetwork,
};
use iroha_data_model::prelude::*;
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

/// Arguments for Iroha2 - usually parsed from cli.
#[derive(Debug)]
pub struct Arguments {
    /// Set this flag on the peer that should submit genesis on the network initial start.
    pub submit_genesis: bool,
    /// Set custom genesis file path. `None` if `submit_genesis` set to `false`.
    pub genesis_path: Option<PathBuf>,
    /// Set custom config file path.
    pub config_path: PathBuf,
}

const CONFIGURATION_PATH: &str = "config.json";
const GENESIS_PATH: &str = "genesis.json";
const SUBMIT_GENESIS: bool = false;

impl Default for Arguments {
    fn default() -> Self {
        Self {
            submit_genesis: SUBMIT_GENESIS,
            genesis_path: Some(GENESIS_PATH.into()),
            config_path: CONFIGURATION_PATH.into(),
        }
    }
}

/// Iroha is an [Orchestrator](https://en.wikipedia.org/wiki/Orchestration_%28computing%29) of the
/// system. It configures, coordinates and manages transactions and queries processing, work of consensus and storage.
pub struct Iroha<G = GenesisNetwork, S = Sumeragi<G>, B = BlockSynchronizer<S>>
where
    G: GenesisNetworkTrait,
    S: SumeragiTrait<GenesisNetwork = G>,
    B: BlockSynchronizerTrait<Sumeragi = S>,
{
    /// World state view
    pub wsv: Arc<WorldStateView>,
    /// Queue of transactions
    pub queue: Arc<Queue>,
    /// Sumeragi consensus
    pub sumeragi: AlwaysAddr<S>,
    /// Kura - block storage
    pub kura: Arc<Kura>,
    /// Block synchronization actor
    pub block_sync: AlwaysAddr<B>,
    /// Torii web server
    pub torii: Option<Torii>,
    /// Thread handlers
    thread_handlers: Vec<ThreadHandler>,
}

impl<G, S, B> Drop for Iroha<G, S, B>
where
    G: GenesisNetworkTrait,
    S: SumeragiTrait<GenesisNetwork = G>,
    B: BlockSynchronizerTrait<Sumeragi = S>,
{
    fn drop(&mut self) {
        // Drop thread handles first
        let _thread_handles = core::mem::take(&mut self.thread_handlers);
    }
}

impl<G, S, B> Iroha<G, S, B>
where
    G: GenesisNetworkTrait,
    S: SumeragiTrait<GenesisNetwork = G>,
    B: BlockSynchronizerTrait<Sumeragi = S>,
{
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
    pub async fn new(
        args: &Arguments,
        instruction_judge: InstructionJudgeBoxed,
        query_judge: QueryJudgeBoxed,
    ) -> Result<Self> {
        let broker = Broker::new();
        let mut config = match Configuration::from_path(&args.config_path) {
            Ok(config) => config,
            Err(_) => Configuration::default(),
        };
        config.load_environment()?;

        let telemetry = iroha_logger::init(&config.logger)?;
        iroha_logger::info!("Hyperledgerいろは2にようこそ！");
        iroha_logger::info!("(translation) Welcome to Hyperledger Iroha 2!");

        let genesis = if let Some(genesis_path) = &args.genesis_path {
            G::from_configuration(
                args.submit_genesis,
                RawGenesisBlock::from_path(genesis_path)?,
                Some(&config.genesis),
                &config.sumeragi.transaction_limits,
            )
            .wrap_err("Failed to initialize genesis.")?
        } else {
            None
        };

        Self::with_genesis(
            genesis,
            config,
            instruction_judge,
            query_judge,
            broker,
            telemetry,
        )
        .await
    }

    fn prepare_panic_hook(notify_shutdown: Arc<Notify>) {
        let hook = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            hook(info);

            // What clippy suggests is much less readable in this case
            #[allow(clippy::option_if_let_else)]
            let panic_message = if let Some(message) = info.payload().downcast_ref::<&str>() {
                message
            } else if let Some(message) = info.payload().downcast_ref::<String>() {
                message
            } else {
                "unspecified"
            };

            let location = match info.location() {
                Some(location) => format!("{}:{}", location.file(), location.line()),
                None => "unspecified".to_owned(),
            };

            iroha_logger::error!(%panic_message, %location, "A panic occured, shutting down");

            notify_shutdown.notify_one();
        }));
    }

    /// Create Iroha with specified broker, config, and genesis.
    ///
    /// # Errors
    /// - Reading telemetry configs
    /// - telemetry setup
    /// - Initialization of [`Sumeragi`]
    pub async fn with_genesis(
        genesis: Option<G>,
        config: Configuration,
        instruction_judge: InstructionJudgeBoxed,
        query_judge: QueryJudgeBoxed,
        broker: Broker,
        telemetry: Option<iroha_logger::Telemetries>,
    ) -> Result<Self> {
        if !config.disable_panic_terminal_colors {
            if let Err(e) = color_eyre::install() {
                let error_message = format!("{e:#}");
                iroha_logger::error!(error = %error_message, "Tried to install eyre_hook twice",);
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

        let (events_sender, _) = broadcast::channel(100);
        let world = World::with(
            domains(&config),
            config.sumeragi.trusted_peers.peers.clone(),
        );
        let wsv = Arc::new(WorldStateView::from_configuration(
            config.wsv,
            world,
            events_sender.clone(),
        ));

        let query_judge = Arc::from(query_judge);

        let transaction_validator = TransactionValidator::new(
            config.sumeragi.transaction_limits,
            Arc::from(instruction_judge),
            Arc::clone(&query_judge),
            Arc::clone(&wsv),
        );

        // Validate every transaction in genesis block
        if let Some(ref genesis) = genesis {
            transaction_validator
                .validate_every(genesis.iter().cloned())
                .wrap_err("Transaction validation failed in genesis block")?;
        }

        let notify_shutdown = Arc::new(Notify::new());

        let queue = Arc::new(Queue::from_configuration(&config.queue, Arc::clone(&wsv)));
        let telemetry_started = Self::start_telemetry(telemetry, &config).await?;
        let kura = Kura::from_configuration(&config.kura, Arc::clone(&wsv), broker.clone())?;

        let kura_thread_handler = Kura::start(Arc::clone(&kura));

        let sumeragi: AlwaysAddr<_> = S::from_configuration(
            &config.sumeragi,
            events_sender.clone(),
            Arc::clone(&wsv),
            transaction_validator,
            telemetry_started,
            genesis,
            Arc::clone(&queue),
            broker.clone(),
            Arc::clone(&kura),
            network_addr.clone(),
        )
        .wrap_err("Failed to initialize Sumeragi.")?
        .start()
        .await
        .expect_running();

        kura.async_init_all_important().await;
        let block_sync = B::from_configuration(
            &config.block_sync,
            Arc::clone(&wsv),
            sumeragi.clone(),
            PeerId::new(&config.torii.p2p_addr, &config.public_key),
            broker.clone(),
        )
        .start()
        .await
        .expect_running();

        let torii = Torii::from_configuration(
            config.clone(),
            Arc::clone(&wsv),
            Arc::clone(&queue),
            query_judge,
            events_sender,
            network_addr.clone(),
            Arc::clone(&notify_shutdown),
        );

        Self::start_listening_signal(Arc::clone(&notify_shutdown))?;

        Self::prepare_panic_hook(notify_shutdown);

        let torii = Some(torii);
        Ok(Self {
            wsv,
            queue,
            sumeragi,
            kura,
            block_sync,
            torii,
            thread_handlers: vec![kura_thread_handler],
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
            .ok_or_else(|| eyre!("Seems like peer was already started"))?
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
            .ok_or_else(|| eyre!("Seems like peer was already started"))?;
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
                .wrap_err("Failed to setup telemetry")
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

    // Which raises the question: does it make sense to enable `nursery` lints?
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
                _ = sigint.recv() => {},
                _ = sigterm.recv() => {},
            }

            notify_shutdown.notify_waiters();
        });

        Ok(handle)
    }
}

/// Returns the `domain_name: domain` mapping, for initial domains.
///
/// # Errors
/// - Genesis account public key not specified.
fn domains(configuration: &Configuration) -> [Domain; 1] {
    let key = configuration.genesis.account_public_key.clone();
    [Domain::from(GenesisDomain::new(key))]
}

#[cfg(test)]
mod tests {
    use std::{panic, thread};

    use serial_test::serial;

    use super::*;

    #[allow(clippy::panic)]
    #[tokio::test]
    #[serial]
    async fn iroha_should_notify_on_panic() {
        let notify = Arc::new(Notify::new());
        let hook = panic::take_hook();
        <crate::Iroha>::prepare_panic_hook(Arc::clone(&notify));
        let _res = thread::spawn(move || {
            panic!("Test panic");
        })
        .join();
        notify.notified().await;
        panic::set_hook(hook);
    }
}
