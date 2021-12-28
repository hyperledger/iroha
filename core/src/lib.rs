//! Iroha - A simple, enterprise-grade decentralized ledger.

pub mod block;
pub mod block_sync;
pub mod config;
pub mod event;
pub mod genesis;
mod init;
pub mod kura;
pub mod modules;
pub mod queue;
pub mod samples;
pub mod smartcontracts;
pub mod stream;
pub mod sumeragi;
pub mod torii;
pub mod tx;
pub mod wsv;

use std::{path::PathBuf, sync::Arc, time::Duration};

use eyre::{eyre, Result, WrapErr};
use genesis::GenesisNetworkTrait;
use iroha_actor::{broker::*, prelude::*};
use iroha_data_model::prelude::*;
use iroha_logger::{FutureTelemetry, SubstrateTelemetry};
use parity_scale_codec::{Decode, Encode};
use smartcontracts::permissions::{IsInstructionAllowedBoxed, IsQueryAllowedBoxed};
use tokio::{sync::broadcast, task::JoinHandle};

use crate::{
    block_sync::{
        message::VersionedMessage as BlockSyncMessage, BlockSynchronizer, BlockSynchronizerTrait,
    },
    config::Configuration,
    genesis::GenesisNetwork,
    kura::{Kura, KuraTrait},
    prelude::*,
    queue::Queue,
    sumeragi::{message::VersionedMessage as SumeragiMessage, Sumeragi, SumeragiTrait},
    torii::Torii,
    wsv::WorldTrait,
};

/// The interval at which sumeragi checks if there are tx in the `queue`.
pub const TX_RETRIEVAL_INTERVAL: Duration = Duration::from_millis(100);

/// Specialized type of Iroha Network
pub type IrohaNetwork = iroha_p2p::Network<NetworkMessage>;

/// The network message
#[derive(Clone, Debug, Encode, Decode, iroha_actor::Message)]
pub enum NetworkMessage {
    /// Blockchain message
    SumeragiMessage(Box<SumeragiMessage>),
    /// Block sync message
    BlockSync(Box<BlockSyncMessage>),
    /// Health check message
    Health,
}

/// Iroha is an [Orchestrator](https://en.wikipedia.org/wiki/Orchestration_%28computing%29) of the
/// system. It configures, coordinates and manages transactions and queries processing, work of consensus and storage.
pub struct Iroha<
    W = World,
    G = GenesisNetwork,
    K = Kura<W>,
    S = Sumeragi<G, K, W>,
    B = BlockSynchronizer<S, W>,
> where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    K: KuraTrait<World = W>,
    S: SumeragiTrait<GenesisNetwork = G, Kura = K, World = W>,
    B: BlockSynchronizerTrait<Sumeragi = S, World = W>,
{
    /// World state view
    pub wsv: Arc<WorldStateView<W>>,
    /// Queue of transactions
    pub queue: Arc<Queue>,
    /// Sumeragi consensus
    pub sumeragi: AlwaysAddr<S>,
    /// Kura - block storage
    pub kura: AlwaysAddr<K>,
    /// Block synchronization actor
    pub block_sync: AlwaysAddr<B>,
    /// Torii web server
    pub torii: Option<Torii<W>>,
}

impl<W, G, S, K, B> Iroha<W, G, K, S, B>
where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    K: KuraTrait<World = W>,
    S: SumeragiTrait<GenesisNetwork = G, Kura = K, World = W>,
    B: BlockSynchronizerTrait<Sumeragi = S, World = W>,
{
    /// To make `Iroha` peer work all actors should be started first.
    /// After that moment it you can start it with listening to torii events.
    ///
    /// # Errors
    /// Can fail if fails:
    /// - Reading genesis from disk
    /// - Reading telemetry configs and setuping telemetry
    /// - Initialization of sumeragi
    pub async fn new(
        args: &Arguments,
        instruction_validator: IsInstructionAllowedBoxed<K::World>,
        query_validator: IsQueryAllowedBoxed<K::World>,
    ) -> Result<Self> {
        let broker = Broker::new();
        Self::with_broker(args, instruction_validator, query_validator, broker).await
    }

    /// Create Iroha with specified broker.
    ///
    /// # Errors
    /// Can fail if fails:
    /// - Reading genesis from disk
    /// - Reading telemetry configs and setuping telemetry
    /// - Initialization of sumeragi
    pub async fn with_broker(
        args: &Arguments,
        instruction_validator: IsInstructionAllowedBoxed<K::World>,
        query_validator: IsQueryAllowedBoxed<K::World>,
        broker: Broker,
    ) -> Result<Self> {
        let mut config = Configuration::from_path(&args.config_path)?;
        config.load_environment()?;
        Self::with_broker_and_config(args, config, instruction_validator, query_validator, broker)
            .await
    }

    /// Creates Iroha with specified broker and custom config that overrides `args`
    ///
    /// # Errors
    /// Can fail if fails:
    /// - Reading genesis from disk
    /// - Reading telemetry configs and setuping telemetry
    /// - Initialization of sumeragi
    pub async fn with_broker_and_config(
        args: &Arguments,
        config: Configuration,
        instruction_validator: IsInstructionAllowedBoxed<K::World>,
        query_validator: IsQueryAllowedBoxed<K::World>,
        broker: Broker,
    ) -> Result<Self> {
        let genesis = G::from_configuration(
            args.submit_genesis,
            crate::genesis::RawGenesisBlock::from_path(&args.genesis_path)?,
            &config.genesis,
            config.torii.max_instruction_number,
        )
        .wrap_err("Failed to initialize genesis.")?;

        Self::with_genesis(
            genesis,
            config,
            instruction_validator,
            query_validator,
            broker,
        )
        .await
    }

    /// Create Iroha with specified broker, config, and genesis.
    ///
    /// # Errors
    /// Can fail if fails:
    /// - Reading telemetry configs and setuping telemetry
    /// - Initialization of sumeragi
    #[allow(clippy::non_ascii_literal)]
    pub async fn with_genesis(
        genesis: Option<G>,
        config: Configuration,
        instruction_validator: IsInstructionAllowedBoxed<K::World>,
        query_validator: IsQueryAllowedBoxed<K::World>,
        broker: Broker,
    ) -> Result<Self> {
        // TODO: use channel for prometheus/telemetry endpoint
        #[allow(unused)]
        let telemetry = iroha_logger::init(&config.logger)?;
        iroha_logger::info!("Hyperledgerいろは2にようこそ！");

        let listen_addr = config.torii.p2p_addr.clone();
        iroha_logger::info!(%listen_addr, "Starting peer");
        #[allow(clippy::expect_used)]
        let network = IrohaNetwork::new(
            broker.clone(),
            listen_addr,
            config.public_key.clone(),
            config.network.mailbox,
        )
        .await
        .wrap_err("Unable to start P2P-network")?;
        let network_addr = network.start().await;

        let (events_sender, _) = broadcast::channel(100);
        let wsv = Arc::new(WorldStateView::with_events(
            Some(events_sender.clone()),
            config.wsv,
            W::with(
                init::domains(&config).wrap_err("Failed to get initial domains")?,
                config.sumeragi.trusted_peers.peers.clone(),
            ),
        ));
        let queue = Arc::new(Queue::from_configuration(&config.queue));

        let telemetry_started = Self::start_telemetry(telemetry, &config).await?;
        let query_validator = Arc::new(query_validator);
        let kura = K::from_configuration(&config.kura, Arc::clone(&wsv), broker.clone())
            .await?
            .preinit();
        let sumeragi: AlwaysAddr<_> = S::from_configuration(
            &config.sumeragi,
            events_sender.clone(),
            Arc::clone(&wsv),
            instruction_validator,
            Arc::clone(&query_validator),
            telemetry_started,
            genesis,
            Arc::clone(&queue),
            broker.clone(),
            kura.address.clone().expect_running().clone(),
            network_addr.clone(),
        )
        .wrap_err("Failed to initialize Sumeragi.")?
        .start()
        .await
        .expect_running();
        let kura = kura.start().await.expect_running();
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
            query_validator,
            events_sender,
            network_addr.clone(),
        );
        let torii = Some(torii);
        Ok(Self {
            wsv,
            queue,
            sumeragi,
            kura,
            block_sync,
            torii,
        })
    }

    /// To make `Iroha` peer work it should be started first. After
    /// that moment it will listen for incoming requests and messages.
    ///
    /// # Errors
    /// Can fail if initing kura fails
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
    /// # Errors
    /// Can fail if initing kura fails
    pub fn start_as_task(&mut self) -> Result<JoinHandle<eyre::Result<()>>> {
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
        telemetry: Option<(SubstrateTelemetry, FutureTelemetry)>,
        config: &Configuration,
    ) -> Result<bool> {
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
        _telemetry: Option<(SubstrateTelemetry, FutureTelemetry)>,
        _config: &Configuration,
    ) -> Result<bool> {
        Ok(false)
    }
}

/// Allow to check if an item is included in a blockchain.
pub trait IsInBlockchain {
    /// Checks if this item has already been committed or rejected.
    fn is_in_blockchain<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> bool;
}

const CONFIGURATION_PATH: &str = "config.json";
const GENESIS_PATH: &str = "genesis.json";

/// Arguments for Iroha2 - usually parsed from cli.
#[derive(Debug)]
pub struct Arguments {
    /// Set this flag on the peer that should submit genesis on the network initial start.
    pub submit_genesis: bool,
    /// Set custom genesis file path.
    pub genesis_path: PathBuf,
    /// Set custom config file path.
    pub config_path: PathBuf,
}

impl Default for Arguments {
    fn default() -> Self {
        Self {
            submit_genesis: false,
            genesis_path: GENESIS_PATH.into(),
            config_path: CONFIGURATION_PATH.into(),
        }
    }
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.

    #[doc(inline)]
    pub use iroha_crypto::{Hash, KeyPair, PrivateKey, PublicKey, Signature};

    #[doc(inline)]
    pub use crate::{
        block::{
            CommittedBlock, PendingBlock, ValidBlock, VersionedCommittedBlock, VersionedValidBlock,
        },
        smartcontracts::permissions::AllowAll,
        smartcontracts::ValidQuery,
        tx::{
            AcceptedTransaction, ValidTransaction, VersionedAcceptedTransaction,
            VersionedValidTransaction,
        },
        wsv::{World, WorldStateView},
        IsInBlockchain,
    };
}
