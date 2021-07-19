//! Iroha - A simple, enterprise-grade decentralized ledger.

pub mod block;
pub mod block_sync;
pub mod config;
pub mod event;
pub mod genesis;
mod init;
pub mod kura;
pub mod maintenance;
mod merkle;
pub mod modules;
pub mod queue;
pub mod smartcontracts;
pub mod sumeragi;
#[cfg(feature = "telemetry")]
mod telemetry;
pub mod torii;
pub mod tx;
pub mod wsv;

use std::{convert::Infallible, sync::Arc, time::Duration};

use genesis::GenesisNetworkTrait;
use iroha_actor::{broker::*, prelude::*};
use iroha_data_model::prelude::*;
use iroha_error::{error, Result, WrapErr};
use smartcontracts::permissions::{IsInstructionAllowedBoxed, IsQueryAllowedBoxed};
use tokio::{sync::mpsc, task::JoinHandle};
use wsv::{World, WorldTrait};

use crate::{
    block::VersionedValidBlock,
    block_sync::{BlockSynchronizer, BlockSynchronizerTrait},
    config::Configuration,
    genesis::GenesisNetwork,
    kura::{Kura, KuraTrait},
    maintenance::System,
    prelude::*,
    queue::{Queue, QueueTrait},
    sumeragi::{Sumeragi, SumeragiTrait},
    torii::Torii,
};

/// The interval at which sumeragi checks if there are tx in the `queue`.
pub const TX_RETRIEVAL_INTERVAL: Duration = Duration::from_millis(100);

/// Iroha is an [Orchestrator](https://en.wikipedia.org/wiki/Orchestration_%28computing%29) of the
/// system. It configures, coordinates and manages transactions and queries processing, work of consensus and storage.
pub struct Iroha<
    W = World,
    G = GenesisNetwork,
    Q = Queue<W>,
    S = Sumeragi<Q, G, W>,
    K = Kura<W>,
    B = BlockSynchronizer<S, W>,
> where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    Q: QueueTrait<World = W>,
    S: SumeragiTrait<Queue = Q, GenesisNetwork = G, World = W>,
    K: KuraTrait<World = W>,
    B: BlockSynchronizerTrait<Sumeragi = S, World = W>,
{
    /// World state view
    pub wsv: Arc<WorldStateView<W>>,
    /// Queue of transactions
    pub queue: AlwaysAddr<Q>,
    /// Sumeragi consensus
    pub sumeragi: AlwaysAddr<S>,
    /// Kura - block storage
    pub kura: AlwaysAddr<K>,
    /// Block synchronization actor
    pub block_sync: AlwaysAddr<B>,
    /// Torii web server
    pub torii: Option<Torii<Q, S, W>>,
}

impl<W, G, Q, S, K, B> Iroha<W, G, Q, S, K, B>
where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    Q: QueueTrait<World = W>,
    S: SumeragiTrait<Queue = Q, GenesisNetwork = G, World = W>,
    K: KuraTrait<World = W>,
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
        config: &Configuration,
        instruction_validator: IsInstructionAllowedBoxed<K::World>,
        query_validator: IsQueryAllowedBoxed<K::World>,
    ) -> Result<Self> {
        let broker = Broker::new();
        Self::with_broker(config, instruction_validator, query_validator, broker).await
    }

    /// Creates Iroha with specified broker
    /// # Errors
    /// Can fail if fails:
    /// - Reading genesis from disk
    /// - Reading telemetry configs and setuping telemetry
    /// - Initialization of sumeragi
    pub async fn with_broker(
        config: &Configuration,
        instruction_validator: IsInstructionAllowedBoxed<K::World>,
        query_validator: IsQueryAllowedBoxed<K::World>,
        broker: Broker,
    ) -> Result<Self> {
        // TODO: use channel for prometheus/telemetry endpoint
        #[allow(unused)]
        let telemetry = iroha_logger::init(config.logger_configuration);

        //iroha_logger::info!(?config, "Loaded configuration");

        let (events_sender, events_receiver) = mpsc::channel(100);
        let wsv = Arc::new(WorldStateView::from_config(
            config.wsv_configuration,
            W::with(
                init::domains(config),
                config.sumeragi_configuration.trusted_peers.peers.clone(),
            ),
        ));
        let queue = Q::from_configuration(
            &config.queue_configuration,
            Arc::clone(&wsv),
            broker.clone(),
        )
        .start()
        .await
        .expect_running();

        let genesis_network = G::from_configuration(
            &config.genesis_configuration,
            config.torii_configuration.torii_max_instruction_number,
        )
        .wrap_err("Failed to initialize genesis.")?;

        #[cfg(feature = "telemetry")]
        if let Some(telemetry) = telemetry {
            drop(
                telemetry::start(&config.telemetry, telemetry)
                    .await
                    .wrap_err("Failed to setup telemetry")?,
            );
        }
        let query_validator = Arc::new(query_validator);
        let sumeragi: AlwaysAddr<_> = S::from_configuration(
            &config.sumeragi_configuration,
            events_sender,
            Arc::clone(&wsv),
            instruction_validator,
            Arc::clone(&query_validator),
            genesis_network,
            queue.clone(),
            broker.clone(),
        )
        .wrap_err("Failed to initialize Sumeragi.")?
        .start()
        .await
        .expect_running();

        let kura =
            K::from_configuration(&config.kura_configuration, Arc::clone(&wsv), broker.clone())?
                .start()
                .await
                .expect_running();
        let block_sync = B::from_configuration(
            &config.block_sync_configuration,
            Arc::clone(&wsv),
            sumeragi.clone(),
            PeerId::new(
                &config.torii_configuration.torii_p2p_url,
                &config.public_key,
            ),
            config
                .sumeragi_configuration
                .n_topology_shifts_before_reshuffle,
            broker.clone(),
        )
        .start()
        .await
        .expect_running();

        let torii = Torii::from_configuration(
            config.torii_configuration.clone(),
            Arc::clone(&wsv),
            System::new(config),
            queue.clone(),
            sumeragi.clone(),
            query_validator,
            events_receiver,
            broker.clone(),
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

    /// To make `Iroha` peer work it should be started first. After that moment it will listen for
    /// incoming requests and messages.
    ///
    /// # Errors
    /// Can fail if initing kura fails
    #[iroha_futures::telemetry_future]
    pub async fn start(&mut self) -> Result<Infallible> {
        iroha_logger::info!("Starting Iroha.");
        self.torii
            .take()
            .ok_or_else(|| error!("Seems like peer was already started"))?
            .start()
            .await
            .wrap_err("Failed to start Torii")
    }

    /// Starts iroha in separate tokio task.
    /// # Errors
    /// Can fail if initing kura fails
    pub fn start_as_task(&mut self) -> Result<JoinHandle<Result<Infallible>>> {
        iroha_logger::info!("Starting Iroha.");
        let torii = self
            .torii
            .take()
            .ok_or_else(|| error!("Seems like peer was already started"))?;
        Ok(tokio::spawn(async move {
            torii.start().await.wrap_err("Failed to start Torii")
        }))
    }
}

/// Allow to check if an item is included in a blockchain.
pub trait IsInBlockchain {
    /// Checks if this item has already been committed or rejected.
    fn is_in_blockchain<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> bool;
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
        smartcontracts::Query,
        tx::{
            AcceptedTransaction, ValidTransaction, VersionedAcceptedTransaction,
            VersionedValidTransaction,
        },
        wsv::WorldStateView,
        IsInBlockchain,
    };
}
