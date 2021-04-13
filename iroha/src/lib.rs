//! Iroha - A simple, enterprise-grade decentralized ledger.

pub mod account;
pub mod asset;
pub mod block;
pub mod block_sync;
pub mod config;
pub mod domain;
pub mod event;
pub mod expression;
pub mod genesis;
mod init;
pub mod isi;
mod kura;
pub mod maintenance;
mod merkle;
pub mod modules;
pub mod permissions;
pub mod query;
mod queue;
pub mod sumeragi;
pub mod torii;
pub mod tx;
pub mod world;
pub mod wsv;

use std::{sync::Arc, time::Duration};

use async_std::{
    prelude::*,
    sync::RwLock,
    sync::{self, Receiver, Sender},
    task,
};
use iroha_data_model::prelude::*;
use iroha_error::{Result, WrapErr};
use iroha_logger::InstrumentFutures;
use permissions::PermissionsValidatorBox;

use crate::{
    block::VersionedValidBlock,
    block_sync::{message::Message as BlockSyncMessage, BlockSynchronizer},
    config::Configuration,
    genesis::GenesisNetwork,
    kura::Kura,
    maintenance::System,
    prelude::*,
    queue::Queue,
    sumeragi::{message::VersionedMessage as SumeragiVersionedMessage, Sumeragi},
    torii::Torii,
};

/// The interval at which sumeragi checks if there are tx in the `queue`.
pub const TX_RETRIEVAL_INTERVAL: Duration = Duration::from_millis(100);

/// Type of `Sender<VersionedValidBlock>` which should be used for channels of `VersionedValidBlock` messages.
pub type ValidBlockSender = Sender<VersionedValidBlock>;
/// Type of `Receiver<ValidBlock>` which should be used for channels of `ValidBlock` messages.
pub type ValidBlockReceiver = Receiver<VersionedValidBlock>;
/// Type of `Sender<CommittedBlock>` which should be used for channels of `CommittedBlock` messages.
pub type CommittedBlockSender = Sender<VersionedCommittedBlock>;
/// Type of `Receiver<CommittedBlock>` which should be used for channels of `CommittedBlock` messages.
pub type CommittedBlockReceiver = Receiver<VersionedCommittedBlock>;
/// Type of `Sender<AcceptedTransaction>` which should be used for channels of `AcceptedTransaction` messages.
pub type TransactionSender = Sender<VersionedAcceptedTransaction>;
/// Type of `Receiver<AcceptedTransaction>` which should be used for channels of
/// `AcceptedTransaction` messages.
pub type TransactionReceiver = Receiver<VersionedAcceptedTransaction>;
/// Type of `Sender<Message>` which should be used for channels of `Message` messages.
pub type SumeragiMessageSender = Sender<SumeragiVersionedMessage>;
/// Type of `Receiver<Message>` which should be used for channels of `Message` messages.
pub type SumeragiMessageReceiver = Receiver<SumeragiVersionedMessage>;
/// Type of `Sender<Message>` which should be used for channels of `Message` messages.
pub type BlockSyncMessageSender = Sender<BlockSyncMessage>;
/// Type of `Receiver<Message>` which should be used for channels of `Message` messages.
pub type BlockSyncMessageReceiver = Receiver<BlockSyncMessage>;

/// Iroha is an [Orchestrator](https://en.wikipedia.org/wiki/Orchestration_%28computing%29) of the
/// system. It configure, coordinate and manage transactions and queries processing, work of consensus and storage.
#[derive(Debug)]
pub struct Iroha {
    torii: Arc<RwLock<Torii>>,
    queue: Arc<RwLock<Queue>>,
    sumeragi: Arc<RwLock<Sumeragi>>,
    kura: Arc<RwLock<Kura>>,
    transactions_receiver: TransactionReceiver,
    wsv_blocks_receiver: CommittedBlockReceiver,
    kura_blocks_receiver: CommittedBlockReceiver,
    sumeragi_message_receiver: SumeragiMessageReceiver,
    block_sync_message_receiver: BlockSyncMessageReceiver,
    world_state_view: Arc<WorldStateView>,
    block_sync: Arc<RwLock<BlockSynchronizer>>,
    genesis_network: Option<GenesisNetwork>,
}

impl Iroha {
    /// Default `Iroha` constructor used to build it based on the provided `Configuration`.
    /// # Errors
    /// Fails if fails one of the subparts initialization
    pub fn new(
        config: &Configuration,
        permissions_validator: PermissionsValidatorBox,
    ) -> Result<Self> {
        iroha_logger::init(config.logger_configuration);
        iroha_logger::info!(?config, "Loaded configuration");

        let (transactions_sender, transactions_receiver) = sync::channel(100);
        let (wsv_blocks_sender, wsv_blocks_receiver) = sync::channel(100);
        let (kura_blocks_sender, kura_blocks_receiver) = sync::channel(100);
        let (sumeragi_message_sender, sumeragi_message_receiver) = sync::channel(100);
        let (block_sync_message_sender, block_sync_message_receiver) = sync::channel(100);
        let (events_sender, events_receiver) = sync::channel(100);
        let world_state_view = Arc::new(WorldStateView::from_config(
            config.wsv_configuration,
            World::with(
                init::domains(config),
                config.sumeragi_configuration.trusted_peers.peers.clone(),
            ),
        ));
        let queue = Arc::new(RwLock::new(Queue::from_configuration(
            &config.queue_configuration,
        )));
        let sumeragi = Arc::new(RwLock::new(
            Sumeragi::from_configuration(
                &config.sumeragi_configuration,
                kura_blocks_sender,
                events_sender.clone(),
                Arc::clone(&world_state_view),
                transactions_sender.clone(),
                permissions_validator,
            )
            .wrap_err("Failed to initialize Sumeragi.")?,
        ));
        let torii = Torii::from_configuration(
            config.torii_configuration.clone(),
            Arc::clone(&world_state_view),
            transactions_sender,
            sumeragi_message_sender,
            block_sync_message_sender,
            System::new(config),
            Arc::clone(&queue),
            Arc::clone(&sumeragi),
            (events_sender, events_receiver),
        );
        let kura = Kura::from_configuration(&config.kura_configuration, wsv_blocks_sender)?;
        let kura = Arc::new(RwLock::new(kura));
        let block_sync = Arc::new(RwLock::new(BlockSynchronizer::from_configuration(
            &config.block_sync_configuration,
            Arc::clone(&world_state_view),
            Arc::clone(&sumeragi),
            PeerId::new(
                &config.torii_configuration.torii_p2p_url,
                &config.public_key,
            ),
            config
                .sumeragi_configuration
                .n_topology_shifts_before_reshuffle,
        )));
        let genesis_network = GenesisNetwork::from_configuration(
            &config.genesis_configuration,
            config.torii_configuration.torii_max_instruction_number,
        )
        .wrap_err("Failed to initialize genesis.")?;
        Ok(Iroha {
            queue,
            torii: Arc::new(RwLock::new(torii)),
            sumeragi,
            kura,
            world_state_view,
            transactions_receiver,
            wsv_blocks_receiver,
            sumeragi_message_receiver,
            kura_blocks_receiver,
            block_sync_message_receiver,
            block_sync,
            genesis_network,
        })
    }

    /// To make `Iroha` peer work it should be started first. After that moment it will listen for
    /// incoming requests and messages.
    ///
    /// # Errors
    /// Can fail if initing kura fails
    #[allow(clippy::eval_order_dependence, clippy::too_many_lines)]
    pub async fn start(&self) -> Result<()> {
        iroha_logger::info!("Starting Iroha.");
        //TODO: ensure the initialization order of `Kura`,`WSV` and `Sumeragi`.
        let kura = Arc::clone(&self.kura);
        let sumeragi = Arc::clone(&self.sumeragi);
        let blocks = kura.write().await.init().await?;
        sumeragi.write().await.init(
            self.world_state_view.latest_block_hash().await,
            self.world_state_view.height().await,
        );
        let world_state_view = Arc::clone(&self.world_state_view);
        world_state_view.init(blocks).await;
        sumeragi.write().await.update_network_topology().await;
        let torii = Arc::clone(&self.torii);
        let torii_handle = task::spawn(
            async move {
                if let Err(e) = torii.write().await.start().await {
                    iroha_logger::error!("Failed to start Torii: {}", e);
                }
            }
            .in_current_span(),
        );
        self.block_sync.read().await.start();
        let mut transactions_receiver = self.transactions_receiver.clone();
        let queue = Arc::clone(&self.queue);
        let tx_handle = task::spawn(
            async move {
                while let Some(transaction) = transactions_receiver.next().await {
                    if let Err(e) = queue.write().await.push_pending_transaction(transaction) {
                        iroha_logger::error!(
                            "Failed to put transaction into queue of pending tx: {}",
                            e
                        )
                    }
                }
            }
            .in_current_span(),
        );
        let queue = Arc::clone(&self.queue);
        let world_state_view = Arc::clone(&self.world_state_view);
        let voting_handle = task::spawn(
            async move {
                loop {
                    if !sumeragi.write().await.voting_in_progress().await {
                        let is_leader = sumeragi.read().await.is_leader();
                        let transactions = queue
                            .write()
                            .await
                            .get_pending_transactions(is_leader, &world_state_view);
                        if let Err(e) = sumeragi.write().await.round(transactions).await {
                            iroha_logger::error!("Round failed: {}", e);
                        }
                    }
                    task::sleep(TX_RETRIEVAL_INTERVAL).await;
                }
            }
            .in_current_span(),
        );
        let mut wsv_blocks_receiver = self.wsv_blocks_receiver.clone();
        let world_state_view = Arc::clone(&self.world_state_view);
        let sumeragi = Arc::clone(&self.sumeragi);
        let block_sync = Arc::clone(&self.block_sync);
        let wsv_handle = task::spawn(
            async move {
                while let Some(block) = wsv_blocks_receiver.next().await {
                    world_state_view.apply(block).await;
                    sumeragi.write().await.update_network_topology().await;
                    block_sync.write().await.continue_sync().await;
                }
            }
            .in_current_span(),
        );
        let mut sumeragi_message_receiver = self.sumeragi_message_receiver.clone();
        let sumeragi = Arc::clone(&self.sumeragi);
        let sumeragi_message_handle = task::spawn(
            async move {
                while let Some(message) = sumeragi_message_receiver.next().await {
                    if let Err(e) = message.handle(&mut *sumeragi.write().await).await {
                        iroha_logger::error!("Handle message failed: {}", e);
                    }
                }
            }
            .in_current_span(),
        );
        let mut block_sync_message_receiver = self.block_sync_message_receiver.clone();
        let block_sync = Arc::clone(&self.block_sync);
        let block_sync_message_handle = task::spawn(
            async move {
                while let Some(message) = block_sync_message_receiver.next().await {
                    message.handle(&mut *block_sync.write().await).await;
                }
            }
            .in_current_span(),
        );
        let mut kura_blocks_receiver = self.kura_blocks_receiver.clone();
        let kura = Arc::clone(&self.kura);
        let kura_handle = task::spawn(
            async move {
                while let Some(block) = kura_blocks_receiver.next().await {
                    if let Err(e) = kura.write().await.store(block).await {
                        iroha_logger::error!("Failed to write block: {}", e)
                    }
                }
            }
            .in_current_span(),
        );

        let sumeragi = Arc::clone(&self.sumeragi);
        let genesis_network = self.genesis_network.clone();
        let genesis_network_handle = task::spawn(
            async move {
                if let Some(genesis_network) = genesis_network {
                    if let Err(err) = genesis_network.submit_transactions(sumeragi).await {
                        iroha_logger::error!("Failed to submit genesis transactions: {}", err)
                    }
                }
            }
            .in_current_span(),
        );

        futures::join!(
            torii_handle,
            kura_handle,
            voting_handle,
            wsv_handle,
            sumeragi_message_handle,
            tx_handle,
            block_sync_message_handle,
            genesis_network_handle,
        );
        Ok(())
    }
}

/// Allow to check if item included in blockchain
pub trait IsInBlockchain {
    /// Checks if this item has already been committed or rejected.
    fn is_in_blockchain(&self, world_state_view: &WorldStateView) -> bool;
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
        permissions::AllowAll,
        query::Query,
        tx::{
            AcceptedTransaction, ValidTransaction, VersionedAcceptedTransaction,
            VersionedValidTransaction,
        },
        wsv::WorldStateView,
        CommittedBlockReceiver, CommittedBlockSender, Iroha, IsInBlockchain, TransactionReceiver,
        TransactionSender, ValidBlockReceiver, ValidBlockSender,
    };
}
