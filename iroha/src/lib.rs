//! Iroha - A simple, enterprise-grade decentralized ledger.

#![warn(
    anonymous_parameters,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    private_doc_tests,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    future_incompatible,
    nonstandard_style,
    unsafe_code,
    unused_import_braces,
    unused_results,
    variant_size_differences
)]

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

use crate::{
    block_sync::{message::Message as BlockSyncMessage, BlockSynchronizer},
    config::Configuration,
    genesis::GenesisBlock,
    kura::Kura,
    maintenance::System,
    prelude::*,
    queue::Queue,
    sumeragi::{message::Message as SumeragiMessage, Sumeragi},
    torii::Torii,
};
use async_std::{
    prelude::*,
    sync::{self, Receiver, RwLock, Sender},
    task,
};
use iroha_data_model::prelude::*;
use permissions::PermissionsValidatorBox;
use std::{sync::Arc, time::Duration};

/// The interval at which sumeragi checks if there are tx in the `queue`.
pub const TX_RETRIEVAL_INTERVAL: Duration = Duration::from_millis(100);

/// Type of `Sender<ValidBlock>` which should be used for channels of `ValidBlock` messages.
pub type ValidBlockSender = Sender<ValidBlock>;
/// Type of `Receiver<ValidBlock>` which should be used for channels of `ValidBlock` messages.
pub type ValidBlockReceiver = Receiver<ValidBlock>;
/// Type of `Sender<CommittedBlock>` which should be used for channels of `CommittedBlock` messages.
pub type CommittedBlockSender = Sender<CommittedBlock>;
/// Type of `Receiver<CommittedBlock>` which should be used for channels of `CommittedBlock` messages.
pub type CommittedBlockReceiver = Receiver<CommittedBlock>;
/// Type of `Sender<AcceptedTransaction>` which should be used for channels of `AcceptedTransaction` messages.
pub type TransactionSender = Sender<AcceptedTransaction>;
/// Type of `Receiver<AcceptedTransaction>` which should be used for channels of
/// `AcceptedTransaction` messages.
pub type TransactionReceiver = Receiver<AcceptedTransaction>;
/// Type of `Sender<Message>` which should be used for channels of `Message` messages.
pub type SumeragiMessageSender = Sender<SumeragiMessage>;
/// Type of `Receiver<Message>` which should be used for channels of `Message` messages.
pub type SumeragiMessageReceiver = Receiver<SumeragiMessage>;
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
    transactions_receiver: Arc<RwLock<TransactionReceiver>>,
    wsv_blocks_receiver: Arc<RwLock<CommittedBlockReceiver>>,
    kura_blocks_receiver: Arc<RwLock<ValidBlockReceiver>>,
    sumeragi_message_receiver: Arc<RwLock<SumeragiMessageReceiver>>,
    block_sync_message_receiver: Arc<RwLock<BlockSyncMessageReceiver>>,
    world_state_view: Arc<RwLock<WorldStateView>>,
    block_sync: Arc<RwLock<BlockSynchronizer>>,
    genesis_block: Option<GenesisBlock>,
}

impl Iroha {
    /// Default `Iroha` constructor used to build it based on the provided `Configuration`.
    pub fn new(config: Configuration, permissions_checker: PermissionsValidatorBox) -> Self {
        iroha_logger::init(&config.logger_configuration).expect("Failed to initialize logger.");
        log::info!("Configuration: {:?}", config);
        let (transactions_sender, transactions_receiver) = sync::channel(100);
        let (wsv_blocks_sender, wsv_blocks_receiver) = sync::channel(100);
        let (kura_blocks_sender, kura_blocks_receiver) = sync::channel(100);
        let (sumeragi_message_sender, sumeragi_message_receiver) = sync::channel(100);
        let (block_sync_message_sender, block_sync_message_receiver) = sync::channel(100);
        let (events_sender, events_receiver) = sync::channel(100);
        let world_state_view = Arc::new(RwLock::new(WorldStateView::new(World::with(
            init::domains(&config.init_configuration),
            config.sumeragi_configuration.trusted_peers.clone(),
        ))));
        let torii = Torii::from_configuration(
            &config.torii_configuration,
            Arc::clone(&world_state_view),
            transactions_sender.clone(),
            sumeragi_message_sender,
            block_sync_message_sender,
            System::new(&config),
            (events_sender.clone(), events_receiver),
        );
        let kura = Kura::from_configuration(&config.kura_configuration, wsv_blocks_sender);
        let sumeragi = Arc::new(RwLock::new(
            Sumeragi::from_configuration(
                &config.sumeragi_configuration,
                Arc::new(RwLock::new(kura_blocks_sender)),
                events_sender,
                world_state_view.clone(),
                transactions_sender,
                permissions_checker,
            )
            .expect("Failed to initialize Sumeragi."),
        ));
        let kura = Arc::new(RwLock::new(kura));
        let block_sync = Arc::new(RwLock::new(BlockSynchronizer::from_configuration(
            &config.block_sync_configuration,
            kura.clone(),
            sumeragi.clone(),
            PeerId::new(
                &config.torii_configuration.torii_p2p_url,
                &config.public_key,
            ),
        )));
        let queue = Arc::new(RwLock::new(Queue::from_configuration(
            &config.queue_configuration,
        )));

        let genesis_block = config
            .genesis_block_path
            .as_ref()
            .map(|genesis_block_path| {
                GenesisBlock::from_configuration(genesis_block_path, &config.init_configuration)
                    .expect("Failed to initialize genesis.")
            });

        Iroha {
            queue,
            torii: Arc::new(RwLock::new(torii)),
            sumeragi,
            kura,
            world_state_view,
            transactions_receiver: Arc::new(RwLock::new(transactions_receiver)),
            wsv_blocks_receiver: Arc::new(RwLock::new(wsv_blocks_receiver)),
            sumeragi_message_receiver: Arc::new(RwLock::new(sumeragi_message_receiver)),
            kura_blocks_receiver: Arc::new(RwLock::new(kura_blocks_receiver)),
            block_sync_message_receiver: Arc::new(RwLock::new(block_sync_message_receiver)),
            block_sync,
            genesis_block,
        }
    }

    /// To make `Iroha` peer work it should be started first. After that moment it will listen for
    /// incoming requests and messages.
    #[allow(clippy::eval_order_dependence)]
    pub async fn start(&self) -> Result<(), String> {
        log::info!("Starting Iroha.");
        //TODO: ensure the initialization order of `Kura`,`WSV` and `Sumeragi`.
        let kura = Arc::clone(&self.kura);
        let sumeragi = Arc::clone(&self.sumeragi);
        kura.write().await.init().await?;
        sumeragi.write().await.init(
            kura.read().await.latest_block_hash(),
            kura.read().await.height(),
        );
        let world_state_view = Arc::clone(&self.world_state_view);
        world_state_view
            .write()
            .await
            .init(&kura.read().await.blocks);
        sumeragi.write().await.update_network_topology().await;
        let torii = Arc::clone(&self.torii);
        let torii_handle = task::spawn(async move {
            if let Err(e) = torii.write().await.start().await {
                log::error!("Failed to start Torii: {}", e);
            }
        });
        self.block_sync.read().await.start();
        let transactions_receiver = Arc::clone(&self.transactions_receiver);
        let queue = Arc::clone(&self.queue);
        let tx_handle = task::spawn(async move {
            while let Some(transaction) = transactions_receiver.write().await.next().await {
                if let Err(e) = queue.write().await.push_pending_transaction(transaction) {
                    log::error!("Failed to put transaction into queue of pending tx: {}", e)
                }
            }
        });
        let queue = Arc::clone(&self.queue);
        let voting_handle = task::spawn(async move {
            loop {
                if !sumeragi.write().await.voting_in_progress().await {
                    sumeragi
                        .write()
                        .await
                        .round(queue.write().await.pop_pending_transactions())
                        .await
                        .expect("Round failed.");
                }
                task::sleep(TX_RETRIEVAL_INTERVAL).await;
            }
        });
        let wsv_blocks_receiver = Arc::clone(&self.wsv_blocks_receiver);
        let world_state_view = Arc::clone(&self.world_state_view);
        let sumeragi = Arc::clone(&self.sumeragi);
        let block_sync = Arc::clone(&self.block_sync);
        let wsv_handle = task::spawn(async move {
            while let Some(block) = wsv_blocks_receiver.write().await.next().await {
                world_state_view.write().await.apply(&block);
                sumeragi.write().await.update_network_topology().await;
                block_sync.write().await.continue_sync().await;
            }
        });
        let sumeragi_message_receiver = Arc::clone(&self.sumeragi_message_receiver);
        let sumeragi = Arc::clone(&self.sumeragi);
        let sumeragi_message_handle = task::spawn(async move {
            while let Some(message) = sumeragi_message_receiver.write().await.next().await {
                if let Err(e) = message.handle(&mut *sumeragi.write().await).await {
                    log::error!("Handle message failed: {}", e);
                }
            }
        });
        let block_sync_message_receiver = Arc::clone(&self.block_sync_message_receiver);
        let block_sync = Arc::clone(&self.block_sync);
        let block_sync_message_handle = task::spawn(async move {
            while let Some(message) = block_sync_message_receiver.write().await.next().await {
                message.handle(&mut *block_sync.write().await).await;
            }
        });
        let kura_blocks_receiver = Arc::clone(&self.kura_blocks_receiver);
        let kura = Arc::clone(&self.kura);
        let kura_handle = task::spawn(async move {
            while let Some(block) = kura_blocks_receiver.write().await.next().await {
                let _hash = kura
                    .write()
                    .await
                    .store(block)
                    .await
                    .expect("Failed to write block.");
            }
        });

        let queue = Arc::clone(&self.queue);
        if let Some(ref genesis_block) = self.genesis_block {
            log::info!("Initialize iroha using the genesis block");
            for transaction in genesis_block.transactions.iter() {
                if let Err(e) = queue
                    .write()
                    .await
                    .push_pending_transaction(transaction.clone())
                {
                    log::error!(
                        "Failed to push transactions from genesis block to queue error: {}",
                        e
                    )
                }
            }
        }

        futures::join!(
            torii_handle,
            kura_handle,
            voting_handle,
            wsv_handle,
            sumeragi_message_handle,
            tx_handle,
            block_sync_message_handle,
        );
        Ok(())
    }
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.

    #[doc(inline)]
    pub use crate::{
        block::{CommittedBlock, PendingBlock, ValidBlock},
        permissions::AllowAll,
        query::Query,
        tx::{AcceptedTransaction, ValidTransaction},
        wsv::WorldStateView,
        CommittedBlockReceiver, CommittedBlockSender, Iroha, TransactionReceiver,
        TransactionSender, ValidBlockReceiver, ValidBlockSender,
    };

    #[doc(inline)]
    pub use iroha_crypto::{Hash, KeyPair, PrivateKey, PublicKey, Signature};
}
