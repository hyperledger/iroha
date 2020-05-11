pub mod account;
pub mod asset;
pub mod block;
pub mod config;
pub mod crypto;
pub mod domain;
pub mod isi;
mod kura;
mod merkle;
pub mod peer;
pub mod query;
mod queue;
pub mod sumeragi;
pub mod torii;
pub mod tx;
pub mod wsv;

use crate::{
    config::Configuration,
    kura::Kura,
    peer::{Peer, PeerId},
    prelude::*,
    queue::Queue,
    sumeragi::{Message, Sumeragi},
    torii::Torii,
};
use async_std::{
    prelude::*,
    sync::{self, Receiver, RwLock, Sender},
    task,
};
use parity_scale_codec::{Decode, Encode};
use std::time::Duration;
use std::{path::Path, sync::Arc};

pub type BlockSender = Sender<ValidBlock>;
pub type BlockReceiver = Receiver<ValidBlock>;
pub type TransactionSender = Sender<Transaction>;
pub type TransactionReceiver = Receiver<Transaction>;
pub type MessageSender = Sender<Message>;
pub type MessageReceiver = Receiver<Message>;

/// Iroha is an [Orchestrator](https://en.wikipedia.org/wiki/Orchestration_%28computing%29) of the
/// system. It configure, coordinate and manage transactions and queries processing, work of consensus and storage.
pub struct Iroha {
    torii: Arc<RwLock<Torii>>,
    queue: Arc<RwLock<Queue>>,
    sumeragi: Arc<RwLock<Sumeragi>>,
    kura: Arc<RwLock<Kura>>,
    transactions_receiver: Arc<RwLock<TransactionReceiver>>,
    blocks_receiver: Arc<RwLock<BlockReceiver>>,
    message_receiver: Arc<RwLock<MessageReceiver>>,
    world_state_view: Arc<RwLock<WorldStateView>>,
    block_build_step_ms: u64,
}

impl Iroha {
    pub fn new(config: Configuration) -> Self {
        let (transactions_sender, transactions_receiver) = sync::channel(100);
        let (blocks_sender, blocks_receiver) = sync::channel(100);
        let (message_sender, message_receiver) = sync::channel(100);
        let world_state_view = Arc::new(RwLock::new(WorldStateView::new(Peer::new(
            config.torii_url.clone(),
            &Vec::new(),
        ))));
        let torii = Torii::new(
            &config.torii_url,
            Arc::clone(&world_state_view),
            transactions_sender,
            message_sender,
        );
        let (public_key, private_key) = config.key_pair();
        let kura = Arc::new(RwLock::new(Kura::new(
            config.mode,
            Path::new(&config.kura_block_store_path),
            blocks_sender,
        )));
        //TODO: get peers from json and blockchain
        //The id of this peer
        let iroha_peer_id = PeerId {
            address: config.torii_url.to_string(),
            public_key,
        };
        let peers = match config.trusted_peers {
            Some(peers) => peers,
            None => vec![iroha_peer_id.clone()],
        };
        let sumeragi = Arc::new(RwLock::new(
            Sumeragi::new(
                private_key,
                &peers,
                iroha_peer_id,
                config.max_faulty_peers,
                kura.clone(),
                world_state_view.clone(),
            )
            .expect("Failed to initialize Sumeragi."),
        ));
        let queue = Arc::new(RwLock::new(Queue::default()));
        Iroha {
            queue,
            torii: Arc::new(RwLock::new(torii)),
            sumeragi,
            kura,
            world_state_view,
            transactions_receiver: Arc::new(RwLock::new(transactions_receiver)),
            blocks_receiver: Arc::new(RwLock::new(blocks_receiver)),
            message_receiver: Arc::new(RwLock::new(message_receiver)),
            block_build_step_ms: config.block_build_step_ms,
        }
    }

    pub async fn start(&self) -> Result<(), String> {
        let kura = Arc::clone(&self.kura);
        kura.write().await.init().await?;
        let torii = Arc::clone(&self.torii);
        task::spawn(async move {
            if let Err(e) = torii.write().await.start().await {
                eprintln!("Failed to start Torii: {}", e);
            }
        });
        let transactions_receiver = Arc::clone(&self.transactions_receiver);
        let queue = Arc::clone(&self.queue);
        task::spawn(async move {
            while let Some(transaction) = transactions_receiver.write().await.next().await {
                queue.write().await.push_pending_transaction(transaction);
            }
        });
        let queue = Arc::clone(&self.queue);
        let sumeragi = Arc::clone(&self.sumeragi);
        let world_state_view = Arc::clone(&self.world_state_view);
        let block_build_step_ms = self.block_build_step_ms;
        task::spawn(async move {
            loop {
                if let Some(block) = sumeragi
                    .write()
                    .await
                    .round(queue.write().await.pop_pending_transactions())
                    .await
                    .expect("Round failed.")
                {
                    let _hash = kura
                        .write()
                        .await
                        .store(
                            block
                                .validate(&*world_state_view.write().await)
                                .expect("Failed to validate block."),
                        )
                        .await
                        .expect("Failed to write block.");
                }
                task::sleep(Duration::from_millis(block_build_step_ms)).await;
            }
        });
        let blocks_receiver = Arc::clone(&self.blocks_receiver);
        let world_state_view = Arc::clone(&self.world_state_view);
        task::spawn(async move {
            while let Some(block) = blocks_receiver.write().await.next().await {
                world_state_view.write().await.put(&block).await;
            }
        });
        let message_receiver = Arc::clone(&self.message_receiver);
        let sumeragi = Arc::clone(&self.sumeragi);
        task::spawn(async move {
            while let Some(message) = message_receiver.write().await.next().await {
                let _result = sumeragi.write().await.handle_message(message).await;
            }
        });
        Ok(())
    }
}

/// Identification of an Iroha's entites. Consists of Entity's name and Domain's name.
///
/// # Example
///
/// ```
/// use iroha::Id;
///
/// let id = Id::new("gold", "mine");
/// ```
#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq, std::hash::Hash, Encode, Decode)]
pub struct Id {
    pub entity_name: String,
    pub domain_name: String,
}

impl Id {
    pub fn new(entity_name: &str, domain_name: &str) -> Self {
        Id {
            entity_name: entity_name.to_string(),
            domain_name: domain_name.to_string(),
        }
    }
}

impl From<&str> for Id {
    fn from(string: &str) -> Id {
        let vector: Vec<&str> = string.split('@').collect();
        Id {
            entity_name: String::from(vector[0]),
            domain_name: String::from(vector[1]),
        }
    }
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.

    #[doc(inline)]
    pub use crate::{
        account::Account,
        asset::Asset,
        block::{PendingBlock, ValidBlock},
        config::Configuration,
        crypto::{Hash, PrivateKey, PublicKey, Signature},
        domain::Domain,
        isi::{Contract, Instruction},
        peer::Peer,
        query::{Query, QueryRequest, QueryResult},
        tx::{Transaction, TransactionRequest},
        wsv::WorldStateView,
        BlockReceiver, BlockSender, Id, Iroha, TransactionReceiver, TransactionSender,
    };
}
