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
    sumeragi::{Message as SumeragiMessage, Sumeragi},
    torii::{Message as ToriiMessage, Torii},
};
use async_std::{
    prelude::*,
    sync::{self, Receiver, RwLock, Sender},
    task,
};
use parity_scale_codec::{Decode, Encode};
use std::{path::Path, sync::Arc, time::Duration};

pub type BlockSender = Sender<ValidBlock>;
pub type BlockReceiver = Receiver<ValidBlock>;
pub type TransactionSender = Sender<AcceptedTransaction>;
pub type TransactionReceiver = Receiver<AcceptedTransaction>;
pub type SumeragiMessageSender = Sender<SumeragiMessage>;
pub type SumeragiMessageReceiver = Receiver<SumeragiMessage>;
pub type ToriiMessageSender = Sender<ToriiMessage>;
pub type ToriiMessageReceiver = Receiver<ToriiMessage>;

/// Iroha is an [Orchestrator](https://en.wikipedia.org/wiki/Orchestration_%28computing%29) of the
/// system. It configure, coordinate and manage transactions and queries processing, work of consensus and storage.
pub struct Iroha {
    torii: Arc<RwLock<Torii>>,
    queue: Arc<RwLock<Queue>>,
    sumeragi: Arc<RwLock<Sumeragi>>,
    kura: Arc<RwLock<Kura>>,
    transactions_receiver: Arc<RwLock<TransactionReceiver>>,
    blocks_to_wsv_receiver: Arc<RwLock<BlockReceiver>>,
    messages_to_sumeragi_receiver: Arc<RwLock<SumeragiMessageReceiver>>,
    messages_to_torii_receiver: Arc<RwLock<ToriiMessageReceiver>>,
    world_state_view: Arc<RwLock<WorldStateView>>,
    block_build_step_ms: u64,
}

impl Iroha {
    pub fn new(config: Configuration) -> Self {
        let (transactions_sender, transactions_receiver) = sync::channel(100);
        let (blocks_to_wsv_sender, blocks_to_wsv_receiver) = sync::channel(100);
        let (messages_to_sumeragi_sender, messages_to_sumeragi_receiver) = sync::channel(100);
        let (messages_to_torii_sender, messages_to_torii_receiver) = sync::channel(100);
        let world_state_view = Arc::new(RwLock::new(WorldStateView::new(Peer::new(
            config.torii_url.clone(),
            &Vec::new(),
        ))));
        let torii = Torii::new(
            &config.torii_url,
            Arc::clone(&world_state_view),
            transactions_sender,
            messages_to_sumeragi_sender,
        );
        let (public_key, private_key) = config.key_pair();
        let kura = Arc::new(RwLock::new(Kura::new(
            config.mode,
            Path::new(&config.kura_block_store_path),
            blocks_to_wsv_sender,
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
                Arc::new(RwLock::new(messages_to_torii_sender)),
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
            blocks_to_wsv_receiver: Arc::new(RwLock::new(blocks_to_wsv_receiver)),
            messages_to_sumeragi_receiver: Arc::new(RwLock::new(messages_to_sumeragi_receiver)),
            messages_to_torii_receiver: Arc::new(RwLock::new(messages_to_torii_receiver)),
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
        let blocks_to_wsv_receiver = Arc::clone(&self.blocks_to_wsv_receiver);
        let world_state_view = Arc::clone(&self.world_state_view);
        task::spawn(async move {
            while let Some(block) = blocks_to_wsv_receiver.write().await.next().await {
                world_state_view.write().await.put(&block).await;
            }
        });
        let messages_to_sumeragi_receiver = Arc::clone(&self.messages_to_sumeragi_receiver);
        let sumeragi = Arc::clone(&self.sumeragi);
        task::spawn(async move {
            while let Some(message) = messages_to_sumeragi_receiver.write().await.next().await {
                let _result = sumeragi.write().await.handle_message(message).await;
            }
        });
        let messages_to_torii_receiver = Arc::clone(&self.messages_to_torii_receiver);
        task::spawn(async move {
            while let Some(message) = messages_to_torii_receiver.write().await.next().await {
                let _result = Torii::send(message).await;
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
        tx::{AcceptedTransaction, RequestedTransaction, SignedTransaction, ValidTransaction},
        wsv::WorldStateView,
        BlockReceiver, BlockSender, Id, Iroha, TransactionReceiver, TransactionSender,
    };
}
