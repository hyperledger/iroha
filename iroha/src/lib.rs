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
    sumeragi::{Message, Role, Sumeragi},
    torii::{uri, Torii},
};
use async_std::{
    prelude::*,
    sync::{self, Receiver, RwLock, Sender},
    task,
};
use iroha_network::{Network, Request};
use parity_scale_codec::{Decode, Encode};
use std::time::Duration;
use std::{path::Path, sync::Arc, time::Instant};

pub type BlockSender = Sender<Block>;
pub type BlockReceiver = Receiver<Block>;
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
    last_round_time: Arc<RwLock<Instant>>,
    transactions_receiver: Arc<RwLock<TransactionReceiver>>,
    blocks_receiver: Arc<RwLock<BlockReceiver>>,
    message_receiver: Arc<RwLock<MessageReceiver>>,
    world_state_view: Arc<RwLock<WorldStateView>>,
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
            last_round_time: Arc::new(RwLock::new(Instant::now())),
        }
    }

    pub fn start(&self) -> Result<(), String> {
        let kura = Arc::clone(&self.kura);
        task::block_on(async move { kura.write().await.init().await })?;
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
        let last_round_time = Arc::clone(&self.last_round_time);
        let world_state_view = Arc::clone(&self.world_state_view);
        //TODO: decide what should be the minimum time to accumulate tx before creating a block
        task::spawn(async move {
            loop {
                let mut sumeragi = sumeragi.write().await;
                if !sumeragi.has_pending_block() {
                    let transactions = queue.write().await.pop_pending_transactions();
                    if !transactions.is_empty() {
                        if let Role::Leader = sumeragi.role() {
                            sumeragi
                                .validate_and_store(transactions, Arc::clone(&world_state_view))
                                .await
                                .expect("Failed to accept transactions into blockchain.");
                        } else {
                            //TODO: send pending transactions to all peers and as leader check what tx have already been committed
                            //Sends transactions to leader
                            let mut send_futures = Vec::new();
                            for transaction in &transactions {
                                send_futures.push(Network::send_request_to(
                                    &sumeragi.leader().address,
                                    Request::new(
                                        uri::INSTRUCTIONS_URI.to_string(),
                                        transaction.as_requested().into(),
                                    ),
                                ));
                            }
                            let _results = futures::future::join_all(send_futures).await;
                        }
                        *last_round_time.write().await = Instant::now();
                    }
                }
                task::sleep(Duration::from_millis(20)).await;
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
        block::Block,
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
