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
mod sumeragi;
pub mod torii;
pub mod tx;
pub mod wsv;

use crate::{
    config::Configuration,
    kura::Kura,
    peer::{Message, Peer, PeerId},
    prelude::*,
    queue::Queue,
    sumeragi::Sumeragi,
    torii::{uri, Torii},
};
use futures::{
    channel::mpsc::{self, UnboundedReceiver, UnboundedSender},
    executor::{self, ThreadPool},
    lock::Mutex,
    prelude::*,
};
use iroha_network::{Network, Request};
use parity_scale_codec::{Decode, Encode};
use std::{path::Path, sync::Arc, time::Instant};

pub type BlockSender = UnboundedSender<Block>;
pub type BlockReceiver = UnboundedReceiver<Block>;
pub type TransactionSender = UnboundedSender<Transaction>;
pub type TransactionReceiver = UnboundedReceiver<Transaction>;
pub type MessageSender = UnboundedSender<Message>;
pub type MessageReceiver = UnboundedReceiver<Message>;

/// Iroha is an [Orchestrator](https://en.wikipedia.org/wiki/Orchestration_%28computing%29) of the
/// system. It configure, coordinate and manage transactions and queries processing, work of consensus and storage.
pub struct Iroha {
    torii: Arc<Mutex<Torii>>,
    queue: Arc<Mutex<Queue>>,
    sumeragi: Arc<Mutex<Sumeragi>>,
    kura: Arc<Mutex<Kura>>,
    last_round_time: Arc<Mutex<Instant>>,
    transactions_receiver: Arc<Mutex<TransactionReceiver>>,
    blocks_receiver: Arc<Mutex<BlockReceiver>>,
    message_receiver: Arc<Mutex<MessageReceiver>>,
    world_state_view: Arc<Mutex<WorldStateView>>,
    pool: ThreadPool,
}

impl Iroha {
    pub fn new(config: Configuration) -> Self {
        let (transactions_sender, transactions_receiver) = mpsc::unbounded();
        let (blocks_sender, blocks_receiver) = mpsc::unbounded();
        let (message_sender, message_receiver) = mpsc::unbounded();
        let world_state_view = Arc::new(Mutex::new(WorldStateView::new(Peer::new(
            config.torii_url.clone(),
            &Vec::new(),
        ))));
        let pool = ThreadPool::new().expect("Failed to create new Thread Pool.");
        let torii = Torii::new(
            &config.torii_url,
            pool.clone(),
            Arc::clone(&world_state_view),
            transactions_sender,
            message_sender,
        );
        let (public_key, private_key) =
            crypto::generate_key_pair().expect("Failed to generate key pair.");
        //TODO: get peers from json and blockchain
        let sumeragi = Arc::new(Mutex::new(
            Sumeragi::new(
                public_key,
                private_key,
                &[PeerId {
                    address: config.torii_url.to_string(),
                    public_key,
                }],
                None,
                0,
            )
            .expect("Failed to initialize Sumeragi."),
        ));
        let kura = Kura::new(
            config.mode,
            Path::new(&config.kura_block_store_path),
            blocks_sender,
        );
        let queue = Arc::new(Mutex::new(Queue::default()));
        Iroha {
            queue,
            torii: Arc::new(Mutex::new(torii)),
            sumeragi,
            kura: Arc::new(Mutex::new(kura)),
            world_state_view,
            transactions_receiver: Arc::new(Mutex::new(transactions_receiver)),
            blocks_receiver: Arc::new(Mutex::new(blocks_receiver)),
            message_receiver: Arc::new(Mutex::new(message_receiver)),
            last_round_time: Arc::new(Mutex::new(Instant::now())),
            pool,
        }
    }

    pub fn start(self) -> Result<(), String> {
        let kura = Arc::clone(&self.kura);
        executor::block_on(async move { kura.lock().await.init().await })?;
        let torii = Arc::clone(&self.torii);
        self.pool.spawn_ok(async move {
            torii.lock().await.start().await;
        });
        let transactions_receiver = Arc::clone(&self.transactions_receiver);
        let queue = Arc::clone(&self.queue);
        self.pool.spawn_ok(async move {
            while let Some(transaction) = transactions_receiver.lock().await.next().await {
                queue.lock().await.push_pending_transaction(transaction);
            }
        });
        let queue = Arc::clone(&self.queue);
        let kura = Arc::clone(&self.kura);
        let sumeragi = Arc::clone(&self.sumeragi);
        let last_round_time = Arc::clone(&self.last_round_time);
        let world_state_view = Arc::clone(&self.world_state_view);
        //TODO: decide what should be the minimum time to accumulate tx before creating a block
        //TODO: create block only if the peer is a leader
        //TODO: call sumeragi `on_block_created`
        self.pool.spawn_ok(async move {
            loop {
                let transactions = queue.lock().await.pop_pending_transactions();
                if !transactions.is_empty() {
                    let mut send_futures = Vec::new();
                    for peer_id in &world_state_view.lock().await.peer().peers {
                        for transaction in &transactions {
                            let peer_id = peer_id.clone();
                            send_futures.push(async move {
                                let _response = Network::send_request_to(
                                    peer_id.address.as_ref(),
                                    Request::new(uri::BLOCKS_URI.to_string(), transaction.into()),
                                )
                                .await;
                            });
                        }
                    }
                    let _results = futures::future::join_all(send_futures).await;
                    kura.lock()
                        .await
                        .store(
                            sumeragi
                                .lock()
                                .await
                                .sign_transactions(transactions)
                                .await
                                .expect("Failed to sign transactions."),
                            &*world_state_view.lock().await,
                        )
                        .await
                        .expect("Failed to accept transactions into blockchain.");
                    *last_round_time.lock().await = Instant::now();
                }
            }
        });
        let blocks_receiver = Arc::clone(&self.blocks_receiver);
        let world_state_view = Arc::clone(&self.world_state_view);
        self.pool.spawn_ok(async move {
            while let Some(block) = blocks_receiver.lock().await.next().await {
                world_state_view.lock().await.put(&block).await;
            }
        });
        let message_receiver = Arc::clone(&self.message_receiver);
        let sumeragi = Arc::clone(&self.sumeragi);
        self.pool.spawn_ok(async move {
            while let Some(message) = message_receiver.lock().await.next().await {
                match message {
                    Message::SumeragiMessage(message) => {
                        let _result = sumeragi.lock().await.handle_message(message).await;
                    }
                }
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
