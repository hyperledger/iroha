//! Gossiper is actor which is responsible for transaction gossiping

use std::{num::NonZeroU32, sync::Arc, time::Duration};

use iroha_config::parameters::actual::TransactionGossiper as Config;
use iroha_data_model::{transaction::SignedTransaction, ChainId};
use iroha_p2p::Broadcast;
use parity_scale_codec::{Decode, Encode};
use tokio::sync::mpsc;

use crate::{
    queue::Queue, state::State, tx::AcceptedTransaction, IrohaNetwork, NetworkMessage,
    WorldReadOnly,
};

/// [`Gossiper`] actor handle.
#[derive(Clone)]
pub struct TransactionGossiperHandle {
    message_sender: mpsc::Sender<TransactionGossip>,
}

impl TransactionGossiperHandle {
    /// Send [`TransactionGossip`] to actor
    pub async fn gossip(&self, gossip: TransactionGossip) {
        self.message_sender
            .send(gossip)
            .await
            .expect("Gossiper must handle messages until there is at least one handle to it")
    }
}

/// Actor which gossips transactions and receives transaction gossips
pub struct TransactionGossiper {
    /// Unique id of the blockchain. Used for simple replay attack protection.
    chain_id: ChainId,
    /// The time between gossip messages. More frequent gossiping shortens
    /// the time to sync, but can overload the network.
    gossip_period: Duration,
    /// Maximum size of a batch that is being gossiped. Smaller size leads
    /// to longer time to synchronise, useful if you have high packet loss.
    gossip_size: NonZeroU32,
    network: IrohaNetwork,
    queue: Arc<Queue>,
    state: Arc<State>,
}

impl TransactionGossiper {
    /// Start [`Self`] actor.
    pub fn start(self) -> TransactionGossiperHandle {
        let (message_sender, message_receiver) = mpsc::channel(1);
        tokio::task::spawn(self.run(message_receiver));
        TransactionGossiperHandle { message_sender }
    }

    /// Construct [`Self`] from configuration
    pub fn from_config(
        chain_id: ChainId,
        Config {
            gossip_period,
            gossip_size,
        }: Config,
        network: IrohaNetwork,
        queue: Arc<Queue>,
        state: Arc<State>,
    ) -> Self {
        Self {
            chain_id,
            gossip_period,
            gossip_size,
            network,
            queue,
            state,
        }
    }

    async fn run(self, mut message_receiver: mpsc::Receiver<TransactionGossip>) {
        let mut gossip_period = tokio::time::interval(self.gossip_period);
        loop {
            tokio::select! {
                _ = gossip_period.tick() => self.gossip_transactions(),
                transaction_gossip = message_receiver.recv() => {
                    let Some(transaction_gossip) = transaction_gossip else {
                        iroha_logger::info!("All handler to Gossiper are dropped. Shutting down...");
                        break;
                    };
                    self.handle_transaction_gossip(transaction_gossip);
                }
            }
            tokio::task::yield_now().await;
        }
    }

    fn gossip_transactions(&self) {
        let txs = self
            .queue
            .n_random_transactions(self.gossip_size.get(), &self.state.view());

        if txs.is_empty() {
            return;
        }

        iroha_logger::trace!(tx_count = txs.len(), "Gossiping transactions");
        self.network.broadcast(Broadcast {
            data: NetworkMessage::TransactionGossiper(Box::new(TransactionGossip::new(txs))),
        });
    }

    fn handle_transaction_gossip(&self, TransactionGossip { txs }: TransactionGossip) {
        iroha_logger::trace!(size = txs.len(), "Received new transaction gossip");

        for tx in txs {
            let (max_clock_drift, tx_limits) = {
                let state_view = self.state.world.view();
                let params = state_view.parameters();
                (params.sumeragi().max_clock_drift(), params.transaction)
            };

            match AcceptedTransaction::accept(tx, &self.chain_id, max_clock_drift, tx_limits) {
                Ok(tx) => match self.queue.push(tx, self.state.view()) {
                    Ok(()) => {}
                    Err(crate::queue::Failure {
                        tx,
                        err: crate::queue::Error::InBlockchain,
                    }) => {
                        iroha_logger::debug!(tx = %tx.as_ref().hash(), "Transaction already in blockchain, ignoring...")
                    }
                    Err(crate::queue::Failure {
                        tx,
                        err: crate::queue::Error::IsInQueue,
                    }) => {
                        iroha_logger::trace!(tx = %tx.as_ref().hash(), "Transaction already in the queue, ignoring...")
                    }
                    Err(crate::queue::Failure { tx, err }) => {
                        iroha_logger::error!(?err, tx = %tx.as_ref().hash(), "Failed to enqueue transaction.")
                    }
                },
                Err(err) => iroha_logger::error!(%err, "Transaction rejected"),
            }
        }
    }
}

/// Message for gossiping batches of transactions.
#[derive(Decode, Encode, Debug, Clone)]
pub struct TransactionGossip {
    /// Batch of transactions.
    pub txs: Vec<SignedTransaction>,
}

impl TransactionGossip {
    /// Constructor.
    pub fn new(txs: Vec<AcceptedTransaction>) -> Self {
        Self {
            // Converting into non-accepted transaction because it's not possible
            // to guarantee that the sending peer checked transaction limits
            txs: txs.into_iter().map(Into::into).collect(),
        }
    }
}
