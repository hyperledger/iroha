//! Module with queue actor

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::Debug,
    sync::Arc,
    time::Duration,
};

use iroha_actor::{broker::*, prelude::*, Context as ActorContext};
use iroha_data_model::prelude::*;
use iroha_error::{error, Result};

use self::config::QueueConfiguration;
use crate::{prelude::*, wsv::WorldTrait};

/// Transaction queue
#[derive(Debug)]
pub struct Queue<W: WorldTrait> {
    pending_tx_hash_queue: VecDeque<Hash>,
    pending_tx_by_hash: BTreeMap<Hash, VersionedAcceptedTransaction>,
    max_txs_in_block: usize,
    max_txs_in_queue: usize,
    tx_time_to_live: Duration,
    wsv: Arc<WorldStateView<W>>,
    broker: Broker,
}

/// Queue trait
pub trait QueueTrait:
    Actor
    + Handler<PopPendingTransactions, Result = Vec<VersionedAcceptedTransaction>>
    + Handler<VersionedAcceptedTransaction, Result = ()>
    + Handler<GetPendingTransactions, Result = PendingTransactions>
    + Debug
{
    /// World for checking if tx is in blockchain and for checking signatures
    type World: WorldTrait;

    /// Makes queue from configuration and WSV
    fn from_configuration(
        cfg: &QueueConfiguration,
        wsv: Arc<WorldStateView<Self::World>>,
        broker: Broker,
    ) -> Self;
}

impl<W: WorldTrait> QueueTrait for Queue<W> {
    type World = W;

    fn from_configuration(
        cfg: &QueueConfiguration,
        wsv: Arc<WorldStateView<W>>,
        broker: Broker,
    ) -> Self {
        Self {
            pending_tx_hash_queue: VecDeque::new(),
            pending_tx_by_hash: BTreeMap::new(),
            max_txs_in_block: cfg.maximum_transactions_in_block as usize,
            max_txs_in_queue: cfg.maximum_transactions_in_queue as usize,
            tx_time_to_live: Duration::from_millis(cfg.transaction_time_to_live_ms),
            wsv,
            broker,
        }
    }
}

/// Pops pending transactions from queue
#[derive(Debug, Clone, Copy, Message)]
#[message(result = "Vec<VersionedAcceptedTransaction>")]
pub struct PopPendingTransactions {
    /// Is peer leader?
    pub is_leader: bool,
}

/// Gets pending txs without modifying a queue
#[derive(Debug, Clone, Copy, Default, Message)]
#[message(result = "PendingTransactions")]
pub struct GetPendingTransactions;

#[async_trait::async_trait]
impl<W: WorldTrait> Actor for Queue<W> {
    async fn on_start(&mut self, ctx: &mut ActorContext<Self>) {
        self.broker
            .subscribe::<VersionedAcceptedTransaction, _>(ctx);
    }
}

#[async_trait::async_trait]
impl<W: WorldTrait> Handler<PopPendingTransactions> for Queue<W> {
    type Result = Vec<VersionedAcceptedTransaction>;
    async fn handle(
        &mut self,
        PopPendingTransactions { is_leader }: PopPendingTransactions,
    ) -> Self::Result {
        self.get_pending_txs(is_leader)
    }
}

#[async_trait::async_trait]
impl<W: WorldTrait> Handler<VersionedAcceptedTransaction> for Queue<W> {
    type Result = ();
    #[iroha_logger::log(skip(self, tx))]
    async fn handle(&mut self, tx: VersionedAcceptedTransaction) {
        if let Err(error) = self.push_pending_tx(tx) {
            iroha_logger::error!(%error, "Failed to put tx into queue of pending tx")
        }
    }
}

#[async_trait::async_trait]
impl<W: WorldTrait> Handler<GetPendingTransactions> for Queue<W> {
    type Result = PendingTransactions;
    async fn handle(
        &mut self,
        GetPendingTransactions: GetPendingTransactions,
    ) -> PendingTransactions {
        self.pending_txs()
    }
}

impl<W: WorldTrait> Queue<W> {
    /// Get cloned txs that are currently in a queue.
    pub fn pending_txs(&self) -> PendingTransactions {
        self.pending_tx_by_hash
            .values()
            .cloned()
            .map(VersionedAcceptedTransaction::into_inner_v1)
            .map(Transaction::from)
            .collect()
    }

    /// Puts new tx into queue.
    /// # Errors
    /// Returns error if queue is full.
    pub fn push_pending_tx(&mut self, tx: VersionedAcceptedTransaction) -> Result<()> {
        if let Some(transaction) = self.pending_tx_by_hash.get_mut(&tx.hash()) {
            let mut signatures: BTreeSet<_> = transaction
                .as_inner_v1()
                .signatures
                .iter()
                .cloned()
                .collect();
            let mut new_signatures: BTreeSet<_> =
                tx.into_inner_v1().signatures.into_iter().collect();
            signatures.append(&mut new_signatures);
            transaction.as_mut_inner_v1().signatures = signatures.into_iter().collect();
            Ok(())
        } else if self.pending_tx_hash_queue.len() < self.max_txs_in_queue {
            self.pending_tx_hash_queue.push_back(tx.hash());
            let _result = self.pending_tx_by_hash.insert(tx.hash(), tx);
            Ok(())
        } else {
            Err(error!("The queue is full."))
        }
    }

    /// Gets at most `max_txs_in_block` number of transactions, but does not drop them out of the queue.
    /// Drops only the transactions that have reached their TTL or are already in blockchain.
    /// For MST transactions if on leader, waits for them to gather enough signatures before, showing them as output of this function.
    ///
    /// The reason for not dropping transaction when getting them, is that in the case of a view change this peer might become a leader,
    /// or might need to forward transaction to the leader to check if the leader is not faulty.
    /// If there is no view change and the block is committed then the transactions will simply drop because they are in a blockchain already.
    #[allow(clippy::expect_used)]
    pub fn get_pending_txs(&mut self, is_leader: bool) -> Vec<VersionedAcceptedTransaction> {
        let mut output_txs = Vec::new();
        let mut left_behind_txs = VecDeque::new();
        let mut counter = self.max_txs_in_block;

        while counter > 0 && !self.pending_tx_hash_queue.is_empty() {
            let tx_hash = self
                .pending_tx_hash_queue
                .pop_front()
                .expect("Unreachable, as queue not empty");
            let tx = &self.pending_tx_by_hash[&tx_hash];

            let expired = tx.is_expired(self.tx_time_to_live);

            if expired {
                iroha_logger::warn!("Transaction with hash {} dropped due to expired TTL. This can happen either due to signature condition being not satisfied in time or too many transactions in the queue.", tx_hash)
            }

            if expired || tx.is_in_blockchain(&*self.wsv) {
                self.pending_tx_by_hash
                    .remove(&tx_hash)
                    .expect("Should always be present, as contained in queue");
                continue;
            }

            let signature_condition_passed = match tx.check_signature_condition(&*self.wsv) {
                Ok(passed) => passed,
                Err(e) => {
                    iroha_logger::error!(%e, "Not passed signature");
                    self.pending_tx_by_hash
                        .remove(&tx_hash)
                        .expect("Should always be present, as contained in queue");
                    continue;
                }
            };

            if !is_leader || signature_condition_passed {
                output_txs.push(self.pending_tx_by_hash[&tx_hash].clone());
                counter -= 1;
            }

            left_behind_txs.push_back(tx_hash);
        }

        left_behind_txs.append(&mut self.pending_tx_hash_queue);
        self.pending_tx_hash_queue = left_behind_txs;

        output_txs
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use serde::{Deserialize, Serialize};

    const DEFAULT_MAXIMUM_TRANSACTIONS_IN_BLOCK: u32 = 2_u32.pow(13);
    // 24 hours
    const DEFAULT_TRANSACTION_TIME_TO_LIVE_MS: u64 = 24 * 60 * 60 * 1000;
    const DEFAULT_MAXIMUM_TRANSACTIONS_IN_QUEUE: u32 = 2_u32.pow(16);

    /// Configuration for `Queue`.
    #[derive(Copy, Clone, Deserialize, Serialize, Debug, Configurable)]
    #[serde(rename_all = "UPPERCASE")]
    #[serde(default)]
    #[config(env_prefix = "QUEUE_")]
    pub struct QueueConfiguration {
        /// The upper limit of the number of transactions per block.
        pub maximum_transactions_in_block: u32,
        /// The upper limit of the number of transactions waiting in this queue.
        pub maximum_transactions_in_queue: u32,
        /// The transaction will be dropped after this time if it is still in a `Queue`.
        pub transaction_time_to_live_ms: u64,
    }

    impl Default for QueueConfiguration {
        fn default() -> Self {
            Self {
                maximum_transactions_in_block: DEFAULT_MAXIMUM_TRANSACTIONS_IN_BLOCK,
                maximum_transactions_in_queue: DEFAULT_MAXIMUM_TRANSACTIONS_IN_QUEUE,
                transaction_time_to_live_ms: DEFAULT_TRANSACTION_TIME_TO_LIVE_MS,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::{thread, time::Duration};

    use iroha_data_model::{domain::DomainsMap, peer::PeersIds};

    use super::*;
    use crate::wsv::World;

    fn accepted_tx(
        account: &str,
        domain: &str,
        proposed_ttl_ms: u64,
        key: Option<&KeyPair>,
    ) -> VersionedAcceptedTransaction {
        let key = key
            .cloned()
            .unwrap_or_else(|| KeyPair::generate().expect("Failed to generate keypair."));

        let tx = Transaction::new(
            Vec::new(),
            <Account as Identifiable>::Id::new(account, domain),
            proposed_ttl_ms,
        )
        .sign(&key)
        .expect("Failed to sign.");
        VersionedAcceptedTransaction::from_transaction(tx, 4096)
            .expect("Failed to accept Transaction.")
    }

    pub fn world_with_test_domains(public_key: PublicKey) -> World {
        let domains = DomainsMap::new();
        let mut domain = Domain::new("wonderland");
        let account_id = AccountId::new("alice", "wonderland");
        let mut account = Account::new(account_id.clone());
        account.signatories.push(public_key);
        domain.accounts.insert(account_id, account);
        domains.insert("wonderland".to_string(), domain);
        World::with(domains, PeersIds::new())
    }

    #[test]
    fn push_pending_tx() {
        let mut queue = Queue::<World>::from_configuration(
            &QueueConfiguration {
                maximum_transactions_in_block: 2,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: 100,
            },
            Arc::default(),
            Broker::new(),
        );

        queue
            .push_pending_tx(accepted_tx("account", "domain", 100_000, None))
            .expect("Failed to push tx into queue");
    }

    #[test]
    fn push_pending_tx_overflow() {
        let max_txs_in_queue = 10;
        let mut queue = Queue::<World>::from_configuration(
            &QueueConfiguration {
                maximum_transactions_in_block: 2,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: max_txs_in_queue,
            },
            Arc::default(),
            Broker::new(),
        );
        for _ in 0..max_txs_in_queue {
            queue
                .push_pending_tx(accepted_tx("account", "domain", 100_000, None))
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        assert!(queue
            .push_pending_tx(accepted_tx("account", "domain", 100_000, None))
            .is_err());
    }

    #[test]
    fn push_multisignature_tx() {
        let mut queue = Queue::<World>::from_configuration(
            &QueueConfiguration {
                maximum_transactions_in_block: 2,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: 100,
            },
            Arc::default(),
            Broker::new(),
        );
        let tx = Transaction::new(
            Vec::new(),
            <Account as Identifiable>::Id::new("account", "domain"),
            100_000,
        );
        let get_tx = || {
            VersionedAcceptedTransaction::from_transaction(
                tx.clone()
                    .sign(&KeyPair::generate().expect("Failed to generate keypair."))
                    .expect("Failed to sign."),
                4096,
            )
            .expect("Failed to accept Transaction.")
        };

        queue
            .push_pending_tx(get_tx())
            .expect("Failed to push tx into queue");

        queue
            .push_pending_tx(get_tx())
            .expect("Failed to push tx into queue");

        assert_eq!(queue.pending_tx_hash_queue.len(), 1);
        let signature_count = queue
            .pending_tx_by_hash
            .get(
                queue
                    .pending_tx_hash_queue
                    .front()
                    .expect("Failed to get first tx."),
            )
            .expect("Failed to get tx by hash.")
            .as_inner_v1()
            .signatures
            .len();
        assert_eq!(signature_count, 2);
    }

    #[test]
    fn get_pending_txs() {
        let max_block_tx = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let mut queue = Queue::<World>::from_configuration(
            &QueueConfiguration {
                maximum_transactions_in_block: max_block_tx,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: 100,
            },
            Arc::new(WorldStateView::new(world_with_test_domains(
                alice_key.public_key.clone(),
            ))),
            Broker::new(),
        );
        for _ in 0..5 {
            queue
                .push_pending_tx(accepted_tx(
                    "alice",
                    "wonderland",
                    100_000,
                    Some(&alice_key),
                ))
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(queue.get_pending_txs(false).len(), max_block_tx as usize)
    }

    #[test]
    fn drop_tx_if_in_blockchain() {
        let max_block_tx = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let world_state_view =
            WorldStateView::new(world_with_test_domains(alice_key.public_key.clone()));
        let tx = accepted_tx("alice", "wonderland", 100_000, Some(&alice_key));
        let _ = world_state_view.transactions.insert(tx.hash());
        let mut queue = Queue::<World>::from_configuration(
            &QueueConfiguration {
                maximum_transactions_in_block: max_block_tx,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: 100,
            },
            Arc::new(world_state_view),
            Broker::new(),
        );
        queue
            .push_pending_tx(tx)
            .expect("Failed to push tx into queue");
        assert_eq!(queue.get_pending_txs(false).len(), 0);
    }

    #[test]
    fn get_pending_txs_with_timeout() {
        let max_block_tx = 6;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let mut queue = Queue::<World>::from_configuration(
            &QueueConfiguration {
                maximum_transactions_in_block: max_block_tx,
                transaction_time_to_live_ms: 200,
                maximum_transactions_in_queue: 100,
            },
            Arc::new(WorldStateView::new(world_with_test_domains(
                alice_key.public_key.clone(),
            ))),
            Broker::new(),
        );
        for _ in 0..(max_block_tx - 1) {
            queue
                .push_pending_tx(accepted_tx("alice", "wonderland", 100, Some(&alice_key)))
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        queue
            .push_pending_tx(accepted_tx("alice", "wonderland", 200, Some(&alice_key)))
            .expect("Failed to push tx into queue");
        std::thread::sleep(Duration::from_millis(101));
        assert_eq!(queue.get_pending_txs(false).len(), 1);

        queue.wsv = Arc::new(WorldStateView::new(World::new()));

        queue
            .push_pending_tx(accepted_tx("alice", "wonderland", 300, Some(&alice_key)))
            .expect("Failed to push tx into queue");
        std::thread::sleep(Duration::from_millis(101));
        assert_eq!(queue.get_pending_txs(false).len(), 0);
    }

    #[test]
    fn get_pending_txs_on_leader() {
        let max_block_tx = 2;

        let alice_key_1 = KeyPair::generate().expect("Failed to generate keypair.");
        let alice_key_2 = KeyPair::generate().expect("Failed to generate keypair.");
        let mut domain = Domain::new("wonderland");
        let account_id = AccountId::new("alice", "wonderland");
        let mut account = Account::new(account_id.clone());
        account.signatories.push(alice_key_1.public_key.clone());
        account.signatories.push(alice_key_2.public_key.clone());
        let _result = domain.accounts.insert(account_id, account);
        let mut domains = BTreeMap::new();
        let _result = domains.insert("wonderland".to_string(), domain);

        let world_state_view = WorldStateView::new(World::with(domains, BTreeSet::new()));
        let mut queue = Queue::from_configuration(
            &QueueConfiguration {
                maximum_transactions_in_block: max_block_tx,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: 100,
            },
            Arc::new(world_state_view),
            Broker::new(),
        );

        let bob_key = KeyPair::generate().expect("Failed to generate keypair.");
        let alice_tx_1 = accepted_tx("alice", "wonderland", 100_000, Some(&alice_key_1));
        thread::sleep(Duration::from_millis(10));
        let alice_tx_2 = accepted_tx("alice", "wonderland", 100_000, Some(&alice_key_2));
        thread::sleep(Duration::from_millis(10));
        let alice_tx_3 = accepted_tx("alice", "wonderland", 100_000, Some(&bob_key));
        thread::sleep(Duration::from_millis(10));
        let alice_tx_4 = accepted_tx("alice", "wonderland", 100_000, Some(&alice_key_1));
        queue
            .push_pending_tx(alice_tx_1.clone())
            .expect("Failed to push tx into queue");
        queue
            .push_pending_tx(alice_tx_2.clone())
            .expect("Failed to push tx into queue");
        queue
            .push_pending_tx(alice_tx_3)
            .expect("Failed to push tx into queue");
        queue
            .push_pending_tx(alice_tx_4)
            .expect("Failed to push tx into queue");
        let output_txs: Vec<_> = queue
            .get_pending_txs(true)
            .into_iter()
            .map(|tx| tx.hash())
            .collect();
        assert_eq!(output_txs, vec![alice_tx_1.hash(), alice_tx_2.hash()]);
        assert_eq!(queue.pending_tx_hash_queue.len(), 4);
    }
}
