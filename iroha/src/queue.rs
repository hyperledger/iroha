use self::config::QueueConfiguration;
use crate::prelude::*;
use iroha_data_model::prelude::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

#[derive(Debug)]
pub struct Queue {
    pending_tx_hash_queue: VecDeque<Hash>,
    pending_tx_by_hash: BTreeMap<Hash, AcceptedTransaction>,
    maximum_transactions_in_block: usize,
    maximum_transactions_in_queue: usize,
    transaction_time_to_live: Duration,
}

impl Queue {
    /// Get cloned transactions that are currently in a queue.
    pub fn pending_transactions(&self) -> PendingTransactions {
        self.pending_tx_by_hash
            .values()
            .cloned()
            .map(Transaction::from)
            .collect()
    }

    pub fn from_configuration(config: &QueueConfiguration) -> Queue {
        Queue {
            pending_tx_hash_queue: VecDeque::new(),
            pending_tx_by_hash: BTreeMap::new(),
            maximum_transactions_in_block: config.maximum_transactions_in_block as usize,
            maximum_transactions_in_queue: config.maximum_transactions_in_queue as usize,
            transaction_time_to_live: Duration::from_millis(config.transaction_time_to_live_ms),
        }
    }

    pub fn push_pending_transaction(&mut self, tx: AcceptedTransaction) -> Result<(), String> {
        if let Some(transaction) = self.pending_tx_by_hash.get_mut(&tx.hash()) {
            let mut signatures: BTreeSet<_> = transaction.signatures.iter().cloned().collect();
            let mut new_signatures: BTreeSet<_> = tx.signatures.into_iter().collect();
            signatures.append(&mut new_signatures);
            transaction.signatures = signatures.into_iter().collect();
            Ok(())
        } else if self.pending_tx_hash_queue.len() < self.maximum_transactions_in_queue {
            self.pending_tx_hash_queue.push_back(tx.hash());
            let _result = self.pending_tx_by_hash.insert(tx.hash(), tx);
            Ok(())
        } else {
            Err("The queue is full.".to_string())
        }
    }

    pub fn pop_pending_transactions(
        &mut self,
        is_leader: bool,
        world_state_view: &WorldStateView,
    ) -> Vec<AcceptedTransaction> {
        let mut output_transactions = Vec::new();
        let mut left_behind_transactions = VecDeque::new();
        let mut counter = self.maximum_transactions_in_block;
        while counter > 0 && !self.pending_tx_hash_queue.is_empty() {
            let transaction_hash = self
                .pending_tx_hash_queue
                .pop_front()
                .expect("Failed to get front transaction.");
            let transaction = self
                .pending_tx_by_hash
                .get(&transaction_hash)
                .expect("Failed to get tx by hash.");
            if !transaction.is_expired(self.transaction_time_to_live) {
                if is_leader {
                    if transaction
                        .check_signature_condition(world_state_view)
                        .map_or(false, |b| b)
                    {
                        output_transactions.push(
                            self.pending_tx_by_hash
                                .remove(&transaction_hash)
                                .expect("Failed to get tx by hash."),
                        );
                        counter -= 1;
                    } else {
                        left_behind_transactions.push_back(transaction_hash);
                    }
                } else {
                    output_transactions.push(
                        self.pending_tx_by_hash
                            .remove(&transaction_hash)
                            .expect("Failed to get tx by hash."),
                    );
                    counter -= 1;
                }
            }
        }
        left_behind_transactions.append(&mut self.pending_tx_hash_queue);
        self.pending_tx_hash_queue = left_behind_transactions;
        output_transactions
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use serde::Deserialize;
    use std::env;

    const MAXIMUM_TRANSACTIONS_IN_BLOCK: &str = "MAXIMUM_TRANSACTIONS_IN_BLOCK";
    // 2^13
    const DEFAULT_MAXIMUM_TRANSACTIONS_IN_BLOCK: u32 = 8_192;
    const TRANSACTION_TIME_TO_LIVE_MS: &str = "TRANSACTION_TIME_TO_LIVE_MS";
    // 24 hours
    const DEFAULT_TRANSACTION_TIME_TO_LIVE_MS: u64 = 24 * 60 * 60 * 1000;
    const MAXIMUM_TRANSACTIONS_IN_QUEUE: &str = "MAXIMUM_TRANSACTIONS_IN_QUEUE";
    // 2^16
    const DEFAULT_MAXIMUM_TRANSACTIONS_IN_QUEUE: u32 = 65_536;

    /// Configuration for `Queue`.
    #[derive(Copy, Clone, Deserialize, Debug)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct QueueConfiguration {
        /// The upper limit of the number of transactions per block.
        #[serde(default = "default_maximum_transactions_in_block")]
        pub maximum_transactions_in_block: u32,
        /// The upper limit of the number of transactions waiting in this queue.
        #[serde(default = "default_maximum_transactions_in_queue")]
        pub maximum_transactions_in_queue: u32,
        /// The transaction will be dropped after this time if it is still in a `Queue`.
        #[serde(default = "default_transaction_time_to_live_ms")]
        pub transaction_time_to_live_ms: u64,
    }

    impl QueueConfiguration {
        /// Load environment variables and replace predefined parameters with these variables
        /// values.
        pub fn load_environment(&mut self) -> Result<(), String> {
            if let Ok(max_block_tx) = env::var(MAXIMUM_TRANSACTIONS_IN_BLOCK) {
                self.maximum_transactions_in_block =
                    serde_json::from_str(&max_block_tx).map_err(|e| {
                        format!(
                            "Failed to parse maximum number of transactions per block: {}",
                            e
                        )
                    })?;
            }
            if let Ok(max_queue_tx) = env::var(MAXIMUM_TRANSACTIONS_IN_QUEUE) {
                self.maximum_transactions_in_queue =
                    serde_json::from_str(&max_queue_tx).map_err(|e| {
                        format!(
                            "Failed to parse maximum number of transactions in a queue: {}",
                            e
                        )
                    })?;
            }
            if let Ok(transaction_ttl_ms) = env::var(TRANSACTION_TIME_TO_LIVE_MS) {
                self.transaction_time_to_live_ms = serde_json::from_str(&transaction_ttl_ms)
                    .map_err(|e| format!("Failed to parse transaction's ttl: {}", e))?;
            }
            Ok(())
        }
    }

    fn default_maximum_transactions_in_block() -> u32 {
        DEFAULT_MAXIMUM_TRANSACTIONS_IN_BLOCK
    }

    fn default_transaction_time_to_live_ms() -> u64 {
        DEFAULT_TRANSACTION_TIME_TO_LIVE_MS
    }

    fn default_maximum_transactions_in_queue() -> u32 {
        DEFAULT_MAXIMUM_TRANSACTIONS_IN_QUEUE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::Accept;
    use std::{collections::BTreeMap, thread, time::Duration};

    #[test]
    fn push_pending_transaction() {
        let mut queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100000,
            maximum_transactions_in_queue: 100,
        });
        queue
            .push_pending_transaction(
                Transaction::new(
                    Vec::new(),
                    <Account as Identifiable>::Id::new("account", "domain"),
                    100000,
                )
                .sign(&KeyPair::generate().expect("Failed to generate keypair."))
                .expect("Failed to sign.")
                .accept()
                .expect("Failed to accept Transaction."),
            )
            .expect("Failed to push tx into queue");
    }

    #[test]
    fn push_pending_transaction_overflow() {
        let maximum_transactions_in_queue = 10;
        let mut queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100000,
            maximum_transactions_in_queue,
        });
        for _ in 0..maximum_transactions_in_queue {
            queue
                .push_pending_transaction(
                    Transaction::new(
                        Vec::new(),
                        <Account as Identifiable>::Id::new("account", "domain"),
                        100000,
                    )
                    .sign(&KeyPair::generate().expect("Failed to generate keypair."))
                    .expect("Failed to sign.")
                    .accept()
                    .expect("Failed to accept Transaction."),
                )
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }
        assert!(queue
            .push_pending_transaction(
                Transaction::new(
                    Vec::new(),
                    <Account as Identifiable>::Id::new("account", "domain"),
                    100000,
                )
                .sign(&KeyPair::generate().expect("Failed to generate keypair."))
                .expect("Failed to sign.")
                .accept()
                .expect("Failed to accept Transaction."),
            )
            .is_err());
    }

    #[test]
    fn push_multisignature_transaction() {
        let mut queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100000,
            maximum_transactions_in_queue: 100,
        });
        let transaction = Transaction::new(
            Vec::new(),
            <Account as Identifiable>::Id::new("account", "domain"),
            100000,
        );
        queue
            .push_pending_transaction(
                transaction
                    .clone()
                    .sign(&KeyPair::generate().expect("Failed to generate keypair."))
                    .expect("Failed to sign.")
                    .accept()
                    .expect("Failed to accept Transaction."),
            )
            .expect("Failed to push tx into queue");
        queue
            .push_pending_transaction(
                transaction
                    .clone()
                    .sign(&KeyPair::generate().expect("Failed to generate keypair."))
                    .expect("Failed to sign.")
                    .accept()
                    .expect("Failed to accept Transaction."),
            )
            .expect("Failed to push tx into queue");
        assert_eq!(queue.pending_tx_hash_queue.len(), 1);
        let signature_count = queue
            .pending_tx_by_hash
            .get(
                queue
                    .pending_tx_hash_queue
                    .front()
                    .expect("Failed to get first transaction."),
            )
            .expect("Failed to get tx by hash.")
            .signatures
            .len();
        assert_eq!(signature_count, 2);
    }

    #[test]
    fn pop_pending_transactions() {
        let max_block_tx = 2;
        let mut queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 100000,
            maximum_transactions_in_queue: 100,
        });
        for _ in 0..5 {
            queue
                .push_pending_transaction(
                    Transaction::new(
                        Vec::new(),
                        <Account as Identifiable>::Id::new("account", "domain"),
                        100000,
                    )
                    .sign(&KeyPair::generate().expect("Failed to generate keypair."))
                    .expect("Failed to sign.")
                    .accept()
                    .expect("Failed to accept Transaction."),
                )
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            queue
                .pop_pending_transactions(false, &WorldStateView::new(World::new()))
                .len(),
            max_block_tx as usize
        )
    }

    #[test]
    fn pop_pending_transactions_with_timeout() {
        let max_block_tx = 6;
        let mut queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 200,
            maximum_transactions_in_queue: 100,
        });
        for _ in 0..(max_block_tx - 1) {
            queue
                .push_pending_transaction(
                    Transaction::new(
                        Vec::new(),
                        <Account as Identifiable>::Id::new("account", "domain"),
                        100,
                    )
                    .sign(&KeyPair::generate().expect("Failed to generate keypair."))
                    .expect("Failed to sign.")
                    .accept()
                    .expect("Failed to accept Transaction."),
                )
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }
        queue
            .push_pending_transaction(
                Transaction::new(
                    Vec::new(),
                    <Account as Identifiable>::Id::new("account", "domain"),
                    200,
                )
                .sign(&KeyPair::generate().expect("Failed to generate keypair."))
                .expect("Failed to sign.")
                .accept()
                .expect("Failed to accept Transaction."),
            )
            .expect("Failed to push tx into queue");
        std::thread::sleep(Duration::from_millis(101));
        assert_eq!(
            queue
                .pop_pending_transactions(false, &WorldStateView::new(World::new()))
                .len(),
            1
        );
        queue
            .push_pending_transaction(
                Transaction::new(
                    Vec::new(),
                    <Account as Identifiable>::Id::new("account", "domain"),
                    300,
                )
                .sign(&KeyPair::generate().expect("Failed to generate keypair."))
                .expect("Failed to sign.")
                .accept()
                .expect("Failed to accept Transaction."),
            )
            .expect("Failed to push tx into queue");
        std::thread::sleep(Duration::from_millis(201));
        assert_eq!(
            queue
                .pop_pending_transactions(false, &WorldStateView::new(World::new()))
                .len(),
            0
        );
    }

    #[test]
    fn pop_pending_transactions_on_leader() {
        let max_block_tx = 2;
        let mut queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 100000,
            maximum_transactions_in_queue: 100,
        });
        let alice_key_1 = KeyPair::generate().expect("Failed to generate keypair.");
        let alice_key_2 = KeyPair::generate().expect("Failed to generate keypair.");
        let bob_key = KeyPair::generate().expect("Failed to generate keypair.");
        let alice_transaction_1 = Transaction::new(
            Vec::new(),
            <Account as Identifiable>::Id::new("alice", "wonderland"),
            100000,
        )
        .sign(&alice_key_1)
        .expect("Failed to sign.")
        .accept()
        .expect("Failed to accept Transaction.");
        thread::sleep(Duration::from_millis(10));
        let alice_transaction_2 = Transaction::new(
            Vec::new(),
            <Account as Identifiable>::Id::new("alice", "wonderland"),
            100000,
        )
        .sign(&alice_key_2)
        .expect("Failed to sign.")
        .accept()
        .expect("Failed to accept Transaction.");
        thread::sleep(Duration::from_millis(10));
        let alice_transaction_3 = Transaction::new(
            Vec::new(),
            <Account as Identifiable>::Id::new("alice", "wonderland"),
            100000,
        )
        .sign(&bob_key)
        .expect("Failed to sign.")
        .accept()
        .expect("Failed to accept Transaction.");
        thread::sleep(Duration::from_millis(10));
        let alice_transaction_4 = Transaction::new(
            Vec::new(),
            <Account as Identifiable>::Id::new("alice", "wonderland"),
            100000,
        )
        .sign(&alice_key_1)
        .expect("Failed to sign.")
        .accept()
        .expect("Failed to accept Transaction.");
        queue
            .push_pending_transaction(alice_transaction_1.clone())
            .expect("Failed to push tx into queue");
        queue
            .push_pending_transaction(alice_transaction_2.clone())
            .expect("Failed to push tx into queue");
        queue
            .push_pending_transaction(alice_transaction_3)
            .expect("Failed to push tx into queue");
        queue
            .push_pending_transaction(alice_transaction_4.clone())
            .expect("Failed to push tx into queue");
        let mut domain = Domain::new("wonderland");
        let account_id = AccountId::new("alice", "wonderland");
        let mut account = Account::new(account_id.clone());
        account.signatories.push(alice_key_1.public_key);
        account.signatories.push(alice_key_2.public_key);
        let _result = domain.accounts.insert(account_id, account);
        let mut domains = BTreeMap::new();
        let _result = domains.insert("wonderland".to_string(), domain);
        let world_state_view = WorldStateView::new(World::with(domains, BTreeSet::new()));
        let output_transactions: Vec<_> = queue
            .pop_pending_transactions(true, &world_state_view)
            .into_iter()
            .map(|tx| tx.hash())
            .collect();
        assert_eq!(
            output_transactions,
            vec![alice_transaction_1.hash(), alice_transaction_2.hash()]
        );
        assert_eq!(queue.pending_tx_hash_queue.len(), 2);
        let output_transactions: Vec<_> = queue
            .pop_pending_transactions(true, &world_state_view)
            .into_iter()
            .map(|tx| tx.hash())
            .collect();
        assert_eq!(output_transactions, vec![alice_transaction_4.hash()]);
        assert_eq!(queue.pending_tx_hash_queue.len(), 1);
    }
}
