use self::config::QueueConfiguration;
use crate::prelude::*;
use std::time::Duration;

#[derive(Debug)]
pub struct Queue {
    pending_tx: Vec<AcceptedTransaction>,
    maximum_transactions_in_block: usize,
    maximum_transactions_in_queue: usize,
    transaction_time_to_live: Duration,
}

impl Queue {
    pub fn from_configuration(config: &QueueConfiguration) -> Queue {
        Queue {
            pending_tx: Vec::new(),
            maximum_transactions_in_block: config.maximum_transactions_in_block as usize,
            maximum_transactions_in_queue: config.maximum_transactions_in_queue as usize,
            transaction_time_to_live: Duration::from_millis(config.transaction_time_to_live_ms),
        }
    }

    pub fn push_pending_transaction(&mut self, tx: AcceptedTransaction) -> Result<(), String> {
        if self.pending_tx.len() < self.maximum_transactions_in_queue {
            self.pending_tx.push(tx);
            Ok(())
        } else {
            Err("The queue is full.".to_string())
        }
    }

    pub fn pop_pending_transactions(&mut self) -> Vec<AcceptedTransaction> {
        self.pending_tx = self
            .pending_tx
            .iter()
            .cloned()
            .filter(|transaction| !transaction.is_expired(self.transaction_time_to_live))
            .collect();
        let pending_transactions_length = self.pending_tx.len();
        let amount_to_drain = if self.maximum_transactions_in_block > pending_transactions_length {
            pending_transactions_length
        } else {
            self.maximum_transactions_in_block
        };
        self.pending_tx.drain(..amount_to_drain).collect()
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
    use iroha_data_model::prelude::*;

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
        }
        assert_eq!(
            queue.pop_pending_transactions().len(),
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
        assert_eq!(queue.pop_pending_transactions().len(), 1);
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
        assert_eq!(queue.pop_pending_transactions().len(), 0);
    }
}
