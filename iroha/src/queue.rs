use self::config::QueueConfiguration;
use crate::prelude::*;

#[derive(Debug)]
pub struct Queue {
    pending_tx: Vec<AcceptedTransaction>,
    maximum_transactions_in_block: usize,
}

impl Queue {
    pub fn from_configuration(config: &QueueConfiguration) -> Queue {
        Queue {
            pending_tx: Vec::new(),
            maximum_transactions_in_block: config.maximum_transactions_in_block as usize,
        }
    }

    pub fn push_pending_transaction(&mut self, tx: AcceptedTransaction) {
        self.pending_tx.push(tx);
    }

    pub fn pop_pending_transactions(&mut self) -> Vec<AcceptedTransaction> {
        let pending_transactions_length = self.pending_tx.len();
        let amount_to_drain = if self.maximum_transactions_in_block > pending_transactions_length {
            pending_transactions_length
        } else {
            self.maximum_transactions_in_block
        };
        self.pending_tx.drain(..amount_to_drain).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pending_transaction() {
        let mut queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: 2,
        });
        queue.push_pending_transaction(
            RequestedTransaction::new(
                Vec::new(),
                <Account as Identifiable>::Id::new("account", "domain"),
            )
            .accept()
            .expect("Failed to create Transaction."),
        );
    }

    #[test]
    fn pop_pending_transactions() {
        let max_block_tx = 2;
        let mut queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: max_block_tx,
        });
        for _ in 0..5 {
            queue.push_pending_transaction(
                RequestedTransaction::new(
                    Vec::new(),
                    <Account as Identifiable>::Id::new("account", "domain"),
                )
                .accept()
                .expect("Failed to create Transaction."),
            );
        }
        assert_eq!(
            queue.pop_pending_transactions().len(),
            max_block_tx as usize
        )
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_derive::*;
    use serde::Deserialize;
    use std::env;

    const MAXIMUM_TRANSACTIONS_IN_BLOCK: &str = "MAXIMUM_TRANSACTIONS_IN_BLOCK";
    const DEFAULT_MAXIMUM_TRANSACTIONS_IN_BLOCK: u32 = 10;

    /// Configuration for `Queue`.
    #[derive(Clone, Deserialize, Debug)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct QueueConfiguration {
        /// The upper limit of the number of transactions per block.
        #[serde(default = "default_maximum_transactions_in_block")]
        pub maximum_transactions_in_block: u32,
    }

    impl QueueConfiguration {
        /// Load environment variables and replace predefined parameters with these variables
        /// values.
        #[log]
        pub fn load_environment(&mut self) -> Result<(), String> {
            if let Ok(max_block_tx) = env::var(MAXIMUM_TRANSACTIONS_IN_BLOCK) {
                self.maximum_transactions_in_block =
                    serde_json::from_str(&max_block_tx).map_err(|e| {
                        format!("Failed to maximum number of transactions per block: {}", e)
                    })?;
            }
            Ok(())
        }
    }

    fn default_maximum_transactions_in_block() -> u32 {
        DEFAULT_MAXIMUM_TRANSACTIONS_IN_BLOCK
    }
}
