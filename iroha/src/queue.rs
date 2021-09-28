//! Module with queue actor

use std::time::Duration;

use crossbeam_queue::ArrayQueue;
use dashmap::{mapref::entry::Entry, DashMap};
use eyre::Result;
use iroha_data_model::prelude::*;

use self::config::QueueConfiguration;
use crate::{prelude::*, wsv::WorldTrait};

/// Lockfree queue for transactions
///
/// Multiple producers, single consumer
#[derive(Debug)]
pub struct Queue {
    queue: ArrayQueue<Hash>,
    txs: DashMap<Hash, VersionedAcceptedTransaction>,
    /// Length of dashmap.
    ///
    /// DashMap right now just iterates over itself and calculates its length like this:
    /// self.txs.iter().len()
    txs_in_block: usize,
    max_txs: usize,
    ttl: Duration,
}

impl Queue {
    /// Makes queue from configuration
    pub fn from_configuration(cfg: &QueueConfiguration) -> Self {
        Self {
            queue: ArrayQueue::new(cfg.maximum_transactions_in_queue as usize),
            txs: DashMap::new(),
            max_txs: cfg.maximum_transactions_in_queue as usize,
            txs_in_block: cfg.maximum_transactions_in_block as usize,
            ttl: Duration::from_millis(cfg.transaction_time_to_live_ms),
        }
    }

    /// Returns all pending transactions.
    pub fn all_transactions(&'_ self) -> Vec<VersionedAcceptedTransaction> {
        self.txs.iter().map(|e| e.value().clone()).collect()
    }

    /// Pushes transaction into queue
    /// # Errors
    /// Returns transaction if queue is full
    #[allow(
        clippy::unwrap_in_result,
        clippy::expect_used,
        clippy::missing_panics_doc
    )]
    pub fn push<W: WorldTrait>(
        &self,
        tx: VersionedAcceptedTransaction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), VersionedAcceptedTransaction> {
        if tx.is_expired(self.ttl) {
            iroha_logger::warn!("Transaction expired");
            return Err(tx);
        }
        if tx.is_in_blockchain(wsv) {
            iroha_logger::warn!("Transaction is already applied");
            return Err(tx);
        }

        if self.txs.len() >= self.max_txs {
            iroha_logger::warn!("Transaction queue is full");
            return Err(tx);
        }

        let hash = tx.hash();
        let entry = match self.txs.entry(hash) {
            Entry::Occupied(mut old_tx) => {
                // MST case
                old_tx
                    .get_mut()
                    .as_mut_inner_v1()
                    .signatures
                    .append(&mut tx.into_inner_v1().signatures);
                return Ok(());
            }
            Entry::Vacant(entry) => entry,
        };

        entry.insert(tx);
        self.queue.push(hash).map_err(|hash| {
            self.txs
                .remove(&hash)
                .expect("Inserted just before match")
                .1
        })
    }

    /// Pops single transaction.
    ///
    /// Records unsigned transaction in seen.
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    fn pop<W: WorldTrait>(
        &self,
        wsv: &WorldStateView<W>,
        seen: &mut Vec<Hash>,
    ) -> Option<VersionedAcceptedTransaction> {
        loop {
            let hash = self.queue.pop()?;
            let entry = match self.txs.entry(hash) {
                Entry::Occupied(entry) => entry,
                Entry::Vacant(_) => unreachable!(),
            };

            if entry.get().is_expired(self.ttl) {
                iroha_logger::warn!("Transaction expired");
                entry.remove_entry();
                continue;
            }
            if entry.get().is_in_blockchain(wsv) {
                entry.remove_entry();
                continue;
            }

            let sig_condition = match entry.get().check_signature_condition(wsv) {
                Ok(condition) => condition,
                Err(error) => {
                    iroha_logger::error!(%error, "Not passed signature condition");
                    entry.remove_entry();
                    continue;
                }
            };

            seen.push(hash);

            if sig_condition {
                return Some(entry.remove());
            }
        }
    }

    /// Gets transactions till they fill whole block or till the end of queue.
    ///
    /// BEWARE: Shouldn't be called concurently, as it can become inconsistent
    #[allow(clippy::missing_panics_doc, clippy::unwrap_in_result)]
    pub fn get_transactions_for_block<W: WorldTrait>(
        &self,
        wsv: &WorldStateView<W>,
    ) -> Vec<VersionedAcceptedTransaction> {
        let mut seen = Vec::new();

        let out = std::iter::repeat_with(|| self.pop(wsv, &mut seen))
            .take_while(Option::is_some)
            .map(Option::unwrap)
            .take(self.txs_in_block)
            .collect::<Vec<_>>();

        #[allow(clippy::expect_used)]
        seen.into_iter()
            .try_for_each(|hash| self.queue.push(hash))
            .expect("As we never exceed the number of transactions pending");

        out
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
    #![allow(clippy::restriction, clippy::all, clippy::pedantic)]

    use std::{
        collections::{BTreeMap, BTreeSet},
        thread,
        time::Duration,
    };

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

        let message = std::iter::repeat_with(rand::random::<char>)
            .take(16)
            .collect();
        let tx = Transaction::new(
            vec![FailBox { message }.into()],
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
    fn push_available_tx() {
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
        });
        let wsv = WorldStateView::new(world_with_test_domains(
            KeyPair::generate().unwrap().public_key,
        ));

        queue
            .push(accepted_tx("account", "domain", 100_000, None), &wsv)
            .expect("Failed to push tx into queue");
    }

    #[test]
    fn push_available_tx_overflow() {
        let max_max_txs = 10;
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: max_max_txs,
        });
        let wsv = WorldStateView::new(world_with_test_domains(
            KeyPair::generate().unwrap().public_key,
        ));

        for _ in 0..max_max_txs {
            queue
                .push(accepted_tx("account", "domain", 100_000, None), &wsv)
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        assert!(queue
            .push(accepted_tx("account", "domain", 100_000, None), &wsv)
            .is_err());
    }

    #[test]
    fn push_multisignature_tx() {
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
        });
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
        let wsv = WorldStateView::new(world_with_test_domains(
            KeyPair::generate().unwrap().public_key,
        ));

        queue.push(get_tx(), &wsv).unwrap();
        queue.push(get_tx(), &wsv).unwrap();

        assert_eq!(queue.queue.len(), 1);
        let signature_count = queue
            .txs
            .get(&queue.queue.pop().unwrap())
            .unwrap()
            .as_inner_v1()
            .signatures
            .len();
        assert_eq!(signature_count, 2);
    }

    #[test]
    fn get_available_txs() {
        let max_block_tx = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = WorldStateView::new(world_with_test_domains(alice_key.public_key.clone()));
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
        });
        for _ in 0..5 {
            queue
                .push(
                    accepted_tx("alice", "wonderland", 100_000, Some(&alice_key)),
                    &wsv,
                )
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        let available = queue.get_transactions_for_block(&wsv);
        assert_eq!(available.len(), max_block_tx as usize);
    }

    #[test]
    fn drop_tx_if_in_blockchain() {
        let max_block_tx = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = WorldStateView::new(world_with_test_domains(alice_key.public_key.clone()));
        let tx = accepted_tx("alice", "wonderland", 100_000, Some(&alice_key));
        wsv.transactions.insert(tx.hash());
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
        });
        assert!(queue.push(tx, &wsv).is_err());
        assert_eq!(queue.get_transactions_for_block(&wsv).len(), 0);
    }

    #[test]
    fn get_available_txs_with_timeout() {
        let max_block_tx = 6;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = WorldStateView::new(world_with_test_domains(alice_key.public_key.clone()));
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 200,
            maximum_transactions_in_queue: 100,
        });
        for _ in 0..(max_block_tx - 1) {
            queue
                .push(
                    accepted_tx("alice", "wonderland", 100, Some(&alice_key)),
                    &wsv,
                )
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        queue
            .push(
                accepted_tx("alice", "wonderland", 200, Some(&alice_key)),
                &wsv,
            )
            .expect("Failed to push tx into queue");
        std::thread::sleep(Duration::from_millis(101));
        assert_eq!(queue.get_transactions_for_block(&wsv).len(), 1);

        let wsv = WorldStateView::new(World::new());

        queue
            .push(
                accepted_tx("alice", "wonderland", 300, Some(&alice_key)),
                &wsv,
            )
            .expect("Failed to push tx into queue");
        std::thread::sleep(Duration::from_millis(101));
        assert_eq!(queue.get_transactions_for_block(&wsv).len(), 0);
    }

    #[test]
    fn get_available_txs_on_leader() {
        let max_block_tx = 2;

        let alice_key_1 = KeyPair::generate().unwrap();
        let alice_key_2 = KeyPair::generate().unwrap();

        let mut domain = Domain::new("wonderland");
        let account_id = AccountId::new("alice", "wonderland");
        let mut account = Account::new(account_id.clone());
        account.signatories.push(alice_key_1.public_key.clone());
        account.signatories.push(alice_key_2.public_key.clone());
        domain.accounts.insert(account_id, account);
        let mut domains = BTreeMap::new();
        domains.insert("wonderland".to_string(), domain);

        let wsv = WorldStateView::new(World::with(domains, BTreeSet::new()));
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
        });

        let bob_key = KeyPair::generate().expect("Failed to generate keypair.");
        let alice_tx_1 = accepted_tx("alice", "wonderland", 1000, Some(&alice_key_1));
        thread::sleep(Duration::from_millis(10));
        let alice_tx_2 = accepted_tx("alice", "wonderland", 1000, Some(&alice_key_2));
        thread::sleep(Duration::from_millis(10));
        let alice_tx_3 = accepted_tx("alice", "wonderland", 1000, Some(&bob_key));
        thread::sleep(Duration::from_millis(10));
        let alice_tx_4 = accepted_tx("alice", "wonderland", 1000, Some(&alice_key_1));
        queue.push(alice_tx_1.clone(), &wsv).unwrap();
        queue.push(alice_tx_2.clone(), &wsv).unwrap();
        queue.push(alice_tx_3, &wsv).unwrap();
        queue.push(alice_tx_4, &wsv).unwrap();
        let output_txs: Vec<_> = queue
            .get_transactions_for_block(&wsv)
            .into_iter()
            .map(|tx| tx.hash())
            .collect::<Vec<_>>();

        assert_eq!(output_txs, vec![alice_tx_1.hash(), alice_tx_2.hash()]);
    }

    #[test]
    fn transactions_available_after_pop() {
        let max_block_tx = 2;

        let alice_key_1 = KeyPair::generate().unwrap();
        let alice_key_2 = KeyPair::generate().unwrap();

        let mut domain = Domain::new("wonderland");
        let account_id = AccountId::new("alice", "wonderland");
        let mut account = Account::new(account_id.clone());
        account.signatories.push(alice_key_1.public_key.clone());
        account.signatories.push(alice_key_2.public_key.clone());
        domain.accounts.insert(account_id, account);
        let mut domains = BTreeMap::new();
        domains.insert("wonderland".to_string(), domain);

        let wsv = WorldStateView::new(World::with(domains, BTreeSet::new()));
        let queue = Queue::from_configuration(&QueueConfiguration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
        });

        let a = queue
            .pop_avaliable(true, &wsv)
            .into_iter()
            .map(|tx| tx.hash())
            .collect::<Vec<_>>();
        let b = queue
            .pop_avaliable(true, &wsv)
            .into_iter()
            .map(|tx| tx.hash())
            .collect::<Vec<_>>();

        assert_eq!(a, b);
    }
}
