//! Module with queue actor
#![allow(clippy::expect_used)]

use std::{sync::Arc, time::Duration};

use crossbeam_queue::ArrayQueue;
use dashmap::{mapref::entry::Entry, DashMap};
use eyre::{Report, Result};
use iroha_crypto::HashOf;
use iroha_data_model::transaction::prelude::*;
use rand::seq::IteratorRandom;
use thiserror::Error;

pub use self::config::Configuration;
use crate::{prelude::*, wsv::WorldTrait};

/// Lockfree queue for transactions
///
/// Multiple producers, single consumer
#[derive(Debug)]
pub struct Queue<W: WorldTrait> {
    queue: ArrayQueue<HashOf<VersionedTransaction>>,
    txs: DashMap<HashOf<VersionedTransaction>, VersionedAcceptedTransaction>,
    /// Length of dashmap.
    ///
    /// DashMap right now just iterates over itself and calculates its length like this:
    /// self.txs.iter().len()
    txs_in_block: usize,
    max_txs: usize,
    ttl: Duration,
    future_threshold: Duration,

    wsv: Arc<WorldStateView<W>>,
}

/// Queue push error
#[derive(Error, Debug)]
pub enum Error {
    /// Queue is full
    #[error("Queue is full")]
    Full,
    /// Transaction is regarded to have been tampered to have a future timestamp
    #[error("Transaction is regarded to have been tampered to have a future timestamp")]
    InFuture,
    /// Transaction expired
    #[error("Transaction is expired")]
    Expired,
    /// Transaction is already in blockchain
    #[error("Transaction is already applied")]
    InBlockchain,
    /// Signature condition check failed
    #[error("Failure during signature condition execution")]
    SignatureCondition(#[from] Report),
}

impl<W: WorldTrait> Queue<W> {
    /// Makes queue from configuration
    pub fn from_configuration(cfg: &Configuration, wsv: Arc<WorldStateView<W>>) -> Self {
        Self {
            queue: ArrayQueue::new(cfg.maximum_transactions_in_queue as usize),
            txs: DashMap::new(),
            max_txs: cfg.maximum_transactions_in_queue as usize,
            txs_in_block: cfg.maximum_transactions_in_block as usize,
            ttl: Duration::from_millis(cfg.transaction_time_to_live_ms),
            future_threshold: Duration::from_millis(cfg.future_threshold_ms),
            wsv,
        }
    }

    fn is_pending(&self, tx: &VersionedAcceptedTransaction) -> bool {
        !tx.is_expired(self.ttl) && !tx.is_in_blockchain(&self.wsv)
    }

    /// Returns all pending transactions.
    pub fn all_transactions(&self) -> Vec<VersionedAcceptedTransaction> {
        self.txs
            .iter()
            .filter(|e| self.is_pending(e.value()))
            .map(|e| e.value().clone())
            .collect()
    }

    /// Returns `n` randomly selected transaction from the queue.
    pub fn n_random_transactions(&self, n: u32) -> Vec<VersionedAcceptedTransaction> {
        self.txs
            .iter()
            .filter(|e| self.is_pending(e.value()))
            .map(|e| e.value().clone())
            .choose_multiple(
                &mut rand::thread_rng(),
                n.try_into().expect("u32 should always fit in usize"),
            )
    }

    fn check_tx(&self, tx: &VersionedAcceptedTransaction) -> Result<(), Error> {
        if tx.is_expired(self.ttl) {
            return Err(Error::Expired);
        }
        if tx.is_in_blockchain(&self.wsv) {
            return Err(Error::InBlockchain);
        }

        tx.check_signature_condition(&self.wsv)?;
        Ok(())
    }

    /// Pushes transaction into queue.
    ///
    /// # Errors
    /// See [`enum@Error`]
    #[allow(
        clippy::unwrap_in_result,
        clippy::expect_used,
        clippy::missing_panics_doc
    )]
    pub fn push(
        &self,
        tx: VersionedAcceptedTransaction,
    ) -> Result<(), (VersionedAcceptedTransaction, Error)> {
        if tx.is_in_future(self.future_threshold) {
            return Err((tx, Error::InFuture));
        }
        if let Err(e) = self.check_tx(&tx) {
            return Err((tx, e));
        }
        if self.txs.len() >= self.max_txs {
            return Err((tx, Error::Full));
        }

        let hash = tx.hash();
        let entry = match self.txs.entry(hash) {
            Entry::Occupied(mut old_tx) => {
                // MST case
                old_tx
                    .get_mut()
                    .as_mut_v1()
                    .signatures
                    .extend(tx.as_v1().signatures.clone());
                return Ok(());
            }
            Entry::Vacant(entry) => entry,
        };

        entry.insert(tx);

        if let Err(err_hash) = self.queue.push(hash) {
            let (_, err_tx) = self
                .txs
                .remove(&err_hash)
                .expect("Inserted just before match");
            return Err((err_tx, Error::Full));
        }
        Ok(())
    }

    /// Pops single transaction.
    ///
    /// Records unsigned transaction in seen.
    #[allow(
        clippy::expect_used,
        clippy::unwrap_in_result,
        clippy::cognitive_complexity
    )]
    fn pop(
        &self,
        seen: &mut Vec<HashOf<VersionedTransaction>>,
    ) -> Option<VersionedAcceptedTransaction> {
        loop {
            let hash = self.queue.pop()?;
            let entry = match self.txs.entry(hash) {
                Entry::Occupied(entry) => entry,
                // As practice shows this code is not `unreachable!()`.
                // When transactions are submitted quickly it can be reached.
                Entry::Vacant(_) => continue,
            };
            if self.check_tx(entry.get()).is_err() {
                entry.remove_entry();
                continue;
            }

            seen.push(hash);
            if entry
                .get()
                .check_signature_condition(&self.wsv)
                .expect("Checked in `check_tx` just above")
            {
                return Some(entry.get().clone());
            }
        }
    }

    /// Returns the number of transactions in the queue
    pub fn tx_len(&self) -> usize {
        self.txs.len()
    }

    /// Gets transactions till they fill whole block or till the end of queue.
    ///
    /// BEWARE: Shouldn't be called in parallel with itself.
    #[allow(clippy::missing_panics_doc, clippy::unwrap_in_result)]
    pub fn get_transactions_for_block(&self) -> Vec<VersionedAcceptedTransaction> {
        let mut seen = Vec::new();

        let out = std::iter::repeat_with(|| self.pop(&mut seen))
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
    const DEFAULT_MAXIMUM_TRANSACTIONS_IN_QUEUE: u32 = 2_u32.pow(16);
    // 24 hours
    const DEFAULT_TRANSACTION_TIME_TO_LIVE_MS: u64 = 24 * 60 * 60 * 1000;
    const DEFAULT_FUTURE_THRESHOLD_MS: u64 = 1000;

    /// Configuration for `Queue`.
    #[derive(Copy, Clone, Deserialize, Serialize, Debug, Configurable, PartialEq, Eq)]
    #[serde(rename_all = "UPPERCASE")]
    #[serde(default)]
    #[config(env_prefix = "QUEUE_")]
    pub struct Configuration {
        /// The upper limit of the number of transactions per block.
        pub maximum_transactions_in_block: u32,
        /// The upper limit of the number of transactions waiting in this queue.
        pub maximum_transactions_in_queue: u32,
        /// The transaction will be dropped after this time if it is still in a `Queue`.
        pub transaction_time_to_live_ms: u64,
        /// The threshold to determine if a transaction has been tampered to have a future timestamp.
        pub future_threshold_ms: u64,
    }

    impl Default for Configuration {
        fn default() -> Self {
            Self {
                maximum_transactions_in_block: DEFAULT_MAXIMUM_TRANSACTIONS_IN_BLOCK,
                maximum_transactions_in_queue: DEFAULT_MAXIMUM_TRANSACTIONS_IN_QUEUE,
                transaction_time_to_live_ms: DEFAULT_TRANSACTION_TIME_TO_LIVE_MS,
                future_threshold_ms: DEFAULT_FUTURE_THRESHOLD_MS,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction, clippy::all, clippy::pedantic)]

    use std::{
        iter,
        str::FromStr,
        sync::Arc,
        thread,
        time::{Duration, Instant},
    };

    use iroha_data_model::prelude::*;
    use rand::Rng;

    use super::*;
    use crate::{wsv::World, PeersIds};

    fn accepted_tx(
        account_id: &str,
        proposed_ttl_ms: u64,
        key: Option<&KeyPair>,
    ) -> VersionedAcceptedTransaction {
        let key = key
            .cloned()
            .unwrap_or_else(|| KeyPair::generate().expect("Failed to generate keypair."));

        let message = std::iter::repeat_with(rand::random::<char>)
            .take(16)
            .collect();
        let instructions: Vec<Instruction> = vec![FailBox { message }.into()];
        let tx = Transaction::new(
            AccountId::from_str(account_id).expect("Valid"),
            instructions.into(),
            proposed_ttl_ms,
        )
        .sign(key)
        .expect("Failed to sign.");
        let limits = TransactionLimits {
            max_instruction_number: 4096,
            max_wasm_size_bytes: 0,
        };
        VersionedAcceptedTransaction::from_transaction(tx, &limits)
            .expect("Failed to accept Transaction.")
    }

    pub fn world_with_test_domains(public_key: PublicKey) -> World {
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build();
        let account = Account::new(account_id, [public_key]).build();
        assert!(domain.add_account(account).is_none());
        World::with([domain], PeersIds::new())
    }

    #[test]
    fn push_tx() {
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains(
            KeyPair::generate().unwrap().public_key,
        )));

        let queue = Queue::from_configuration(
            &Configuration {
                maximum_transactions_in_block: 2,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: 100,
                ..Configuration::default()
            },
            wsv,
        );

        queue
            .push(accepted_tx("alice@wonderland", 100_000, None))
            .expect("Failed to push tx into queue");
    }

    #[test]
    fn push_tx_overflow() {
        let max_txs_in_queue = 10;

        let wsv = Arc::new(WorldStateView::new(world_with_test_domains(
            KeyPair::generate().unwrap().public_key,
        )));

        let queue = Queue::from_configuration(
            &Configuration {
                maximum_transactions_in_block: 2,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: max_txs_in_queue,
                ..Configuration::default()
            },
            wsv,
        );

        for _ in 0..max_txs_in_queue {
            queue
                .push(accepted_tx("alice@wonderland", 100_000, None))
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        assert!(matches!(
            queue.push(accepted_tx("alice@wonderland", 100_000, None)),
            Err((_, Error::Full))
        ));
    }

    #[test]
    fn push_tx_signature_condition_failure() {
        let max_txs_in_queue = 10;

        let wsv = {
            let public_key = KeyPair::generate().unwrap().public_key;
            let domain_id = DomainId::from_str("wonderland").expect("Valid");
            let mut domain = Domain::new(domain_id.clone()).build();
            let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
            let mut account = Account::new(account_id, [public_key]).build();
            account.set_signature_check_condition(SignatureCheckCondition(0_u32.into()));
            assert!(domain.add_account(account).is_none());

            Arc::new(WorldStateView::new(World::with([domain], PeersIds::new())))
        };

        let queue = Queue::from_configuration(
            &Configuration {
                maximum_transactions_in_block: 2,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: max_txs_in_queue,
                ..Configuration::default()
            },
            wsv,
        );

        assert!(matches!(
            queue.push(accepted_tx("alice@wonderland", 100_000, None)),
            Err((_, Error::SignatureCondition(_)))
        ));
    }

    #[test]
    fn push_multisignature_tx() {
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains(
            KeyPair::generate().unwrap().public_key,
        )));

        let queue = Queue::from_configuration(
            &Configuration {
                maximum_transactions_in_block: 2,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: 100,
                ..Configuration::default()
            },
            wsv,
        );
        let tx = Transaction::new(
            AccountId::from_str("alice@wonderland").expect("Valid"),
            Vec::<Instruction>::new().into(),
            100_000,
        );
        let get_tx = || {
            let tx_limits = TransactionLimits {
                max_instruction_number: 4096,
                max_wasm_size_bytes: 0,
            };
            VersionedAcceptedTransaction::from_transaction(
                tx.clone()
                    .sign(KeyPair::generate().expect("Failed to generate keypair."))
                    .expect("Failed to sign."),
                &tx_limits,
            )
            .expect("Failed to accept Transaction.")
        };

        queue.push(get_tx()).unwrap();
        queue.push(get_tx()).unwrap();

        assert_eq!(queue.queue.len(), 1);
        let signature_count = queue
            .txs
            .get(&queue.queue.pop().unwrap())
            .unwrap()
            .as_v1()
            .signatures
            .len();
        assert_eq!(signature_count, 2);
    }

    #[test]
    fn get_available_txs() {
        let max_block_tx = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains(
            alice_key.public_key.clone(),
        )));
        let queue = Queue::from_configuration(
            &Configuration {
                maximum_transactions_in_block: max_block_tx,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: 100,
                ..Configuration::default()
            },
            wsv,
        );
        for _ in 0..5 {
            queue
                .push(accepted_tx("alice@wonderland", 100_000, Some(&alice_key)))
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        let available = queue.get_transactions_for_block();
        assert_eq!(available.len(), max_block_tx as usize);
    }

    #[test]
    fn push_tx_already_in_blockchain() {
        let max_block_tx = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains(
            alice_key.public_key.clone(),
        )));
        let tx = accepted_tx("alice@wonderland", 100_000, Some(&alice_key));
        wsv.transactions.insert(tx.hash());
        let queue = Queue::from_configuration(
            &Configuration {
                maximum_transactions_in_block: max_block_tx,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: 100,
                ..Configuration::default()
            },
            wsv,
        );
        assert!(matches!(queue.push(tx), Err((_, Error::InBlockchain))));
        assert_eq!(queue.txs.len(), 0);
    }

    #[test]
    fn get_tx_drop_if_in_blockchain() {
        let max_block_tx = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains(
            alice_key.public_key.clone(),
        )));
        let tx = accepted_tx("alice@wonderland", 100_000, Some(&alice_key));
        let queue = Queue::from_configuration(
            &Configuration {
                maximum_transactions_in_block: max_block_tx,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: 100,
                ..Configuration::default()
            },
            Arc::clone(&wsv),
        );
        queue.push(tx.clone()).unwrap();
        wsv.transactions.insert(tx.hash());
        assert_eq!(queue.get_transactions_for_block().len(), 0);
        assert_eq!(queue.txs.len(), 0);
    }

    #[test]
    fn get_available_txs_with_timeout() {
        let max_block_tx = 6;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains(
            alice_key.public_key.clone(),
        )));
        let queue = Queue::from_configuration(
            &Configuration {
                maximum_transactions_in_block: max_block_tx,
                transaction_time_to_live_ms: 200,
                maximum_transactions_in_queue: 100,
                ..Configuration::default()
            },
            wsv,
        );
        for _ in 0..(max_block_tx - 1) {
            queue
                .push(accepted_tx("alice@wonderland", 100, Some(&alice_key)))
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        queue
            .push(accepted_tx("alice@wonderland", 200, Some(&alice_key)))
            .expect("Failed to push tx into queue");
        std::thread::sleep(Duration::from_millis(101));
        assert_eq!(queue.get_transactions_for_block().len(), 1);

        queue
            .push(accepted_tx("alice@wonderland", 300, Some(&alice_key)))
            .expect("Failed to push tx into queue");
        std::thread::sleep(Duration::from_millis(210));
        assert_eq!(queue.get_transactions_for_block().len(), 0);
    }

    // Queue should only drop transactions which are already committed or ttl expired.
    // Others should stay in the queue until that moment.
    #[test]
    fn transactions_available_after_pop() {
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains(
            alice_key.public_key.clone(),
        )));
        let queue = Queue::from_configuration(
            &Configuration {
                maximum_transactions_in_block: 2,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: 100,
                ..Configuration::default()
            },
            wsv,
        );
        queue
            .push(accepted_tx("alice@wonderland", 100_000, Some(&alice_key)))
            .expect("Failed to push tx into queue");

        let a = queue
            .get_transactions_for_block()
            .into_iter()
            .map(|tx| tx.hash())
            .collect::<Vec<_>>();
        let b = queue
            .get_transactions_for_block()
            .into_iter()
            .map(|tx| tx.hash())
            .collect::<Vec<_>>();
        assert_eq!(a.len(), 1);
        assert_eq!(a, b);
    }

    #[test]
    fn concurrent_stress_test() {
        let max_block_tx = 10;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains(
            alice_key.public_key.clone(),
        )));
        let wsv_clone = Arc::clone(&wsv);
        let queue = Arc::new(Queue::from_configuration(
            &Configuration {
                maximum_transactions_in_block: max_block_tx,
                transaction_time_to_live_ms: 100_000,
                maximum_transactions_in_queue: 100_000_000,
                ..Configuration::default()
            },
            wsv,
        ));

        let start_time = Instant::now();
        let run_for = Duration::from_secs(5);

        let queue_arc_clone_1 = Arc::clone(&queue);
        let queue_arc_clone_2 = Arc::clone(&queue);

        // Spawn a thread where we push transactions
        let push_txs_handle = thread::spawn(move || {
            while start_time.elapsed() < run_for {
                let tx = accepted_tx("alice@wonderland", 100_000, Some(&alice_key));
                match queue_arc_clone_1.push(tx) {
                    Ok(()) => (),
                    Err((_, Error::Full)) => (),
                    Err((_, err)) => panic!("{}", err),
                }
            }
        });

        // Spawn a thread where we get_transactions_for_block and add them to WSV
        let get_txs_handle = thread::spawn(move || {
            while start_time.elapsed() < run_for {
                for tx in queue_arc_clone_2.get_transactions_for_block() {
                    wsv_clone.transactions.insert(tx.hash());
                }
                // Simulate random small delays
                thread::sleep(Duration::from_millis(rand::thread_rng().gen_range(0..25)));
            }
        });

        push_txs_handle.join().unwrap();
        get_txs_handle.join().unwrap();

        // Last update for queue to drop invalid txs.
        let _ = queue.get_transactions_for_block();

        // Validate the queue state.
        let array_queue: Vec<_> = iter::repeat_with(|| queue.queue.pop())
            .take_while(Option::is_some)
            .map(Option::unwrap)
            .collect();

        assert_eq!(array_queue.len(), queue.txs.len());
        for tx in array_queue {
            assert!(queue.txs.contains_key(&tx));
        }
    }

    #[test]
    fn push_tx_in_future() {
        let future_threshold_ms = 1000;

        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains(
            alice_key.public_key.clone(),
        )));

        let queue = Queue::from_configuration(
            &Configuration {
                future_threshold_ms,
                ..Configuration::default()
            },
            wsv,
        );

        let mut tx = accepted_tx("alice@wonderland", 100_000, Some(&alice_key));
        assert!(queue.push(tx.clone()).is_ok());
        // tamper timestamp
        tx.as_mut_v1().payload.creation_time += 2 * future_threshold_ms;
        assert!(matches!(queue.push(tx), Err((_, Error::InFuture))));
        assert_eq!(queue.txs.len(), 1);
    }
}
