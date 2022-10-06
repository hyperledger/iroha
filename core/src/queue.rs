//! Module with queue actor
#![allow(
    clippy::module_name_repetitions,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic,
    clippy::expect_used
)]

use core::time::Duration;

use crossbeam_queue::ArrayQueue;
use dashmap::{mapref::entry::Entry, DashMap};
use eyre::{eyre, Report, Result};
use iroha_config::queue::Configuration;
use iroha_crypto::HashOf;
use iroha_data_model::transaction::prelude::*;
use rand::seq::IteratorRandom;
use thiserror::Error;

use crate::prelude::*;

/// Lockfree queue for transactions
///
/// Multiple producers, single consumer
#[derive(Debug)]
pub struct Queue {
    /// The queue proper
    queue: ArrayQueue<HashOf<VersionedSignedTransaction>>,
    /// [`VersionedAcceptedTransaction`]s addressed by `Hash`.
    txs: DashMap<HashOf<VersionedSignedTransaction>, VersionedAcceptedTransaction>,
    /// Length of [`DashMap`].
    ///
    /// [`DashMap`] right now just iterates over itself and calculates its length like this:
    /// self.txs.iter().len()
    pub txs_in_block: usize,
    /// The maximum number of transactions
    max_txs: usize,
    /// Length of time after which transactions are dropped.
    pub tx_time_to_live: Duration,
    /// A point in time that is considered `Future` we cannot use
    /// current time, because of network time synchronisation issues
    future_threshold: Duration,
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
    #[error("Failure during signature condition execution, tx hash: {tx_hash}, reason: {reason}")]
    SignatureCondition {
        /// Transaction hash
        tx_hash: HashOf<VersionedSignedTransaction>,
        /// Failure reason
        reason: Report,
    },
}

impl Queue {
    /// Makes queue from configuration
    pub fn from_configuration(cfg: &Configuration) -> Self {
        Self {
            queue: ArrayQueue::new(cfg.maximum_transactions_in_queue as usize),
            txs: DashMap::new(),
            max_txs: cfg.maximum_transactions_in_queue as usize,
            txs_in_block: cfg.maximum_transactions_in_block as usize,
            tx_time_to_live: Duration::from_millis(cfg.transaction_time_to_live_ms),
            future_threshold: Duration::from_millis(cfg.future_threshold_ms),
        }
    }

    fn is_pending(&self, tx: &VersionedAcceptedTransaction, wsv: &WorldStateView) -> bool {
        !tx.is_expired(self.tx_time_to_live) && !tx.is_in_blockchain(wsv)
    }

    /// Returns all pending transactions.
    pub fn all_transactions(&self, wsv: &WorldStateView) -> Vec<VersionedAcceptedTransaction> {
        self.txs
            .iter()
            .filter(|e| self.is_pending(e.value(), wsv))
            .map(|e| e.value().clone())
            .collect()
    }

    /// Returns `n` randomly selected transaction from the queue.
    pub fn n_random_transactions(
        &self,
        n: u32,
        wsv: &WorldStateView,
    ) -> Vec<VersionedAcceptedTransaction> {
        self.txs
            .iter()
            .filter(|e| self.is_pending(e.value(), wsv))
            .map(|e| e.value().clone())
            .choose_multiple(
                &mut rand::thread_rng(),
                n.try_into().expect("u32 should always fit in usize"),
            )
    }

    fn check_tx(
        &self,
        tx: &VersionedAcceptedTransaction,
        wsv: &WorldStateView,
    ) -> Result<(), Error> {
        if tx.is_expired(self.tx_time_to_live) {
            Err(Error::Expired)
        } else if tx.is_in_blockchain(wsv) {
            Err(Error::InBlockchain)
        } else {
            tx.check_signature_condition(wsv)
                .and_then(|success| {
                    success
                        .into_inner()
                        .then_some(())
                        .ok_or_else(|| eyre!("Signature condition check failed"))
                })
                .map_err(|reason| Error::SignatureCondition {
                    tx_hash: tx.hash(),
                    reason,
                })
        }
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
        wsv: &WorldStateView,
    ) -> Result<(), (VersionedAcceptedTransaction, Error)> {
        if tx.is_in_future(self.future_threshold) {
            Err((tx, Error::InFuture))
        } else if let Err(e) = self.check_tx(&tx, wsv) {
            Err((tx, e))
        } else if self.txs.len() >= self.max_txs {
            Err((tx, Error::Full))
        } else {
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
                Err((err_tx, Error::Full))
            } else {
                Ok(())
            }
        }
    }

    /// Pop single transaction.
    ///
    /// Records unsigned transaction in `seen`.
    #[allow(
        clippy::expect_used,
        clippy::unwrap_in_result,
        clippy::cognitive_complexity
    )]
    fn pop(
        &self,
        seen: &mut Vec<HashOf<VersionedSignedTransaction>>,
        wsv: &WorldStateView,
    ) -> Option<VersionedAcceptedTransaction> {
        loop {
            let hash = self.queue.pop()?;
            let entry = match self.txs.entry(hash) {
                Entry::Occupied(entry) => entry,
                // As practice shows this code is not `unreachable!()`.
                // When transactions are submitted quickly it can be reached.
                Entry::Vacant(_) => continue,
            };
            if self.check_tx(entry.get(), wsv).is_err() {
                entry.remove_entry();
                continue;
            }

            seen.push(hash);
            if *entry
                .get()
                .check_signature_condition(wsv)
                .expect("Checked in `check_tx` just above")
            {
                return Some(entry.get().clone());
            }
        }
    }

    /// Pop a single transaction.
    ///
    /// Unlike [`Self::pop`], unsigned transactions are not recorded.
    #[allow(
        clippy::expect_used,
        clippy::unwrap_in_result,
        clippy::cognitive_complexity
    )]
    pub fn pop_without_seen(&self, wsv: &WorldStateView) -> Option<VersionedAcceptedTransaction> {
        loop {
            let hash = self.queue.pop()?;
            let entry = match self.txs.entry(hash) {
                Entry::Occupied(entry) => entry,
                // As practice shows this code is not `unreachable!()`.
                // When transactions are submitted quickly it can be reached.
                Entry::Vacant(_) => continue,
            };
            if self.check_tx(entry.get(), wsv).is_err() {
                entry.remove_entry();
                continue;
            }

            if *entry
                .get()
                .check_signature_condition(wsv)
                .expect("Checked in `check_tx` just above")
            {
                return Some(entry.get().clone());
            }
        }
    }

    /// Return the number of transactions in the queue
    pub fn tx_len(&self) -> usize {
        self.txs.len()
    }

    /// Gets transactions till they fill whole block or till the end of queue.
    ///
    /// BEWARE: Shouldn't be called in parallel with itself.
    #[allow(clippy::missing_panics_doc, clippy::unwrap_in_result)]
    pub fn get_transactions_for_block(
        &self,
        wsv: &WorldStateView,
    ) -> Vec<VersionedAcceptedTransaction> {
        let mut seen = Vec::new();

        let out = std::iter::repeat_with(|| self.pop(&mut seen, wsv))
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

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction, clippy::all, clippy::pedantic)]

    use std::{str::FromStr, sync::Arc, thread, time::Duration};

    use iroha_config::{base::proxy::Builder, queue::ConfigurationProxy};
    use iroha_data_model::prelude::*;
    use rand::Rng as _;

    use super::*;
    use crate::{wsv::World, PeersIds};

    fn accepted_tx(
        account_id: &str,
        proposed_ttl_ms: u64,
        key: KeyPair,
    ) -> VersionedAcceptedTransaction {
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

    pub fn world_with_test_domains(
        signatures: impl IntoIterator<Item = iroha_crypto::PublicKey>,
    ) -> World {
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build();
        let account = Account::new(account_id, signatures).build();
        assert!(domain.add_account(account).is_none());
        World::with([domain], PeersIds::new())
    }

    #[test]
    fn push_tx() {
        let key_pair = KeyPair::generate().unwrap();
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains([key_pair
            .public_key()
            .clone()])));

        let queue = Queue::from_configuration(&Configuration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
            ..ConfigurationProxy::default()
                .build()
                .expect("Default queue config should always build")
        });

        queue
            .push(accepted_tx("alice@wonderland", 100_000, key_pair), &wsv)
            .expect("Failed to push tx into queue");
    }

    #[test]
    fn push_tx_overflow() {
        let max_txs_in_queue = 10;

        let key_pair = KeyPair::generate().unwrap();
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains([key_pair
            .public_key()
            .clone()])));

        let queue = Queue::from_configuration(&Configuration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: max_txs_in_queue,
            ..ConfigurationProxy::default()
                .build()
                .expect("Default queue config should always build")
        });

        for _ in 0..max_txs_in_queue {
            queue
                .push(
                    accepted_tx("alice@wonderland", 100_000, key_pair.clone()),
                    &wsv,
                )
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        assert!(matches!(
            queue.push(accepted_tx("alice@wonderland", 100_000, key_pair), &wsv),
            Err((_, Error::Full))
        ));
    }

    #[test]
    fn push_tx_signature_condition_failure() {
        let max_txs_in_queue = 10;
        let key_pair = KeyPair::generate().unwrap();

        let wsv = {
            let domain_id = DomainId::from_str("wonderland").expect("Valid");
            let mut domain = Domain::new(domain_id.clone()).build();
            let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
            let mut account = Account::new(account_id, [key_pair.public_key().clone()]).build();
            account.set_signature_check_condition(SignatureCheckCondition(false.into()));
            assert!(domain.add_account(account).is_none());

            Arc::new(WorldStateView::new(World::with([domain], PeersIds::new())))
        };

        let queue = Queue::from_configuration(&Configuration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: max_txs_in_queue,
            ..ConfigurationProxy::default()
                .build()
                .expect("Default queue config should always build")
        });

        assert!(matches!(
            queue.push(accepted_tx("alice@wonderland", 100_000, key_pair), &wsv),
            Err((_, Error::SignatureCondition { .. }))
        ));
    }

    #[test]
    fn push_multisignature_tx() {
        let key_pairs = [KeyPair::generate().unwrap(), KeyPair::generate().unwrap()];
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains(
            key_pairs
                .iter()
                .map(|key_pair| key_pair.public_key())
                .cloned(),
        )));

        let queue = Queue::from_configuration(&Configuration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
            ..ConfigurationProxy::default()
                .build()
                .expect("Default queue config should always build")
        });
        let tx = Transaction::new(
            AccountId::from_str("alice@wonderland").expect("Valid"),
            Vec::<Instruction>::new().into(),
            100_000,
        );
        let get_tx = |key_pair| {
            let tx_limits = TransactionLimits {
                max_instruction_number: 4096,
                max_wasm_size_bytes: 0,
            };
            VersionedAcceptedTransaction::from_transaction(
                tx.clone().sign(key_pair).expect("Failed to sign."),
                &tx_limits,
            )
            .expect("Failed to accept Transaction.")
        };

        for key_pair in key_pairs {
            queue.push(get_tx(key_pair), &wsv).unwrap();
        }

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
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains([alice_key
            .public_key()
            .clone()])));
        let queue = Queue::from_configuration(&Configuration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
            ..ConfigurationProxy::default()
                .build()
                .expect("Default queue config should always build")
        });
        for _ in 0..5 {
            queue
                .push(
                    accepted_tx("alice@wonderland", 100_000, alice_key.clone()),
                    &wsv,
                )
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        let available = queue.get_transactions_for_block(&wsv);
        assert_eq!(available.len(), max_block_tx as usize);
    }

    #[test]
    fn push_tx_already_in_blockchain() {
        let max_block_tx = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains([alice_key
            .public_key()
            .clone()])));
        let tx = accepted_tx("alice@wonderland", 100_000, alice_key);
        wsv.transactions.insert(tx.hash());
        let queue = Queue::from_configuration(&Configuration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
            ..ConfigurationProxy::default()
                .build()
                .expect("Default queue config should always build")
        });
        assert!(matches!(
            queue.push(tx, &wsv),
            Err((_, Error::InBlockchain))
        ));
        assert_eq!(queue.txs.len(), 0);
    }

    #[test]
    fn get_tx_drop_if_in_blockchain() {
        let max_block_tx = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains([alice_key
            .public_key()
            .clone()])));
        let tx = accepted_tx("alice@wonderland", 100_000, alice_key);
        let queue = Queue::from_configuration(&Configuration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
            ..ConfigurationProxy::default()
                .build()
                .expect("Default queue config should always build")
        });
        queue.push(tx.clone(), &wsv).unwrap();
        wsv.transactions.insert(tx.hash());
        assert_eq!(queue.get_transactions_for_block(&wsv).len(), 0);
        assert_eq!(queue.txs.len(), 0);
    }

    #[test]
    fn get_available_txs_with_timeout() {
        let max_block_tx = 6;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains([alice_key
            .public_key()
            .clone()])));
        let queue = Queue::from_configuration(&Configuration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 200,
            maximum_transactions_in_queue: 100,
            ..ConfigurationProxy::default()
                .build()
                .expect("Default queue config should always build")
        });
        for _ in 0..(max_block_tx - 1) {
            queue
                .push(
                    accepted_tx("alice@wonderland", 100, alice_key.clone()),
                    &wsv,
                )
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        queue
            .push(
                accepted_tx("alice@wonderland", 200, alice_key.clone()),
                &wsv,
            )
            .expect("Failed to push tx into queue");
        std::thread::sleep(Duration::from_millis(101));
        assert_eq!(queue.get_transactions_for_block(&wsv).len(), 1);

        queue
            .push(accepted_tx("alice@wonderland", 300, alice_key), &wsv)
            .expect("Failed to push tx into queue");
        std::thread::sleep(Duration::from_millis(210));
        assert_eq!(queue.get_transactions_for_block(&wsv).len(), 0);
    }

    // Queue should only drop transactions which are already committed or ttl expired.
    // Others should stay in the queue until that moment.
    #[test]
    fn transactions_available_after_pop() {
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains([alice_key
            .public_key()
            .clone()])));
        let queue = Queue::from_configuration(&Configuration {
            maximum_transactions_in_block: 2,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100,
            ..ConfigurationProxy::default()
                .build()
                .expect("Default queue config should always build")
        });
        queue
            .push(accepted_tx("alice@wonderland", 100_000, alice_key), &wsv)
            .expect("Failed to push tx into queue");

        let a = queue
            .get_transactions_for_block(&wsv)
            .into_iter()
            .map(|tx| tx.hash())
            .collect::<Vec<_>>();
        let b = queue
            .get_transactions_for_block(&wsv)
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
        let wsv = WorldStateView::new(world_with_test_domains([alice_key.public_key().clone()]));

        let queue = Arc::new(Queue::from_configuration(&Configuration {
            maximum_transactions_in_block: max_block_tx,
            transaction_time_to_live_ms: 100_000,
            maximum_transactions_in_queue: 100_000_000,
            ..ConfigurationProxy::default()
                .build()
                .expect("Default queue config should always build")
        }));

        let start_time = std::time::Instant::now();
        let run_for = Duration::from_secs(5);

        let push_txs_handle = {
            let queue_arc_clone = Arc::clone(&queue);
            let wsv_clone = wsv.clone();

            // Spawn a thread where we push transactions
            thread::spawn(move || {
                while start_time.elapsed() < run_for {
                    let tx = accepted_tx("alice@wonderland", 100_000, alice_key.clone());
                    match queue_arc_clone.push(tx, &wsv_clone) {
                        Ok(()) => (),
                        Err((_, Error::Full)) => (),
                        Err((_, err)) => panic!("{}", err),
                    }
                }
            })
        };

        // Spawn a thread where we get_transactions_for_block and add them to WSV
        let get_txs_handle = {
            let queue_arc_clone = Arc::clone(&queue);
            let wsv_clone = wsv.clone();

            thread::spawn(move || {
                while start_time.elapsed() < run_for {
                    for tx in queue_arc_clone.get_transactions_for_block(&wsv_clone) {
                        wsv_clone.transactions.insert(tx.hash());
                    }
                    // Simulate random small delays
                    thread::sleep(Duration::from_millis(rand::thread_rng().gen_range(0..25)));
                }
            })
        };

        push_txs_handle.join().unwrap();
        get_txs_handle.join().unwrap();

        // Last update for queue to drop invalid txs.
        let _ = queue.get_transactions_for_block(&wsv);

        // Validate the queue state.
        let array_queue: Vec<_> = core::iter::repeat_with(|| queue.queue.pop())
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
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains([alice_key
            .public_key()
            .clone()])));

        let queue = Queue::from_configuration(&Configuration {
            future_threshold_ms,
            ..ConfigurationProxy::default()
                .build()
                .expect("Default queue config should always build")
        });

        let mut tx = accepted_tx("alice@wonderland", 100_000, alice_key);
        assert!(queue.push(tx.clone(), &wsv).is_ok());
        // tamper timestamp
        tx.as_mut_v1().payload.creation_time += 2 * future_threshold_ms;
        assert!(matches!(queue.push(tx, &wsv), Err((_, Error::InFuture))));
        assert_eq!(queue.txs.len(), 1);
    }
}
