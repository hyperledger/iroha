//! Module with queue actor
#![allow(
    clippy::module_name_repetitions,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]

use core::time::Duration;
use std::collections::HashSet;

use crossbeam_queue::ArrayQueue;
use dashmap::{mapref::entry::Entry, DashMap};
use eyre::{Report, Result};
use iroha_config::queue::Configuration;
use iroha_crypto::HashOf;
use iroha_data_model::{account::AccountId, transaction::prelude::*};
use iroha_logger::{debug, info, trace, warn};
use iroha_primitives::must_use::MustUse;
use rand::seq::IteratorRandom;
use thiserror::Error;

use crate::{prelude::*, tx::CheckSignatureCondition as _};

/// Lockfree queue for transactions
///
/// Multiple producers, single consumer
#[derive(Debug)]
pub struct Queue {
    /// The queue for transactions
    queue: ArrayQueue<HashOf<VersionedSignedTransaction>>,
    /// [`VersionedAcceptedTransaction`]s addressed by `Hash`
    txs: DashMap<HashOf<VersionedSignedTransaction>, VersionedAcceptedTransaction>,
    /// Amount of transactions per user in the queue
    txs_per_user: DashMap<AccountId, usize>,
    /// The maximum number of transactions in the queue
    max_txs: usize,
    /// The maximum number of transactions in the queue per user. Used to apply throttling
    max_txs_per_user: usize,
    /// Length of time after which transactions are dropped.
    pub tx_time_to_live: Duration,
    /// A point in time that is considered `Future` we cannot use
    /// current time, because of network time synchronisation issues
    future_threshold: Duration,
}

/// Queue push error
#[derive(Error, Debug)]
#[allow(variant_size_differences)]
pub enum Error {
    /// Queue is full
    #[error("Queue is full")]
    Full,
    /// Transaction is regarded to have been tampered to have a future timestamp
    #[error("Transaction is regarded to have been tampered to have a future timestamp")]
    InFuture,
    /// Transaction expired
    #[error(
        "Transaction is expired. Consider increase transaction ttl (current {time_to_live_ms}ms)"
    )]
    Expired {
        /// Transaction time to live
        time_to_live_ms: u64,
    },
    /// Transaction is already in blockchain
    #[error("Transaction is already applied")]
    InBlockchain,
    /// User reached maximum number of transactions in the queue
    #[error("User reached maximum number of trnasctions in the queue")]
    MaximumTransactionsPerUser,
    /// Signature condition check failed
    #[error("Failure during signature condition execution, tx hash: {tx_hash}, reason: {reason}")]
    SignatureCondition {
        /// Transaction hash
        tx_hash: HashOf<VersionedSignedTransaction>,
        /// Failure reason
        reason: Report,
    },
}

/// Failure that can pop up when pushing transaction into the queue
#[derive(Debug)]
pub struct Failure {
    /// Transaction failed to be pushed into the queue
    pub tx: VersionedAcceptedTransaction,
    /// Push failure reason
    pub err: Error,
}

impl Queue {
    /// Makes queue from configuration
    pub fn from_configuration(cfg: &Configuration) -> Self {
        Self {
            queue: ArrayQueue::new(*cfg.max_transactions_in_queue() as usize),
            txs: DashMap::new(),
            txs_per_user: DashMap::new(),
            max_txs: *cfg.max_transactions_in_queue() as usize,
            max_txs_per_user: *cfg.max_transactions_in_queue_per_user() as usize,
            tx_time_to_live: Duration::from_millis(*cfg.transaction_time_to_live_ms()),
            future_threshold: Duration::from_millis(*cfg.future_threshold_ms()),
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
    ) -> Result<MustUse<bool>, Error> {
        if tx.is_in_future(self.future_threshold) {
            Err(Error::InFuture)
        } else if tx.is_expired(self.tx_time_to_live) {
            Err(Error::Expired {
                time_to_live_ms: tx.payload().time_to_live_ms,
            })
        } else if tx.is_in_blockchain(wsv) {
            Err(Error::InBlockchain)
        } else {
            tx.check_signature_condition(wsv)
                .map_err(|reason| Error::SignatureCondition {
                    tx_hash: tx.hash(),
                    reason,
                })
        }
    }

    /// Push transaction into queue.
    ///
    /// # Errors
    /// See [`enum@Error`]
    pub fn push(
        &self,
        tx: VersionedAcceptedTransaction,
        wsv: &WorldStateView,
    ) -> Result<(), Failure> {
        trace!(?tx, "Pushing to the queue");
        if let Err(err) = self.check_tx(&tx, wsv) {
            warn!("Failed to evaluate signature check");
            return Err(Failure { tx, err });
        }

        // Get `txs_len` before entry to avoid deadlock
        let txs_len = self.txs.len();
        let hash = tx.hash();
        let entry = match self.txs.entry(hash) {
            Entry::Occupied(mut old_tx) => {
                // MST case
                old_tx
                    .get_mut()
                    .as_mut_v1()
                    .signatures
                    .extend(tx.as_v1().signatures.clone());
                info!("Signature added to existing multisignature transaction");
                return Ok(());
            }
            Entry::Vacant(entry) => entry,
        };
        if txs_len >= self.max_txs {
            warn!(
                max = self.max_txs,
                "Achieved maximum amount of transactions"
            );
            return Err(Failure {
                tx,
                err: Error::Full,
            });
        }

        if let Err(err) = self.check_and_increase_per_user_tx_count(&tx.payload().account_id) {
            return Err(Failure { tx, err });
        }

        // Insert entry first so that the `tx` popped from `queue` will always have a `(hash, tx)` record in `txs`.
        entry.insert(tx);
        self.queue.push(hash).map_err(|err_hash| {
            warn!("Queue is full");
            let (_, err_tx) = self
                .txs
                .remove(&err_hash)
                .expect("Inserted just before match");
            self.decrease_per_user_tx_count(&err_tx.payload().account_id);
            Failure {
                tx: err_tx,
                err: Error::Full,
            }
        })?;
        trace!("Transaction queue length = {}", self.queue.len(),);
        Ok(())
    }

    /// Pop single transaction from the queue. Record all visited and not removed transactions in `seen`.
    fn pop_from_queue(
        &self,
        seen: &mut Vec<HashOf<VersionedSignedTransaction>>,
        wsv: &WorldStateView,
        expired_transactions: &mut Vec<VersionedAcceptedTransaction>,
    ) -> Option<VersionedAcceptedTransaction> {
        loop {
            let Some(hash) = self.queue.pop() else {
                return None;
            };
            let entry = match self.txs.entry(hash) {
                Entry::Occupied(entry) => entry,
                // FIXME: Reachable under high load. Investigate, see if it's a problem.
                // As practice shows this code is not `unreachable!()`.
                // When transactions are submitted quickly it can be reached.
                Entry::Vacant(_) => {
                    warn!("Looks like we're experiencing a high load");
                    continue;
                }
            };

            let tx = entry.get();
            if tx.is_in_blockchain(wsv) {
                debug!("Transaction is already in blockchain");
                let (_, tx) = entry.remove_entry();
                self.decrease_per_user_tx_count(&tx.payload().account_id);
                continue;
            }
            if tx.is_expired(self.tx_time_to_live) {
                debug!("Transaction is expired");
                let (_, tx) = entry.remove_entry();
                self.decrease_per_user_tx_count(&tx.payload().account_id);
                expired_transactions.push(tx);
                continue;
            }
            seen.push(hash);
            if *tx.check_signature_condition(wsv).unwrap_or(MustUse(false)) {
                // Transactions are not removed from the queue until expired or committed
                return Some(entry.get().clone());
            }
        }
    }

    /// Return the number of transactions in the queue.
    pub fn tx_len(&self) -> usize {
        self.txs.len()
    }

    /// Gets transactions till they fill whole block or till the end of queue.
    ///
    /// BEWARE: Shouldn't be called in parallel with itself.
    #[cfg(test)]
    fn collect_transactions_for_block(
        &self,
        wsv: &WorldStateView,
        max_txs_in_block: usize,
    ) -> Vec<VersionedAcceptedTransaction> {
        let mut transactions = Vec::with_capacity(max_txs_in_block);
        self.get_transactions_for_block(wsv, max_txs_in_block, &mut transactions, &mut Vec::new());
        transactions
    }

    /// Put transactions into provided vector until they fill the whole block or there are no more transactions in the queue.
    ///
    /// BEWARE: Shouldn't be called in parallel with itself.
    pub fn get_transactions_for_block(
        &self,
        wsv: &WorldStateView,
        max_txs_in_block: usize,
        transactions: &mut Vec<VersionedAcceptedTransaction>,
        expired_transactions: &mut Vec<VersionedAcceptedTransaction>,
    ) {
        if transactions.len() >= max_txs_in_block {
            return;
        }

        let mut seen_queue = Vec::new();
        let mut expired_transactions_queue = Vec::new();

        let txs_from_queue = core::iter::from_fn(|| {
            self.pop_from_queue(&mut seen_queue, wsv, &mut expired_transactions_queue)
        });

        let transactions_hashes: HashSet<HashOf<VersionedSignedTransaction>> = transactions
            .iter()
            .map(VersionedAcceptedTransaction::hash)
            .collect();
        let txs = txs_from_queue
            .filter(|tx| !transactions_hashes.contains(&tx.hash()))
            .take(max_txs_in_block - transactions.len());
        transactions.extend(txs);

        seen_queue
            .into_iter()
            .try_for_each(|hash| self.queue.push(hash))
            .expect("Exceeded the number of transactions pending");
        expired_transactions.extend(expired_transactions_queue);
    }

    /// Check that the user adhered to the maximum transaction per user limit and increment their transaction count.
    fn check_and_increase_per_user_tx_count(&self, account_id: &AccountId) -> Result<(), Error> {
        match self.txs_per_user.entry(account_id.clone()) {
            Entry::Vacant(vacant) => {
                vacant.insert(1);
            }
            Entry::Occupied(mut occupied) => {
                let txs = *occupied.get();
                if txs >= self.max_txs_per_user {
                    warn!(
                        max_txs_per_user = self.max_txs_per_user,
                        %account_id,
                        "Account reached maximum allowed number of transactions in the queue per user"
                    );
                    return Err(Error::MaximumTransactionsPerUser);
                }
                *occupied.get_mut() += 1;
            }
        }

        Ok(())
    }

    fn decrease_per_user_tx_count(&self, account_id: &AccountId) {
        let Entry::Occupied(mut occupied) = self.txs_per_user
            .entry(account_id.clone()) else { panic!("Call to decrease always should be paired with increase count. This is a bug.") };

        let count = occupied.get_mut();
        if *count > 1 {
            *count -= 1;
        } else {
            occupied.remove_entry();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction, clippy::all, clippy::pedantic)]

    use std::{str::FromStr, sync::Arc, thread, time::Duration};

    use iroha_config::queue::{Configuration, ConfigurationBuilder};
    use iroha_data_model::{
        account::{ACCOUNT_SIGNATORIES_VALUE, TRANSACTION_SIGNATORIES_VALUE},
        prelude::*,
        transaction::InBlock,
    };
    use iroha_primitives::must_use::MustUse;
    use rand::Rng as _;

    use super::*;
    use crate::{kura::Kura, smartcontracts::isi::Registrable as _, wsv::World, PeersIds};

    fn accepted_tx(
        account_id: &str,
        proposed_ttl_ms: u64,
        key: KeyPair,
    ) -> VersionedAcceptedTransaction {
        let message = std::iter::repeat_with(rand::random::<char>)
            .take(16)
            .collect();
        let instructions: Vec<InstructionBox> = vec![FailBox { message }.into()];
        let tx = TransactionBuilder::new(
            AccountId::from_str(account_id).expect("Valid"),
            instructions,
            proposed_ttl_ms,
        )
        .sign(key)
        .expect("Failed to sign.");
        let limits = TransactionLimits {
            max_instruction_number: 4096,
            max_wasm_size_bytes: 0,
        };
        <AcceptedTransaction as InBlock>::accept(tx, &limits)
            .expect("Failed to accept Transaction.")
            .into()
    }

    pub fn world_with_test_domains(
        signatures: impl IntoIterator<Item = iroha_crypto::PublicKey>,
    ) -> World {
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build(&account_id);
        let account = Account::new(account_id.clone(), signatures).build(&account_id);
        assert!(domain.add_account(account).is_none());
        World::with([domain], PeersIds::new())
    }

    #[test]
    fn push_tx() {
        let key_pair = KeyPair::generate().unwrap();
        let kura = Kura::blank_kura_for_testing();
        let wsv = Arc::new(WorldStateView::new(
            world_with_test_domains([key_pair.public_key().clone()]),
            kura.clone(),
        ));

        let mut config = ConfigurationBuilder::default();
        config.set_transaction_time_to_live_ms(100_000);
        config.set_max_transactions_in_queue(100);
        let config = config.build().expect("Infallible");
        let queue = Queue::from_configuration(&config);

        queue
            .push(accepted_tx("alice@wonderland", 100_000, key_pair), &wsv)
            .expect("Failed to push tx into queue");
    }

    #[test]
    fn push_tx_overflow() {
        let key_pair = KeyPair::generate().unwrap();
        let kura = Kura::blank_kura_for_testing();
        let wsv = Arc::new(WorldStateView::new(
            world_with_test_domains([key_pair.public_key().clone()]),
            kura.clone(),
        ));

        let mut config = ConfigurationBuilder::default();
        config.set_transaction_time_to_live_ms(100_000);
        config.set_max_transactions_in_queue(10);
        let config = config.build().expect("Infallible");
        let queue = Queue::from_configuration(&config);

        for _ in 0..config.max_transactions_in_queue() {
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
            Err(Failure {
                err: Error::Full,
                ..
            })
        ));
    }

    #[test]
    fn push_tx_signature_condition_failure() {
        let key_pair = KeyPair::generate().unwrap();

        let wsv = {
            let domain_id = DomainId::from_str("wonderland").expect("Valid");
            let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
            let mut domain = Domain::new(domain_id.clone()).build(&account_id);
            let mut account = Account::new(account_id.clone(), [key_pair.public_key().clone()])
                .build(&account_id);
            // Cause `check_siganture_condition` failure by trying to convert `u32` to `bool`
            account.signature_check_condition =
                SignatureCheckCondition(EvaluatesTo::new_unchecked(0u32));
            assert!(domain.add_account(account).is_none());

            let kura = Kura::blank_kura_for_testing();
            Arc::new(WorldStateView::new(
                World::with([domain], PeersIds::new()),
                kura.clone(),
            ))
        };

        let mut config = ConfigurationBuilder::default();
        config.set_transaction_time_to_live_ms(100_000);
        config.set_max_transactions_in_queue(10);
        let config = config.build().expect("Infallible");
        let queue = Queue::from_configuration(&config);

        assert!(matches!(
            queue.push(accepted_tx("alice@wonderland", 100_000, key_pair), &wsv),
            Err(Failure {
                err: Error::SignatureCondition { .. },
                ..
            })
        ));
    }

    #[test]
    fn push_multisignature_tx() {
        let max_txs_in_block = 2;
        let key_pairs = [KeyPair::generate().unwrap(), KeyPair::generate().unwrap()];
        let kura = Kura::blank_kura_for_testing();
        let wsv = {
            let domain_id = DomainId::from_str("wonderland").expect("Valid");
            let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
            let mut domain = Domain::new(domain_id.clone()).build(&account_id);
            let mut account = Account::new(
                account_id.clone(),
                key_pairs.iter().map(KeyPair::public_key).cloned(),
            )
            .build(&account_id);
            account.signature_check_condition = SignatureCheckCondition(
                ContainsAll::new(
                    EvaluatesTo::new_unchecked(ContextValue::new(
                        Name::from_str(TRANSACTION_SIGNATORIES_VALUE)
                            .expect("TRANSACTION_SIGNATORIES_VALUE should be valid."),
                    )),
                    EvaluatesTo::new_unchecked(ContextValue::new(
                        Name::from_str(ACCOUNT_SIGNATORIES_VALUE)
                            .expect("ACCOUNT_SIGNATORIES_VALUE should be valid."),
                    )),
                )
                .into(),
            );
            assert!(domain.add_account(account).is_none());
            Arc::new(WorldStateView::new(
                World::with([domain], PeersIds::new()),
                kura.clone(),
            ))
        };

        let mut config = ConfigurationBuilder::default();
        config.set_transaction_time_to_live_ms(100_000);
        config.set_max_transactions_in_queue(100);
        let config = config.build().expect("Infallible");
        let queue = Queue::from_configuration(&config);

        let tx = TransactionBuilder::new(
            AccountId::from_str("alice@wonderland").expect("Valid"),
            Vec::new(),
            100_000,
        );
        let tx_limits = TransactionLimits {
            max_instruction_number: 4096,
            max_wasm_size_bytes: 0,
        };
        let fully_signed_tx: VersionedAcceptedTransaction = {
            let mut signed_tx = tx
                .clone()
                .sign((&key_pairs[0]).clone())
                .expect("Failed to sign.");
            for key_pair in &key_pairs[1..] {
                signed_tx = signed_tx.sign(key_pair.clone()).expect("Failed to sign");
            }
            <AcceptedTransaction as InBlock>::accept(signed_tx, &tx_limits)
                .expect("Failed to accept Transaction.")
                .into()
        };
        // Check that fully signed transaction pass signature check
        assert!(matches!(
            fully_signed_tx.check_signature_condition(&wsv),
            Ok(MustUse(true))
        ));

        let get_tx = |key_pair| {
            <AcceptedTransaction as InBlock>::accept(
                tx.clone().sign(key_pair).expect("Failed to sign."),
                &tx_limits,
            )
            .expect("Failed to accept Transaction.")
            .into()
        };
        for key_pair in key_pairs {
            let partially_signed_tx: VersionedAcceptedTransaction = get_tx(key_pair);
            // Check that non of partially signed pass signature check
            assert!(matches!(
                partially_signed_tx.check_signature_condition(&wsv),
                Ok(MustUse(false))
            ));
            queue
                .push(partially_signed_tx, &wsv)
                .expect("Should be possible to put partially signed transaction into the queue");
        }

        // Check that transactions combined into one instead of duplicating
        assert_eq!(queue.tx_len(), 1);

        let mut available = queue.collect_transactions_for_block(&wsv, max_txs_in_block);
        assert_eq!(available.len(), 1);
        let tx_from_queue = available.pop().expect("Checked that have one transactions");
        // Check that transaction from queue pass signature check
        assert!(matches!(
            tx_from_queue.check_signature_condition(&wsv),
            Ok(MustUse(true))
        ));
    }

    #[test]
    fn get_available_txs() {
        let max_txs_in_block = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let kura = Kura::blank_kura_for_testing();
        let wsv = Arc::new(WorldStateView::new(
            world_with_test_domains([alice_key.public_key().clone()]),
            kura.clone(),
        ));

        let mut config = ConfigurationBuilder::default();
        config.set_transaction_time_to_live_ms(100_000);
        config.set_max_transactions_in_queue(100);
        let config = config.build().expect("Infallible");
        let queue = Queue::from_configuration(&config);

        for _ in 0..5 {
            queue
                .push(
                    accepted_tx("alice@wonderland", 100_000, alice_key.clone()),
                    &wsv,
                )
                .expect("Failed to push tx into queue");
            thread::sleep(Duration::from_millis(10));
        }

        let available = queue.collect_transactions_for_block(&wsv, max_txs_in_block);
        assert_eq!(available.len(), max_txs_in_block);
    }

    #[test]
    fn push_tx_already_in_blockchain() {
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(
            world_with_test_domains([alice_key.public_key().clone()]),
            kura.clone(),
        );
        let tx = accepted_tx("alice@wonderland", 100_000, alice_key);
        wsv.transactions.insert(tx.hash());

        let mut config = ConfigurationBuilder::default();
        config.set_transaction_time_to_live_ms(100_000);
        config.set_max_transactions_in_queue(100);
        let config = config.build().expect("Infallible");
        let queue = Queue::from_configuration(&config);

        assert!(matches!(
            queue.push(tx, &wsv),
            Err(Failure {
                err: Error::InBlockchain,
                ..
            })
        ));
        assert_eq!(queue.txs.len(), 0);
    }

    #[test]
    fn get_tx_drop_if_in_blockchain() {
        let max_txs_in_block = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(
            world_with_test_domains([alice_key.public_key().clone()]),
            kura.clone(),
        );
        let tx = accepted_tx("alice@wonderland", 100_000, alice_key);

        let mut config = ConfigurationBuilder::default();
        config.set_transaction_time_to_live_ms(100_000);
        config.set_max_transactions_in_queue(100);
        let config = config.build().expect("Infallible");
        let queue = Queue::from_configuration(&config);

        queue.push(tx.clone(), &wsv).unwrap();
        wsv.transactions.insert(tx.hash());
        assert_eq!(
            queue
                .collect_transactions_for_block(&wsv, max_txs_in_block)
                .len(),
            0
        );
        assert_eq!(queue.txs.len(), 0);
    }

    #[test]
    fn get_available_txs_with_timeout() {
        let max_txs_in_block = 6;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let kura = Kura::blank_kura_for_testing();
        let wsv = Arc::new(WorldStateView::new(
            world_with_test_domains([alice_key.public_key().clone()]),
            kura.clone(),
        ));

        let mut config = ConfigurationBuilder::default();
        config.set_transaction_time_to_live_ms(200);
        config.set_max_transactions_in_queue(100);
        let config = config.build().expect("Infallible");
        let queue = Queue::from_configuration(&config);

        for _ in 0..(max_txs_in_block - 1) {
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
        assert_eq!(
            queue
                .collect_transactions_for_block(&wsv, max_txs_in_block)
                .len(),
            1
        );

        queue
            .push(accepted_tx("alice@wonderland", 300, alice_key), &wsv)
            .expect("Failed to push tx into queue");
        std::thread::sleep(Duration::from_millis(210));
        assert_eq!(
            queue
                .collect_transactions_for_block(&wsv, max_txs_in_block)
                .len(),
            0
        );
    }

    // Queue should only drop transactions which are already committed or ttl expired.
    // Others should stay in the queue until that moment.
    #[test]
    fn transactions_available_after_pop() {
        let max_txs_in_block = 2;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let kura = Kura::blank_kura_for_testing();
        let wsv = Arc::new(WorldStateView::new(
            world_with_test_domains([alice_key.public_key().clone()]),
            kura.clone(),
        ));

        let mut config = ConfigurationBuilder::default();
        config.set_transaction_time_to_live_ms(100_000);
        config.set_max_transactions_in_queue(100);
        let config = config.build().expect("Infallible");
        let queue = Queue::from_configuration(&config);

        queue
            .push(accepted_tx("alice@wonderland", 100_000, alice_key), &wsv)
            .expect("Failed to push tx into queue");

        let a = queue
            .collect_transactions_for_block(&wsv, max_txs_in_block)
            .into_iter()
            .map(|tx| tx.hash())
            .collect::<Vec<_>>();
        let b = queue
            .collect_transactions_for_block(&wsv, max_txs_in_block)
            .into_iter()
            .map(|tx| tx.hash())
            .collect::<Vec<_>>();
        assert_eq!(a.len(), 1);
        assert_eq!(a, b);
    }

    #[test]
    fn concurrent_stress_test() {
        let max_txs_in_block = 10;
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(
            world_with_test_domains([alice_key.public_key().clone()]),
            kura.clone(),
        );

        let mut config = ConfigurationBuilder::default();
        config.set_transaction_time_to_live_ms(100_000);
        config.set_max_transactions_in_queue(100_000_000);
        let config = config.build().expect("Infallible");
        let queue = Queue::from_configuration(&config);

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
                        Err(Failure {
                            err: Error::Full, ..
                        }) => (),
                        Err(Failure {
                            err: Error::MaximumTransactionsPerUser,
                            ..
                        }) => (),
                        Err(Failure { err, .. }) => panic!("{err}"),
                    }
                }
            })
        };

        // Spawn a thread where we get_transactions_for_block and add them to WSV
        let get_txs_handle = {
            let queue_arc_clone = Arc::clone(&queue);
            let mut wsv_clone = wsv.clone();

            thread::spawn(move || {
                while start_time.elapsed() < run_for {
                    for tx in
                        queue_arc_clone.collect_transactions_for_block(&wsv_clone, max_txs_in_block)
                    {
                        wsv_clone.transactions.insert(tx.hash());
                    }
                    // Simulate random small delays
                    thread::sleep(Duration::from_millis(rand::thread_rng().gen_range(0..25)));
                }
            })
        };

        push_txs_handle.join().unwrap();
        get_txs_handle.join().unwrap();

        // Validate the queue state.
        let array_queue: Vec<_> = core::iter::from_fn(|| queue.queue.pop()).collect();

        assert_eq!(array_queue.len(), queue.txs.len());
        for tx in array_queue {
            assert!(queue.txs.contains_key(&tx));
        }
    }

    #[test]
    fn push_tx_in_future() {
        let alice_key = KeyPair::generate().expect("Failed to generate keypair.");
        let kura = Kura::blank_kura_for_testing();
        let wsv = Arc::new(WorldStateView::new(
            world_with_test_domains([alice_key.public_key().clone()]),
            kura.clone(),
        ));

        let mut config = Configuration::default();
        let mut tx = accepted_tx("alice@wonderland", 100_000, alice_key);
        assert!(queue.push(tx.clone(), &wsv).is_ok());
        // tamper timestamp
        tx.as_mut_v1().payload.creation_time += 2 * config.future_threshold_ms();
        assert!(matches!(
            queue.push(tx, &wsv),
            Err(Failure {
                err: Error::InFuture,
                ..
            })
        ));
        assert_eq!(queue.txs.len(), 1);
    }

    #[test]
    fn queue_throttling() {
        let alice_key_pair = KeyPair::generate().unwrap();
        let bob_key_pair = KeyPair::generate().unwrap();
        let kura = Kura::blank_kura_for_testing();
        let world = {
            let domain_id = DomainId::from_str("wonderland").expect("Valid");
            let alice_account_id = AccountId::from_str("alice@wonderland").expect("Valid");
            let bob_account_id = AccountId::from_str("bob@wonderland").expect("Valid");
            let mut domain = Domain::new(domain_id).build(&alice_account_id);
            let alice_account = Account::new(
                alice_account_id.clone(),
                [alice_key_pair.public_key().clone()],
            )
            .build(&alice_account_id);
            let bob_account =
                Account::new(bob_account_id.clone(), [bob_key_pair.public_key().clone()])
                    .build(&bob_account_id);
            assert!(domain.add_account(alice_account).is_none());
            assert!(domain.add_account(bob_account).is_none());
            World::with([domain], PeersIds::new())
        };
        let mut wsv = WorldStateView::new(world, kura.clone());

        let mut config = ConfigurationBuilder::default();
        config.set_transaction_time_to_live_ms(100_000);
        config.set_max_transactions_in_queue(100);
        let config = config.build().expect("Infallible");
        let queue = Queue::from_configuration(&config);

        // First push by Alice should be fine
        queue
            .push(
                accepted_tx("alice@wonderland", 100_000, alice_key_pair.clone()),
                &wsv,
            )
            .expect("Failed to push tx into queue");

        // Second push by Alice excide limit and will be rejected
        let result = queue.push(
            accepted_tx("alice@wonderland", 100_000, alice_key_pair.clone()),
            &wsv,
        );
        assert!(
            matches!(
                result,
                Err(Failure {
                    tx: _,
                    err: Error::MaximumTransactionsPerUser
                }),
            ),
            "Failed to match: {:?}",
            result,
        );

        // First push by Bob should be fine despite previous Alice error
        queue
            .push(
                accepted_tx("bob@wonderland", 100_000, bob_key_pair.clone()),
                &wsv,
            )
            .expect("Failed to push tx into queue");

        let transactions = queue.collect_transactions_for_block(&wsv, 10);
        assert_eq!(transactions.len(), 2);
        for transaction in transactions {
            // Put transaction hashes into wsv as if they were in the blockchain
            wsv.transactions.insert(transaction.hash());
        }
        // Cleanup transactions
        let transactions = queue.collect_transactions_for_block(&wsv, 10);
        assert!(transactions.is_empty());

        // After cleanup Alice and Bob pushes should work fine
        queue
            .push(
                accepted_tx("alice@wonderland", 100_000, alice_key_pair.clone()),
                &wsv,
            )
            .expect("Failed to push tx into queue");

        queue
            .push(
                accepted_tx("bob@wonderland", 100_000, bob_key_pair.clone()),
                &wsv,
            )
            .expect("Failed to push tx into queue");
    }
}
