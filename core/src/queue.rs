//! Module with queue actor
use core::time::Duration;
use std::{num::NonZeroUsize, ops::Deref, sync::Arc};

use crossbeam_queue::ArrayQueue;
use dashmap::{mapref::entry::Entry, DashMap};
use eyre::Result;
use indexmap::IndexSet;
use iroha_config::parameters::actual::Queue as Config;
use iroha_crypto::HashOf;
use iroha_data_model::{
    account::AccountId,
    events::pipeline::{TransactionEvent, TransactionStatus},
    transaction::prelude::*,
};
use iroha_logger::{trace, warn};
use iroha_primitives::time::TimeSource;
use rand::seq::IteratorRandom;
use thiserror::Error;

use crate::{prelude::*, EventsSender};

impl AcceptedTransaction {
    // TODO: We should have another type of transaction like `CheckedTransaction` in the type system?
    /// Check if [`self`] is committed or rejected.
    fn is_in_blockchain(&self, state_view: &StateView<'_>) -> bool {
        state_view.has_transaction(self.as_ref().hash())
    }
}

/// Lockfree queue for transactions
///
/// Multiple producers, single consumer
#[derive(Debug)]
pub struct Queue {
    events_sender: EventsSender,
    /// The queue for transactions
    tx_hashes: ArrayQueue<HashOf<SignedTransaction>>,
    /// [`AcceptedTransaction`]s addressed by `Hash`
    accepted_txs: DashMap<HashOf<SignedTransaction>, AcceptedTransaction>,
    /// Amount of transactions per user in the queue
    txs_per_user: DashMap<AccountId, usize>,
    /// The maximum number of transactions in the queue
    capacity: NonZeroUsize,
    /// The maximum number of transactions in the queue per user. Used to apply throttling
    capacity_per_user: NonZeroUsize,
    /// The time source used to check transaction against
    ///
    /// A mock time source is used in tests for determinism
    time_source: TimeSource,
    /// Length of time after which transactions are dropped.
    pub tx_time_to_live: Duration,
    /// A point in time that is considered `Future` we cannot use
    /// current time, because of network time synchronisation issues
    future_threshold: Duration,
}

/// Queue push error
#[derive(Error, Copy, Clone, Debug, displaydoc::Display)]
#[allow(variant_size_differences)]
pub enum Error {
    /// Queue is full
    Full,
    /// Transaction is regarded to have been tampered to have a future timestamp
    InFuture,
    /// Transaction expired
    Expired,
    /// Transaction is already applied
    InBlockchain,
    /// User reached maximum number of transactions in the queue
    MaximumTransactionsPerUser,
    /// The transaction is already in the queue
    IsInQueue,
}

/// Failure that can pop up when pushing transaction into the queue
#[derive(Debug)]
pub struct Failure {
    /// Transaction failed to be pushed into the queue
    pub tx: AcceptedTransaction,
    /// Push failure reason
    pub err: Error,
}

/// Will remove transaction from the queue on drop.
/// See [`Queue::remove_stale_transaction`] for details.
pub struct TransactionGuard {
    tx: AcceptedTransaction,
    queue: Arc<Queue>,
}

impl Deref for TransactionGuard {
    type Target = AcceptedTransaction;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl Drop for TransactionGuard {
    fn drop(&mut self) {
        self.queue.remove_stale_transaction(&self.tx);
    }
}

impl Queue {
    /// Makes queue from configuration
    pub fn from_config(
        Config {
            capacity,
            capacity_per_user,
            transaction_time_to_live,
            future_threshold,
        }: Config,
        events_sender: EventsSender,
    ) -> Self {
        Self {
            events_sender,
            tx_hashes: ArrayQueue::new(capacity.get()),
            accepted_txs: DashMap::new(),
            txs_per_user: DashMap::new(),
            capacity,
            capacity_per_user,
            time_source: TimeSource::new_system(),
            tx_time_to_live: transaction_time_to_live,
            future_threshold,
        }
    }

    fn is_pending(&self, tx: &AcceptedTransaction, state_view: &StateView) -> bool {
        !self.is_expired(tx) && !tx.is_in_blockchain(state_view)
    }

    /// Checks if the transaction is waiting longer than its TTL or than the TTL from [`Config`].
    pub fn is_expired(&self, tx: &AcceptedTransaction) -> bool {
        let tx_creation_time = tx.as_ref().creation_time();

        let time_limit = tx.as_ref().time_to_live().map_or_else(
            || self.tx_time_to_live,
            |tx_time_to_live| core::cmp::min(self.tx_time_to_live, tx_time_to_live),
        );

        let curr_time = self.time_source.get_unix_time();
        curr_time.saturating_sub(tx_creation_time) > time_limit
    }

    /// If `true`, this transaction is regarded to have been tampered to have a future timestamp.
    fn is_in_future(&self, tx: &AcceptedTransaction) -> bool {
        let tx_timestamp = tx.as_ref().creation_time();
        let curr_time = self.time_source.get_unix_time();
        tx_timestamp.saturating_sub(curr_time) > self.future_threshold
    }

    /// Returns all pending transactions.
    pub fn all_transactions<'state>(
        &'state self,
        state_view: &'state StateView,
    ) -> impl Iterator<Item = AcceptedTransaction> + 'state {
        self.accepted_txs.iter().filter_map(|tx| {
            if self.is_pending(tx.value(), state_view) {
                return Some(tx.value().clone());
            }

            None
        })
    }

    /// Returns `n` randomly selected transaction from the queue.
    pub fn n_random_transactions(
        &self,
        n: u32,
        state_view: &StateView,
    ) -> Vec<AcceptedTransaction> {
        self.accepted_txs
            .iter()
            .filter(|e| self.is_pending(e.value(), state_view))
            .map(|e| e.value().clone())
            .choose_multiple(
                &mut rand::thread_rng(),
                n.try_into().expect("u32 should always fit in usize"),
            )
    }

    fn check_tx(&self, tx: &AcceptedTransaction, state_view: &StateView) -> Result<(), Error> {
        if self.is_in_future(tx) {
            Err(Error::InFuture)
        } else if self.is_expired(tx) {
            Err(Error::Expired)
        } else if tx.is_in_blockchain(state_view) {
            Err(Error::InBlockchain)
        } else {
            Ok(())
        }
    }

    /// Push transaction into queue.
    ///
    /// # Errors
    /// See [`enum@Error`]
    pub fn push(&self, tx: AcceptedTransaction, state_view: &StateView) -> Result<(), Failure> {
        trace!(tx=%tx.as_ref().hash(), "Pushing to the queue");
        if let Err(err) = self.check_tx(&tx, state_view) {
            return Err(Failure { tx, err });
        }

        // Get `txs_len` before entry to avoid deadlock
        let txs_len = self.accepted_txs.len();
        let hash = tx.as_ref().hash();
        let entry = match self.accepted_txs.entry(hash) {
            Entry::Occupied(_) => {
                return Err(Failure {
                    tx,
                    err: Error::IsInQueue,
                })
            }
            Entry::Vacant(entry) => entry,
        };

        if txs_len >= self.capacity.get() {
            warn!(
                max = self.capacity,
                "Achieved maximum amount of transactions"
            );
            return Err(Failure {
                tx,
                err: Error::Full,
            });
        }

        if let Err(err) = self.check_and_increase_per_user_tx_count(tx.as_ref().authority()) {
            return Err(Failure { tx, err });
        }

        // Insert entry first so that the `tx` popped from `queue` will always have a `(hash, tx)` record in `txs`.
        entry.insert(tx);
        self.tx_hashes.push(hash).map_err(|err_hash| {
            warn!("Queue is full");
            let (_, err_tx) = self
                .accepted_txs
                .remove(&err_hash)
                .expect("Inserted just before match");
            self.decrease_per_user_tx_count(err_tx.as_ref().authority());
            Failure {
                tx: err_tx,
                err: Error::Full,
            }
        })?;
        let _ = self.events_sender.send(
            TransactionEvent {
                hash,
                block_height: None,
                status: TransactionStatus::Queued,
            }
            .into(),
        );
        trace!("Transaction queue length = {}", self.tx_hashes.len(),);
        Ok(())
    }

    /// Pop single transaction from the queue. Removes all transactions that fail the `tx_check`.
    fn pop_from_queue(
        self: &Arc<Self>,
        state_view: &StateView,
        expired_transactions: &mut Vec<AcceptedTransaction>,
    ) -> Option<TransactionGuard> {
        loop {
            let hash = self.tx_hashes.pop()?;

            let entry = match self.accepted_txs.entry(hash) {
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
            if let Err(e) = self.check_tx(tx, state_view) {
                let (_, tx) = entry.remove_entry();
                self.decrease_per_user_tx_count(tx.as_ref().authority());
                if let Error::Expired = e {
                    expired_transactions.push(tx);
                }
                continue;
            }

            let guard = TransactionGuard {
                tx: tx.clone(),
                queue: Arc::clone(self),
            };
            return Some(guard);
        }
    }

    /// Return the number of transactions in the queue.
    pub fn tx_len(&self) -> usize {
        self.accepted_txs.len()
    }

    /// Gets transactions till they fill whole block or till the end of queue.
    ///
    /// BEWARE: Shouldn't be called in parallel with itself.
    #[cfg(test)]
    fn collect_transactions_for_block(
        self: &Arc<Self>,
        state_view: &StateView,
        max_txs_in_block: NonZeroUsize,
    ) -> Vec<TransactionGuard> {
        let mut transactions = Vec::with_capacity(max_txs_in_block.get());
        self.get_transactions_for_block(state_view, max_txs_in_block, &mut transactions);
        transactions
    }

    /// Put transactions into provided vector until they fill the whole block or there are no more transactions in the queue.
    ///
    /// BEWARE: Shouldn't be called in parallel with itself.
    pub fn get_transactions_for_block(
        self: &Arc<Self>,
        state_view: &StateView,
        max_txs_in_block: NonZeroUsize,
        transactions: &mut Vec<TransactionGuard>,
    ) {
        if transactions.len() >= max_txs_in_block.get() {
            return;
        }

        let mut expired_transactions = Vec::new();

        let txs_from_queue =
            core::iter::from_fn(|| self.pop_from_queue(state_view, &mut expired_transactions));

        let transactions_hashes: IndexSet<HashOf<SignedTransaction>> =
            transactions.iter().map(|tx| tx.as_ref().hash()).collect();
        let txs = txs_from_queue
            .filter(|tx| !transactions_hashes.contains(&tx.as_ref().hash()))
            .take(max_txs_in_block.get() - transactions.len());
        transactions.extend(txs);

        expired_transactions
            .into_iter()
            .map(|tx| TransactionEvent {
                hash: tx.as_ref().hash(),
                block_height: None,
                status: TransactionStatus::Expired,
            })
            .for_each(|e| {
                let _ = self.events_sender.send(e.into());
            });
    }

    /// Overview:
    /// 1. Transaction is added to queue using [`Queue::push`] method.
    /// 2. Transaction is moved to [`Sumeragi::transaction_cache`] using [`Queue::pop_from_queue`] method.
    ///    Note that transaction is removed from [`Queue::tx_hashes`], but kept in [`Queue::accepted_tx`],
    ///    this is needed to return `Error::IsInQueue` when adding same transaction twice.
    /// 3. When transaction is removed from [`Sumeragi::transaction_cache`]
    ///    (either because it was expired, or because transaction is commited to blockchain),
    ///    we should remove transaction from [`Queue::accepted_tx`].
    fn remove_stale_transaction(&self, tx: &AcceptedTransaction) {
        let removed = self.accepted_txs.remove(&tx.as_ref().hash());
        if removed.is_some() {
            self.decrease_per_user_tx_count(tx.as_ref().authority());

            if self.is_expired(tx) {
                let event = TransactionEvent {
                    hash: tx.as_ref().hash(),
                    block_height: None,
                    status: TransactionStatus::Expired,
                };
                let _ = self.events_sender.send(event.into());
            }
        }
    }

    /// Check that the user adhered to the maximum transaction per user limit and increment their transaction count.
    fn check_and_increase_per_user_tx_count(&self, account_id: &AccountId) -> Result<(), Error> {
        match self.txs_per_user.entry(account_id.clone()) {
            Entry::Vacant(vacant) => {
                vacant.insert(1);
            }
            Entry::Occupied(mut occupied) => {
                let txs = *occupied.get();
                if txs >= self.capacity_per_user.get() {
                    warn!(
                        max_txs_per_user = self.capacity_per_user,
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
        let Entry::Occupied(mut occupied) = self.txs_per_user.entry(account_id.clone()) else {
            panic!("Call to decrease always should be paired with increase count. This is a bug.")
        };

        let count = occupied.get_mut();
        if *count > 1 {
            *count -= 1;
        } else {
            occupied.remove_entry();
        }
    }
}

#[cfg(test)]
// this is `pub` to re-use internal utils
pub mod tests {
    use std::{str::FromStr, sync::Arc, thread, time::Duration};

    use iroha_data_model::{parameter::TransactionParameters, prelude::*};
    use nonzero_ext::nonzero;
    use rand::Rng as _;
    use test_samples::gen_account_in;
    use tokio::test;

    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        smartcontracts::isi::Registrable as _,
        state::{State, World},
    };

    impl Queue {
        pub fn test(cfg: Config, time_source: &TimeSource) -> Self {
            Self {
                events_sender: tokio::sync::broadcast::Sender::new(1),
                tx_hashes: ArrayQueue::new(cfg.capacity.get()),
                accepted_txs: DashMap::new(),
                txs_per_user: DashMap::new(),
                capacity: cfg.capacity,
                capacity_per_user: cfg.capacity_per_user,
                time_source: time_source.clone(),
                tx_time_to_live: cfg.transaction_time_to_live,
                future_threshold: cfg.future_threshold,
            }
        }
    }

    fn accepted_tx_by_someone(time_source: &TimeSource) -> AcceptedTransaction {
        let (account_id, key_pair) = gen_account_in("wonderland");
        accepted_tx_by(account_id, &key_pair, time_source)
    }

    fn accepted_tx_by(
        account_id: AccountId,
        key_pair: &KeyPair,
        time_source: &TimeSource,
    ) -> AcceptedTransaction {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");
        // Random name needed so all transactions will be different
        let domain_name = format!("dummy{}", rand::random::<u64>());
        let fail_isi = Unregister::domain(domain_name.parse().unwrap());
        let instructions = [fail_isi];
        let tx =
            TransactionBuilder::new_with_time_source(chain_id.clone(), account_id, time_source)
                .with_instructions(instructions)
                .sign(key_pair.private_key());
        let limits = TransactionParameters {
            max_instructions: nonzero!(4096_u64),
            smart_contract_size: nonzero!(1024_u64),
        };
        AcceptedTransaction::accept(tx, &chain_id, limits).expect("Failed to accept Transaction.")
    }

    pub fn world_with_test_domains() -> World {
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let (account_id, _account_keypair) = gen_account_in("wonderland");
        let domain = Domain::new(domain_id).build(&account_id);
        let account = Account::new(account_id.clone()).build(&account_id);
        World::with([domain], [account], [])
    }

    fn config_factory() -> Config {
        Config {
            transaction_time_to_live: Duration::from_secs(100),
            capacity: 100.try_into().unwrap(),
            ..Config::default()
        }
    }

    #[test]
    async fn push_tx() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let state_view = state.view();

        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());

        let queue = Queue::test(config_factory(), &time_source);

        queue
            .push(accepted_tx_by_someone(&time_source), &state_view)
            .expect("Failed to push tx into queue");
    }

    #[test]
    async fn push_tx_overflow() {
        let capacity = nonzero!(10_usize);

        let kura: Arc<Kura> = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let state_view = state.view();

        let (time_handle, time_source) = TimeSource::new_mock(Duration::default());

        let queue = Queue::test(
            Config {
                transaction_time_to_live: Duration::from_secs(100),
                capacity,
                ..Config::default()
            },
            &time_source,
        );

        for _ in 0..capacity.get() {
            queue
                .push(accepted_tx_by_someone(&time_source), &state_view)
                .expect("Failed to push tx into queue");
            time_handle.advance(Duration::from_millis(10));
        }

        assert!(matches!(
            queue.push(accepted_tx_by_someone(&time_source), &state_view),
            Err(Failure {
                err: Error::Full,
                ..
            })
        ));
    }

    #[test]
    async fn get_available_txs() {
        let max_txs_in_block = nonzero!(2_usize);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let state_view = state.view();

        let (time_handle, time_source) = TimeSource::new_mock(Duration::default());

        let queue = Queue::test(
            Config {
                transaction_time_to_live: Duration::from_secs(100),
                ..config_factory()
            },
            &time_source,
        );
        let queue = Arc::new(queue);
        for _ in 0..5 {
            queue
                .push(accepted_tx_by_someone(&time_source), &state_view)
                .expect("Failed to push tx into queue");
            time_handle.advance(Duration::from_millis(10));
        }

        let available = queue.collect_transactions_for_block(&state_view, max_txs_in_block);
        assert_eq!(available.len(), max_txs_in_block.get());
    }

    #[test]
    async fn push_tx_already_in_blockchain() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world_with_test_domains(), kura, query_handle);
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let tx = accepted_tx_by_someone(&time_source);
        let mut state_block = state.block();
        state_block
            .transactions
            .insert(tx.as_ref().hash(), nonzero!(1_usize));
        state_block.commit();
        let state_view = state.view();
        let queue = Queue::test(config_factory(), &time_source);
        assert!(matches!(
            queue.push(tx, &state_view),
            Err(Failure {
                err: Error::InBlockchain,
                ..
            })
        ));
        assert_eq!(queue.accepted_txs.len(), 0);
    }

    #[test]
    async fn get_tx_drop_if_in_blockchain() {
        let max_txs_in_block = nonzero!(2_usize);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world_with_test_domains(), kura, query_handle);
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let tx = accepted_tx_by_someone(&time_source);
        let queue = Queue::test(config_factory(), &time_source);
        let queue = Arc::new(queue);
        queue.push(tx.clone(), &state.view()).unwrap();
        let mut state_block = state.block();
        state_block
            .transactions
            .insert(tx.as_ref().hash(), nonzero!(1_usize));
        state_block.commit();
        assert_eq!(
            queue
                .collect_transactions_for_block(&state.view(), max_txs_in_block)
                .len(),
            0
        );
        assert_eq!(queue.accepted_txs.len(), 0);
    }

    #[test]
    async fn get_available_txs_with_timeout() {
        let max_txs_in_block = nonzero!(6_usize);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let state_view = state.view();

        let (time_handle, time_source) = TimeSource::new_mock(Duration::default());

        let queue = Queue::test(
            Config {
                transaction_time_to_live: Duration::from_millis(200),
                ..config_factory()
            },
            &time_source,
        );
        let queue = Arc::new(queue);
        for _ in 0..(max_txs_in_block.get() - 1) {
            queue
                .push(accepted_tx_by_someone(&time_source), &state_view)
                .expect("Failed to push tx into queue");
            time_handle.advance(Duration::from_millis(100));
        }

        queue
            .push(accepted_tx_by_someone(&time_source), &state_view)
            .expect("Failed to push tx into queue");
        time_handle.advance(Duration::from_millis(101));
        assert_eq!(
            queue
                .collect_transactions_for_block(&state_view, max_txs_in_block)
                .len(),
            1
        );

        queue
            .push(accepted_tx_by_someone(&time_source), &state_view)
            .expect("Failed to push tx into queue");
        time_handle.advance(Duration::from_millis(210));
        assert_eq!(
            queue
                .collect_transactions_for_block(&state_view, max_txs_in_block)
                .len(),
            0
        );
    }

    #[test]
    async fn custom_expired_transaction_is_rejected() {
        const TTL_MS: u64 = 200;

        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        let max_txs_in_block = nonzero!(2_usize);
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let state_view = state.view();

        let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let mut queue = Queue::test(config_factory(), &time_source);
        let (event_sender, mut event_receiver) = tokio::sync::broadcast::channel(1);
        queue.events_sender = event_sender;
        let fail_isi = Unregister::domain("dummy".parse().unwrap());
        let instructions = [fail_isi];
        let mut tx =
            TransactionBuilder::new_with_time_source(chain_id.clone(), alice_id, &time_source)
                .with_instructions(instructions);
        tx.set_ttl(Duration::from_millis(TTL_MS));
        let tx = tx.sign(alice_keypair.private_key());
        let limits = TransactionParameters {
            max_instructions: nonzero!(4096_u64),
            smart_contract_size: nonzero!(1024_u64),
        };
        let tx_hash = tx.hash();
        let tx = AcceptedTransaction::accept(tx, &chain_id, limits)
            .expect("Failed to accept Transaction.");
        queue
            .push(tx.clone(), &state_view)
            .expect("Failed to push tx into queue");
        let queued_tx_event = event_receiver.recv().await.unwrap();

        assert_eq!(
            queued_tx_event,
            TransactionEvent {
                hash: tx_hash,
                block_height: None,
                status: TransactionStatus::Queued,
            }
            .into()
        );

        let mut txs = Vec::new();
        time_handle.advance(Duration::from_millis(TTL_MS + 1));
        let queue = Arc::new(queue);
        queue.get_transactions_for_block(&state_view, max_txs_in_block, &mut txs);
        let expired_tx_event = event_receiver.recv().await.unwrap();
        assert!(txs.is_empty());

        assert_eq!(
            expired_tx_event,
            TransactionEvent {
                hash: tx_hash,
                block_height: None,
                status: TransactionStatus::Expired,
            }
            .into()
        )
    }

    #[test]
    async fn concurrent_stress_test() {
        let max_txs_in_block = nonzero!(10_usize);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));

        let (time_handle, time_source) = TimeSource::new_mock(Duration::default());

        let queue = Arc::new(Queue::test(
            Config {
                transaction_time_to_live: Duration::from_secs(100),
                capacity: 100_000_000.try_into().unwrap(),
                ..Config::default()
            },
            &time_source,
        ));

        let start_time = std::time::Instant::now();
        let run_for = Duration::from_secs(5);

        let push_txs_handle = {
            let queue_arc_clone = Arc::clone(&queue);
            let state = state.clone();

            // Spawn a thread where we push transactions
            thread::spawn(move || {
                while start_time.elapsed() < run_for {
                    let tx = accepted_tx_by_someone(&time_source);
                    match queue_arc_clone.push(tx, &state.view()) {
                        Ok(())
                        | Err(Failure {
                            err: Error::Full | Error::MaximumTransactionsPerUser,
                            ..
                        }) => (),
                        Err(Failure { err, .. }) => panic!("{err}"),
                    }
                }
            })
        };

        // Spawn a thread where we get_transactions_for_block and add them to state
        let get_txs_handle = {
            let queue = Arc::clone(&queue);

            thread::spawn(move || {
                while start_time.elapsed() < run_for {
                    for tx in queue.collect_transactions_for_block(&state.view(), max_txs_in_block)
                    {
                        let mut state_block = state.block();
                        state_block
                            .transactions
                            .insert(tx.as_ref().hash(), nonzero!(1_usize));
                        state_block.commit();
                    }
                    // Simulate random small delays
                    let delay = Duration::from_millis(rand::thread_rng().gen_range(0..25));
                    thread::sleep(delay);
                    time_handle.advance(delay);
                }
            })
        };

        push_txs_handle.join().unwrap();
        get_txs_handle.join().unwrap();

        // Validate the queue state.
        let array_queue: Vec<_> = core::iter::from_fn(|| queue.tx_hashes.pop()).collect();

        assert_eq!(array_queue.len(), queue.accepted_txs.len());
        for tx in array_queue {
            assert!(queue.accepted_txs.contains_key(&tx));
        }
    }

    #[test]
    async fn push_tx_in_future() {
        let future_threshold = Duration::from_secs(1);

        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let state_view = state.view();

        let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Queue::test(
            Config {
                future_threshold,
                ..Config::default()
            },
            &time_source,
        );

        let tx = accepted_tx_by_someone(&time_source);
        assert!(queue.push(tx.clone(), &state_view).is_ok());

        // create the same tx but with timestamp in the future
        time_handle.advance(future_threshold * 2);
        let tx = accepted_tx_by_someone(&time_source);
        time_handle.rewind(future_threshold * 2);

        assert!(matches!(
            queue.push(tx, &state_view),
            Err(Failure {
                err: Error::InFuture,
                ..
            })
        ));
        assert_eq!(queue.accepted_txs.len(), 1);
    }

    #[test]
    async fn queue_throttling() {
        let kura = Kura::blank_kura_for_testing();
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let (bob_id, bob_keypair) = gen_account_in("wonderland");
        let world = {
            let domain_id = DomainId::from_str("wonderland").expect("Valid");
            let domain = Domain::new(domain_id).build(&alice_id);
            let alice_account = Account::new(alice_id.clone()).build(&alice_id);
            let bob_account = Account::new(bob_id.clone()).build(&bob_id);
            World::with([domain], [alice_account, bob_account], [])
        };
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world, kura, query_handle);

        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());

        let queue = Queue::test(
            Config {
                transaction_time_to_live: Duration::from_secs(100),
                capacity: 100.try_into().unwrap(),
                capacity_per_user: 1.try_into().unwrap(),
                ..Config::default()
            },
            &time_source,
        );
        let queue = Arc::new(queue);

        // First push by Alice should be fine
        queue
            .push(
                accepted_tx_by(alice_id.clone(), &alice_keypair, &time_source),
                &state.view(),
            )
            .expect("Failed to push tx into queue");

        // Second push by Alice excide limit and will be rejected
        let result = queue.push(
            accepted_tx_by(alice_id.clone(), &alice_keypair, &time_source),
            &state.view(),
        );
        assert!(
            matches!(
                result,
                Err(Failure {
                    tx: _,
                    err: Error::MaximumTransactionsPerUser
                }),
            ),
            "Failed to match: {result:?}",
        );

        // First push by Bob should be fine despite previous Alice error
        queue
            .push(
                accepted_tx_by(bob_id.clone(), &bob_keypair, &time_source),
                &state.view(),
            )
            .expect("Failed to push tx into queue");

        let transactions = queue.collect_transactions_for_block(&state.view(), nonzero!(10_usize));
        assert_eq!(transactions.len(), 2);
        let mut state_block = state.block();
        for transaction in transactions {
            // Put transaction hashes into state as if they were in the blockchain
            state_block
                .transactions
                .insert(transaction.as_ref().hash(), nonzero!(1_usize));
        }
        state_block.commit();
        // Cleanup transactions
        let transactions = queue.collect_transactions_for_block(&state.view(), nonzero!(10_usize));
        assert!(transactions.is_empty());

        // After cleanup Alice and Bob pushes should work fine
        queue
            .push(
                accepted_tx_by(alice_id, &alice_keypair, &time_source),
                &state.view(),
            )
            .expect("Failed to push tx into queue");

        queue
            .push(
                accepted_tx_by(bob_id, &bob_keypair, &time_source),
                &state.view(),
            )
            .expect("Failed to push tx into queue");
    }
}
