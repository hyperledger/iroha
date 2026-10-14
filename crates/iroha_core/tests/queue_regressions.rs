//! Regression coverage for the transaction queue expiration and drain paths.

//!
//! These tests focus on making sure the queue rejects expired payloads and that the
//! ready/pending drain helpers stay panic-free under concurrent pressure.
use iroha_config::parameters::actual::Queue as QueueConfig;
use iroha_core::{
    queue::{Error as QueueError, Queue},
    state::{State, StateView, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    tx::AcceptedTransaction,
};
use iroha_crypto::KeyPair;
use iroha_data_model::{domain::Domain, prelude::*};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_primitives::time::TimeSource;
use nonzero_ext::nonzero;
use std::{borrow::Cow, collections::BTreeSet, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::time::sleep;
/// Read the queue's bounded ready snapshot and complete pending observation.
trait QueueDrainExt {
    fn drain_ready(
        &self,
        view: &StateView<'_>,
        limit: NonZeroUsize,
    ) -> Vec<AcceptedTransaction<'static>>;
    fn drain_pending(&self, view: &StateView<'_>) -> Vec<AcceptedTransaction<'static>>;
}
impl QueueDrainExt for Arc<Queue> {
    fn drain_ready(
        &self,
        view: &StateView<'_>,
        limit: NonZeroUsize,
    ) -> Vec<AcceptedTransaction<'static>> {
        self.bounded_pending_snapshot_for_testing(view, limit)
            .expect("healthy queue snapshot")
    }
    fn drain_pending(&self, view: &StateView<'_>) -> Vec<AcceptedTransaction<'static>> {
        self.all_transactions(view).collect()
    }
}
fn checked_random_queue_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked queue transaction keypair")
}
#[test]
fn queue_regression_fixture_uses_checked_randomness() {
    let _key_pair = checked_random_queue_keypair();
}
fn build_state() -> (
    Arc<State>,
    NetworkId,
    AccountId,
    KeyPair,
    CertifiedTestChain,
) {
    let key_pair = checked_random_queue_keypair();
    let (public_key, _) = key_pair.clone().into_parts();
    let domain_id: DomainId =
        DomainId::try_new("queue-regressions", "universal").expect("static domain id");
    let account_id = AccountId::of(public_key);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let world = World::with([domain], [account], std::iter::empty());
    // Queue fee admission reads the immutable root installed by actual signed genesis.
    let mut config = TestChainConfig::new(world, 0);
    config.chain_id = ChainId::from("queue-regressions-chain");
    let chain = CertifiedTestChain::start(config).expect("signed queue fixture genesis");
    let state = Arc::clone(chain.state());
    let network_id = *state.network_id_ref();
    // Retain the original executor, event receiver and signed-chain custody for the test.
    (state, network_id, account_id, key_pair, chain)
}
fn queue_config(capacity: usize, ttl: Duration) -> QueueConfig {
    QueueConfig {
        capacity: NonZeroUsize::new(capacity).expect("non-zero capacity"),
        capacity_per_user: NonZeroUsize::new(capacity).expect("non-zero per-user capacity"),
        transaction_time_to_live: ttl,
        ..QueueConfig::default()
    }
}
fn make_transaction(
    network_id: &NetworkId,
    authority: &AccountId,
    key_pair: &KeyPair,
    nonce: usize,
    ttl: Option<Duration>,
    creation_time: Duration,
) -> AcceptedTransaction<'static> {
    let mut builder = TransactionBuilder::new(
        *network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, format!("noop-{nonce}"))]);
    if let Some(ttl) = ttl {
        builder.set_ttl(ttl);
    }
    builder.set_creation_time(creation_time);
    let tx = builder.sign(key_pair.private_key());
    AcceptedTransaction::new_unchecked(Cow::Owned(tx))
}
#[test]
fn queue_rejects_explicitly_expired_transactions() {
    // Coverage: Queue::is_expired TTL override path (`queue.rs`).
    let (state, chain_id, authority, key_pair, _chain) = build_state();
    let (events_sender, _events_receiver) = tokio::sync::broadcast::channel(8);
    let queue = Queue::from_config(queue_config(8, Duration::from_secs(60)), events_sender);
    let expired = make_transaction(
        &chain_id,
        &authority,
        &key_pair,
        0,
        Some(Duration::from_secs(1)),
        Duration::from_secs(0),
    );
    assert!(queue.is_expired(&expired), "transaction should be expired");
    let view = state.view();
    let result = queue.push(expired, view);
    match result {
        Err(failure) => assert!(matches!(failure.err, QueueError::Expired)),
        Ok(()) => panic!("expired transaction unexpectedly enqueued"),
    }
    assert_eq!(queue.queued_len(), 0, "expired transaction must not linger");
}
#[test]
fn queue_rejects_transactions_expiring_by_config_ttl() {
    // Coverage: Queue::is_expired fallback to config TTL (`queue.rs`).
    let (state, chain_id, authority, key_pair, _chain) = build_state();
    let (events_sender, _events_receiver) = tokio::sync::broadcast::channel(4);
    let queue = Queue::from_config(queue_config(4, Duration::from_millis(10)), events_sender);
    let expired = make_transaction(
        &chain_id,
        &authority,
        &key_pair,
        1,
        None,
        Duration::from_secs(0),
    );
    assert!(
        queue.is_expired(&expired),
        "config TTL should expire transaction"
    );
    let view = state.view();
    let result = queue.push(expired, view);
    match result {
        Err(failure) => assert!(matches!(failure.err, QueueError::Expired)),
        Ok(()) => panic!("expired transaction unexpectedly enqueued"),
    }
    assert_eq!(queue.queued_len(), 0, "expired transaction must not linger");
}
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_ready_and_pending_drains_stay_consistent() {
    // Coverage: concurrent access to the queue drain loops (ready vs. pending).
    let (state, chain_id, authority, key_pair, _chain) = build_state();
    let (events_sender, _events_receiver) = tokio::sync::broadcast::channel(16);
    let queue = Arc::new(Queue::from_config(
        queue_config(64, Duration::from_secs(60)),
        events_sender,
    ));
    let now = TimeSource::new_system().get_unix_time();
    let mut expected_hashes = BTreeSet::new();
    // Pre-seed a few transactions to exercise both drain paths immediately.
    for nonce in 0..8 {
        let tx = make_transaction(
            &chain_id,
            &authority,
            &key_pair,
            nonce,
            Some(Duration::from_secs(120)),
            now,
        );
        assert!(
            !queue.is_expired(&tx),
            "seed transactions should remain valid during stress"
        );
        expected_hashes.insert(tx.hash_as_entrypoint());
        queue
            .push(tx, state.view())
            .expect("queue accepts seed transaction");
    }
    let queue_for_ready = Arc::clone(&queue);
    let state_for_ready = Arc::clone(&state);
    let ready_task = async move {
        for _ in 0..32 {
            let view = state_for_ready.view();
            let mut guards = queue_for_ready.drain_ready(&view, nonzero!(4_usize));
            drop(view);
            // Drop guards outside of the view to unblock subsequent drains.
            guards.clear();
            sleep(Duration::from_millis(2)).await;
        }
    };
    let queue_for_pending = Arc::clone(&queue);
    let state_for_pending = Arc::clone(&state);
    let pending_task = async move {
        for _ in 0..32 {
            let view = state_for_pending.view();
            let _pending = queue_for_pending.drain_pending(&view);
            drop(view);
            sleep(Duration::from_millis(1)).await;
        }
    };
    let queue_for_push = Arc::clone(&queue);
    let state_for_push = Arc::clone(&state);
    let chain_id_for_push = chain_id.clone();
    let authority_for_push = authority.clone();
    let key_pair_for_push = key_pair.clone();
    let push_task = async move {
        let mut injected_hashes = BTreeSet::new();
        for nonce in 8..64 {
            let tx = make_transaction(
                &chain_id_for_push,
                &authority_for_push,
                &key_pair_for_push,
                nonce,
                Some(Duration::from_secs(120)),
                TimeSource::new_system().get_unix_time(),
            );
            assert!(
                !queue_for_push.is_expired(&tx),
                "injected transaction is live"
            );
            injected_hashes.insert(tx.hash_as_entrypoint());
            queue_for_push
                .push(tx, state_for_push.view())
                .expect("queue accepts injected transaction during stress");
            sleep(Duration::from_millis(1)).await;
        }
        injected_hashes
    };
    let (_, _, injected_hashes) = tokio::join!(ready_task, pending_task, push_task);
    expected_hashes.extend(injected_hashes);
    // Snapshots retain all original signed inputs. The ready cursor may begin in
    // the middle of the FIFO after concurrent sampling; one bounded window
    // reaches its end, and the next covers the complete retained queue.
    assert_eq!(expected_hashes.len(), 64);
    let remaining = queue.queued_len();
    assert_eq!(remaining, 64);
    let view = state.view();
    let limit = NonZeroUsize::new(remaining).expect("non-zero queue length");
    let first = queue.drain_ready(&view, limit);
    assert!(first.len() <= remaining);
    assert!(
        first
            .iter()
            .all(|tx| expected_hashes.contains(&tx.hash_as_entrypoint()))
    );
    let guards = queue.drain_ready(&view, limit);
    assert_eq!(guards.len(), remaining);
    assert_eq!(
        guards
            .iter()
            .map(AcceptedTransaction::hash_as_entrypoint)
            .collect::<BTreeSet<_>>(),
        expected_hashes
    );
    let pending = queue.drain_pending(&view);
    assert_eq!(pending.len(), remaining);
    assert_eq!(
        pending
            .iter()
            .map(AcceptedTransaction::hash_as_entrypoint)
            .collect::<BTreeSet<_>>(),
        expected_hashes
    );
    drop(view);
    drop((first, guards, pending));
    assert_eq!(queue.queued_len(), remaining);
}
