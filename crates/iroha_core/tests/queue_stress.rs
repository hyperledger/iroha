//! Stress tests for the transaction queue to guard against Arc drain panics.

use iroha_config::parameters::actual::Queue as QueueConfig;
use iroha_core::{
    queue::Queue,
    state::{State, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    tx::AcceptedTransaction,
};
use iroha_crypto::KeyPair;
use iroha_data_model::{domain::Domain, prelude::*};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use nonzero_ext::nonzero;
use std::{borrow::Cow, num::NonZeroUsize, sync::Arc, thread, time::Duration};
fn checked_random_queue_stress_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked queue stress transaction keypair")
}
#[test]
fn queue_stress_fixture_uses_checked_randomness() {
    let _key_pair = checked_random_queue_stress_keypair();
}
fn build_state() -> (
    Arc<State>,
    NetworkId,
    AccountId,
    KeyPair,
    CertifiedTestChain,
) {
    let key_pair = checked_random_queue_stress_keypair();
    let (public_key, _) = key_pair.clone().into_parts();
    let domain_id: DomainId =
        DomainId::try_new("queue-stress", "universal").expect("static domain id");
    let account_id = AccountId::of(public_key);
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let world = World::with([domain], [account], std::iter::empty());
    // Queue fee admission reads the immutable root installed by actual signed genesis.
    let mut config = TestChainConfig::new(world, 0);
    config.chain_id = ChainId::from("queue-stress-chain");
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
        // This regression exercises reclamation on every bounded snapshot, not
        // the independent one-second production sweep throttle.
        expired_cull_interval: Duration::ZERO,
        ..QueueConfig::default()
    }
}
fn make_transaction(
    network_id: &NetworkId,
    authority: &AccountId,
    key_pair: &KeyPair,
    nonce: usize,
    ttl: Duration,
) -> AcceptedTransaction<'static> {
    let mut builder = TransactionBuilder::new(
        *network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, format!("noop-{nonce}"))]);
    builder.set_ttl(ttl);
    let tx = builder.sign(key_pair.private_key());
    AcceptedTransaction::new_unchecked(Cow::Owned(tx))
}
#[test]
fn expired_transactions_drain_without_panic() {
    let (state, chain_id, authority, key_pair, _chain) = build_state();
    let (events_sender, _events_receiver) = tokio::sync::broadcast::channel(8);
    let queue = Arc::new(Queue::from_config(
        queue_config(4, Duration::from_secs(1)),
        events_sender,
    ));
    // Transactions expire quickly, triggering queue drain paths that previously panicked when
    // draining Arc-backed transactions with outstanding clones.
    let iterations = 32;
    for i in 0..iterations {
        let tx = make_transaction(
            &chain_id,
            &authority,
            &key_pair,
            i,
            Duration::from_millis(20),
        );
        let retained = tx.clone();
        queue
            .push(tx, state.view())
            .expect("queue accepts new transaction");
        thread::sleep(Duration::from_millis(30));
        assert!(queue.is_expired(&retained), "original signed input expired");
        let view = state.view();
        let pending = queue
            .bounded_pending_snapshot_for_testing(&view, nonzero!(1_usize))
            .expect("healthy queue snapshot");
        drop(view);
        assert!(pending.is_empty(), "expired tx should not remain available");
        assert_eq!(queue.queued_len(), 0, "queue drained expired transaction");
        assert!(
            queue.is_expired(&retained),
            "outstanding original clone remains valid to inspect"
        );
    }
}
