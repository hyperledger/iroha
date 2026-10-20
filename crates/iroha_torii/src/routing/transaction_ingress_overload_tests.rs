#[cfg(test)]
mod transaction_ingress_overload_tests {
    use super::*;
    use iroha_core::{
        kura::Kura,
        query::store::LiveQueryStore,
        queue::Queue,
        state::{State, World},
    };
    use iroha_logger::Level;
    use std::{
        num::{NonZeroU64, NonZeroUsize},
        sync::Arc,
        time::Duration,
    };
    fn signed_log_transaction(
        network_id: NetworkId,
        key_pair: &KeyPair,
        label: &str,
    ) -> SignedTransaction {
        let authority = AccountId::new(key_pair.public_key().clone());
        TransactionBuilder::new(
            network_id,
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(Log::new(
            Level::INFO,
            label.to_owned(),
        ))])
        .sign(key_pair.private_key())
    }
    fn checked_transaction_ingress_keypair(seed: u8, context: &'static str) -> KeyPair {
        checked_routing_fixture_keypair(seed, iroha_crypto::Algorithm::Ed25519, context)
    }
    #[test]
    fn transaction_ingress_precheck_rejects_incoming_batch_over_retained_byte_budget() {
        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let events: iroha_core::EventsSender = tokio::sync::broadcast::channel(8).0;
        let mut queue_cfg = iroha_config::parameters::actual::Queue {
            capacity: NonZeroUsize::new(32).expect("queue capacity non-zero"),
            capacity_per_user: NonZeroUsize::new(32).expect("queue per-user capacity non-zero"),
            transaction_time_to_live: Duration::from_secs(60),
            ..Default::default()
        };
        queue_cfg.max_retained_bytes =
            NonZeroU64::new(Queue::retained_byte_cost_floor_for_transactions(1))
                .expect("non-zero retained byte budget");
        let queue = Queue::from_config(queue_cfg, events);
        reject_ingress_if_queue_capacity_saturated(&queue, &state, 1)
            .expect("one incoming tx should fit the empty byte budget");
        let err = reject_ingress_if_queue_capacity_saturated(&queue, &state, 2)
            .expect_err("incoming batch should be shed before admission");
        match err {
            Error::PushIntoQueue {
                source,
                backpressure,
            } => {
                assert!(matches!(source.as_ref(), iroha_core::queue::Error::Full));
                assert!(backpressure.is_saturated());
            }
            other => panic!("expected queue backpressure error, got {other:?}"),
        }
    }
    routing_test! { async transaction_ingress_allows_latency_saturated_queue_before_capacity
        let mut world = World::default();
        crate::test_utils::bind_fixture_root(
            &mut world,
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        );
        let state = Arc::new(State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ));
        let events: iroha_core::EventsSender = tokio::sync::broadcast::channel(8).0;
        let queue = Arc::new(Queue::from_config(
            iroha_config::parameters::actual::Queue {
                capacity: NonZeroUsize::new(32).expect("queue capacity non-zero"),
                capacity_per_user: NonZeroUsize::new(32).expect("queue per-user capacity non-zero"),
                transaction_time_to_live: Duration::from_secs(60),
                ..Default::default()
            },
            events,
        ));
        let first_key_pair =
            checked_transaction_ingress_keypair(0x9A, "derive first ingress fixture signer key");
        let first = signed_log_transaction(*state.network_id_ref(), &first_key_pair, "first");
        handle_transaction(Arc::clone(&queue), Arc::clone(&state), first)
            .await
            .expect("first transaction should enter queue");
        queue.backdate_queued_transactions_for_tests(Duration::from_secs(3));
        let second_key_pair =
            checked_transaction_ingress_keypair(0x9B, "derive second ingress fixture signer key");
        let second = signed_log_transaction(*state.network_id_ref(), &second_key_pair, "second");
        handle_transaction(Arc::clone(&queue), Arc::clone(&state), second)
            .await
            .expect(
                "latency-saturated queue should accept fresh ingress until capacity is exhausted",
            );
        let pressure = queue.pressure_snapshot();
        assert!(
            pressure.saturated_by_age,
            "latency saturation must remain visible as queue pressure telemetry"
        );
        assert!(
            !pressure.saturated_by_count,
            "test setup should exercise age-only saturation before capacity"
        );
        let backpressure = queue.current_backpressure();
        assert!(
            !backpressure.is_saturated(),
            "age-only queue pressure must not close ingress before capacity"
        );
        assert_eq!(backpressure.queued(), 2);
        assert_eq!(backpressure.capacity().get(), 32);
    }
}
