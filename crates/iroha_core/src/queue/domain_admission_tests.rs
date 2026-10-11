// Signed network domains remain authoritative after a carrier is preaccepted elsewhere.
fn domain_admission_carriers(
    network: iroha_data_model::NetworkId,
    time: &TimeSource,
) -> [AcceptedTransaction<'static>; 3] {
    let authority = AccountId::new(ALICE_KEYPAIR.public_key().clone());
    let signed = TransactionBuilder::new_with_time_source(
        network,
        authority.clone(),
        time,
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "original queue domain".into())])
    .sign(ALICE_KEYPAIR.private_key());
    let now = signed.creation_time();
    let salt = [0xDA; 32];
    let commitment = compute_sealed_transaction_commitment(&network, &signed, salt, 9);
    [
        TransactionEntrypoint::External(signed.clone()),
        TransactionEntrypoint::SealedCommitment(SignedSealedTransactionCommitment::sign(
            SealedTransactionCommitmentPayload::new(network, authority, commitment, 2, 9, None),
            ALICE_KEYPAIR.private_key(),
        )),
        TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(commitment, signed, salt)),
    ]
    .map(|entrypoint| {
        AcceptedTransaction::accept_entrypoint_at_time(
            entrypoint,
            &network,
            Duration::ZERO,
            TransactionParameters::default(),
            &iroha_config::parameters::actual::Crypto::default(),
            now,
        )
        .expect("the original signed carrier is accepted in its own network")
    })
}

fn assert_preaccepted_foreign_domain_rejected(form: usize) {
    let (state, time) = current_admission_queue_fixture();
    register_test_authority(&state, &AccountId::new(ALICE_KEYPAIR.public_key().clone()));
    let foreign = iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        Hash::new(b"foreign-queue-original-network"),
    ));
    assert_ne!(&foreign, state.network_id_ref());
    let transactions = domain_admission_carriers(foreign, &time);
    let transaction = &transactions[form];
    let bytes = transaction.entrypoint_bytes();
    for boundary in 0..4 {
        let queue = Queue::test(config_factory(), &time);
        let plan = queue.route_plan_with_state(transaction, &state).unwrap();
        let result = match boundary {
            0 => queue.push(transaction.clone(), state.view()).map(|_| ()),
            1 => queue
                .push_with_lane_with_state(transaction.clone(), &state)
                .map(|_| ()),
            2 => queue
                .push_with_gossip_payload_with_state_and_routing_plan(
                    transaction.clone(),
                    &state,
                    plan.clone(),
                    Some(Arc::clone(&bytes)),
                )
                .map(|_| ()),
            _ => queue
                .push_batch_with_lane_with_state_and_routing_plans(
                    vec![(transaction.clone(), plan)],
                    &state,
                )
                .map(|_| ()),
        };
        let failure =
            result.expect_err("foreign preacceptance cannot authorize local queue custody");
        let Error::TransactionDomainMismatch(mismatch) = &failure.err else {
            panic!(
                "expected exact signed domain refusal, got {:?}",
                failure.err
            );
        };
        assert_eq!(
            mismatch.expected,
            TransactionDomain::Network(*state.network_id_ref())
        );
        assert_eq!(mismatch.actual, TransactionDomain::Network(foreign));
        assert_eq!(failure.tx.entrypoint(), transaction.entrypoint());
        assert!(Arc::ptr_eq(&failure.tx.entrypoint_bytes(), &bytes));
        assert_eq!(
            (
                queue.active_len(),
                queue.queued_len(),
                queue.retained_bytes()
            ),
            (0, 0, 0)
        );
        assert!(queue.txs.is_empty());
        assert!(queue.routing_plans.is_empty());
        assert!(queue.tx_encoded_len.is_empty());
        assert!(queue.tx_gas_cost.is_empty());
        assert!(queue.tx_gossip.is_empty());
        assert!(
            queue
                .fee_admission_reservations
                .lock()
                .live_by_entrypoint
                .is_empty()
        );
        assert!(queue.pending_sccp_exempt.lock().is_empty());
        assert!(!queue.admission_faulted());
        let local = domain_admission_carriers(*state.network_id_ref(), &time)[form].clone();
        queue
            .push(local.clone(), state.view())
            .expect("local signed work remains admissible");
        assert_eq!((queue.active_len(), queue.queued_len()), (1, 1));
        assert!(queue.txs.contains_key(&local.hash_as_entrypoint()));
        assert!(!queue.txs.contains_key(&transaction.hash_as_entrypoint()));
    }
}

#[test]
fn queue_rejects_preaccepted_foreign_external_before_custody() {
    assert_preaccepted_foreign_domain_rejected(0);
}

#[test]
fn queue_rejects_preaccepted_foreign_commitment_before_custody() {
    assert_preaccepted_foreign_domain_rejected(1);
}

#[test]
fn queue_rejects_preaccepted_foreign_reveal_before_custody() {
    assert_preaccepted_foreign_domain_rejected(2);
}

#[test]
fn queue_rejects_preaccepted_genesis_domain_before_custody() {
    let (state, _) = current_admission_queue_fixture();
    let authority = AccountId::new(ALICE_KEYPAIR.public_key().clone());
    let signed = TransactionBuilder::new_genesis(
        authority.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "genesis-only queue carrier".into())])
    .sign(ALICE_KEYPAIR.private_key());
    let (_, time) = TimeSource::new_mock(signed.creation_time());
    let genesis = AcceptedTransaction::accept_genesis(
        signed,
        Duration::from_secs(1),
        &authority,
        &iroha_config::parameters::actual::Crypto::default(),
    )
    .expect("the exact signed carrier satisfies genesis-only envelope admission");
    let original = genesis.entrypoint_bytes();
    let queue = Queue::test(config_factory(), &time);
    let failure = queue
        .push(genesis, state.view())
        .expect_err("genesis is never runtime ingress");
    let Error::TransactionDomainMismatch(mismatch) = failure.err else {
        panic!("expected the exact genesis-domain rejection");
    };
    assert_eq!(
        mismatch.expected,
        TransactionDomain::Network(*state.network_id_ref())
    );
    assert_eq!(mismatch.actual, TransactionDomain::Genesis);
    assert!(Arc::ptr_eq(&failure.tx.entrypoint_bytes(), &original));
    assert_eq!(
        (
            queue.active_len(),
            queue.queued_len(),
            queue.retained_bytes()
        ),
        (0, 0, 0)
    );
    assert!(queue.tx_gossip.is_empty());
    assert!(queue.routing_plans.is_empty());
    assert!(
        queue
            .fee_admission_reservations
            .lock()
            .live_by_entrypoint
            .is_empty()
    );
}

#[test]
fn queue_domain_batch_retains_only_accepted_prefix_and_accepts_local_retry() {
    let (state, time) = current_admission_queue_fixture();
    let local = domain_admission_carriers(*state.network_id_ref(), &time);
    let network = iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        Hash::new(b"foreign-domain-batch"),
    ));
    let foreign = domain_admission_carriers(network, &time)[1].clone();
    let original = foreign.entrypoint_bytes();
    let queue = Queue::test(config_factory(), &time);
    let plan = queue.route_plan_with_state(&local[0], &state).unwrap();
    let error = queue
        .push_batch_with_lane_with_state_and_routing_plans(
            vec![
                (local[0].clone(), plan.clone()),
                (foreign.clone(), plan.clone()),
                (local[2].clone(), plan),
            ],
            &state,
        )
        .expect_err("the exact accepted batch prefix ends before a foreign signed domain");
    assert!(matches!(error.err, Error::TransactionDomainMismatch(_)));
    assert!(Arc::ptr_eq(&error.tx.entrypoint_bytes(), &original));
    assert_eq!((queue.active_len(), queue.queued_len()), (1, 1));
    assert!(queue.txs.contains_key(&local[0].hash_as_entrypoint()));
    assert!(!queue.txs.contains_key(&foreign.hash_as_entrypoint()));
    assert!(!queue.txs.contains_key(&local[2].hash_as_entrypoint()));
    assert_eq!(queue.tx_gossip.len(), 1);
    assert_eq!(queue.routing_plans.len(), 1);
    assert_eq!(queue.tx_encoded_len.len(), 1);
    queue
        .push(local[2].clone(), state.view())
        .expect("local retry after batch refusal");
    assert_eq!((queue.active_len(), queue.queued_len()), (2, 2));
    assert_eq!(queue.tx_gossip.len(), 2);
    assert!(!queue.admission_faulted());
}
