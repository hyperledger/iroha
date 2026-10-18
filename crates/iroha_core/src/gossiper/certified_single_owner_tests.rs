// Certified gossip carries one canonical input and preserves physical queue/credit custody.

// Real signed wire measurements guard the cap counter and its canonical framing.
fn gossip_boundary_message(transaction: GossipTransaction) -> TransactionGossip {
    TransactionGossip {
        txs: vec![transaction],
        routes: vec![GossipRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
        }],
        plans: vec![default_plan()],
        plane: GossipPlane::Public,
    }
}

fn gossip_boundary_relay_keys() -> (KeyPair, PeerId) {
    let sender = KeyPair::try_from_seed(vec![0xE5; 32], Algorithm::BlsNormal).unwrap();
    let target = KeyPair::try_from_seed(vec![0xE6; 32], Algorithm::BlsNormal).unwrap();
    (sender, PeerId::new(target.public_key().clone()))
}

fn assert_exact_gossip_frame_boundary(
    message: &TransactionGossip,
    config: &NetworkConfig,
    sender_key: &KeyPair,
    target: &PeerId,
) {
    let sender = PeerId::new(sender_key.public_key().clone());
    let gossip_len = message.encode().len();
    assert_eq!(
        gossip_len,
        tx_gossip_frame_payload_cap(config, &sender, target)
    );
    let payload = NetworkMessage::TransactionGossiper(Arc::new(message.clone()));
    for peer in [None, Some(target)] {
        let materialized = iroha_p2p::network::materialized_signed_data_frame_len_for_test(
            sender_key,
            peer.cloned(),
            payload.clone(),
        )
        .expect("the real direct/broadcast envelope must sign, encode and authenticate");
        assert_eq!(
            Some(materialized),
            tx_gossip_data_frame_len(&sender, peer, gossip_len),
            "count NetworkMessage and P2P framing exactly, including compact prefixes"
        );
        assert_eq!(
            materialized,
            iroha_p2p::network::data_frame_wire_len(&sender, peer, &payload)
        );
        assert!(materialized <= config.max_frame_bytes_tx_gossip);
        assert!(materialized <= iroha_p2p::frame_plaintext_cap(config.max_frame_bytes));
        if peer.is_some() {
            assert_eq!(materialized, config.max_frame_bytes_tx_gossip);
        }
    }
    let mut below = config.clone();
    below.max_frame_bytes_tx_gossip -= 1;
    assert_eq!(
        tx_gossip_frame_payload_cap(&below, &sender, target),
        gossip_len - 1,
        "a one-byte-smaller topic cap must exclude this exact signed frame"
    );
    assert!(
        tx_gossip_data_frame_len(&sender, Some(target), gossip_len + 1).unwrap()
            > config.max_frame_bytes_tx_gossip,
        "the accepted inner budget must be maximal"
    );
    // Independently make the encrypted frame limit the binding constraint.
    let encryption_overhead = 1024 - iroha_p2p::frame_plaintext_cap(1024);
    let mut encrypted = config.clone();
    encrypted.max_frame_bytes_tx_gossip += 1;
    encrypted.max_frame_bytes = config.max_frame_bytes_tx_gossip + encryption_overhead;
    assert_eq!(
        iroha_p2p::frame_plaintext_cap(encrypted.max_frame_bytes),
        config.max_frame_bytes_tx_gossip
    );
    assert_eq!(
        tx_gossip_frame_payload_cap(&encrypted, &sender, target),
        gossip_len
    );
    encrypted.max_frame_bytes -= 1;
    assert_eq!(
        tx_gossip_frame_payload_cap(&encrypted, &sender, target),
        gossip_len - 1
    );
}

#[test]
fn ordinary_gossip_exact_frame_boundary_preserves_original_body_on_requeue() {
    let mut config = test_network_config(socket_addr!(127.0.0.1:0));
    // Keep the exact-boundary fixture smaller than the independent transaction cap.
    config.max_frame_bytes_tx_gossip = 256 * 1024;
    let (sender_key, target) = gossip_boundary_relay_keys();
    let sender = PeerId::new(sender_key.public_key().clone());
    let cap = tx_gossip_frame_payload_cap(&config, &sender, &target);
    let initial_label_len = 160 * 1024;
    let (initial, _) = build_transaction(&"x".repeat(initial_label_len));
    let initial_len = gossip_boundary_message(initial.into()).encode().len();
    let label_len = initial_label_len + cap.checked_sub(initial_len).unwrap();
    let (signed, accepted) = build_transaction(&"x".repeat(label_len));
    signed.verify_signature().unwrap();
    let original_payload = payload_for(&signed);
    let message = gossip_boundary_message(signed.clone().into());
    assert_exact_gossip_frame_boundary(&message, &config, &sender_key, &target);

    let mut gossiper = closed_test_gossiper(NonZeroU32::new(1).unwrap());
    gossiper
        .queue
        .push(accepted, gossiper.state.view())
        .unwrap();
    let selected = gossiper.queue.gossip_batch_with_state(1, &gossiper.state);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].payload.as_slice(), original_payload.as_slice());
    let mut below = config.clone();
    below.max_frame_bytes_tx_gossip -= 1;
    let refused = partition_gossip_batch(
        1,
        tx_gossip_frame_payload_cap(&below, &sender, &target),
        GossipPlane::Public,
        selected,
    );
    assert!(refused.message.txs.is_empty());
    assert_eq!(refused.requeue, vec![signed.hash_as_entrypoint()]);
    gossiper.defer_gossip_hashes(refused.requeue);
    assert_eq!(gossiper.queue.queued_len(), 1);
    gossiper.advance_gossip_tick();
    gossiper.release_deferred_gossip();
    let restored = gossiper.queue.gossip_batch_with_state(1, &gossiper.state);
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].payload.as_slice(), original_payload.as_slice());
    let retry = partition_gossip_batch(1, cap, GossipPlane::Public, restored);
    assert!(retry.requeue.is_empty());
    assert_eq!(retry.message.encode(), message.encode());
    assert_eq!(
        retry.message.txs[0].hash(),
        Some(signed.hash_as_entrypoint())
    );
    assert_eq!(
        retry.message.txs[0].payload().as_slice(),
        original_payload.as_slice()
    );
    assert_eq!(gossiper.queue.queued_len(), 1);
}

#[test]
fn shipped_gossip_frames_carry_the_maximum_admitted_signed_transaction() {
    let config = test_network_config(socket_addr!(127.0.0.1:0));
    let limits = iroha_data_model::parameter::system::TransactionParameters::default();
    let transaction_cap = usize::try_from(limits.max_tx_bytes().get()).unwrap();
    assert_eq!(transaction_cap, 10 * 1024 * 1024);
    let initial_label_len = transaction_cap / 2;
    let (initial, _) = build_transaction(&"x".repeat(initial_label_len));
    let initial_len = norito::canonical_frame_len(&initial).unwrap();
    // Both payloads lie in the same compact-length interval, so only log bytes grow.
    let label_len = initial_label_len + transaction_cap.checked_sub(initial_len).unwrap();
    let (signed, _) = build_transaction(&"x".repeat(label_len));
    let canonical = norito::encode_canonical(&signed).unwrap();
    assert_eq!(canonical.len(), transaction_cap);
    let decoded: SignedTransaction = norito::decode_canonical(&canonical).unwrap();
    assert_eq!(decoded, signed);
    let crypto = iroha_config::parameters::actual::Crypto::default();
    AcceptedTransaction::validate_with_now(
        &signed,
        &test_network_id(),
        Duration::ZERO,
        limits,
        &crypto,
        signed.creation_time(),
    )
    .expect("a maximum-sized ordinary transaction passes stateless admission");
    let (too_large, _) = build_transaction(&"x".repeat(label_len + 1));
    assert_eq!(
        norito::canonical_frame_len(&too_large).unwrap(),
        transaction_cap + 1
    );
    let error = AcceptedTransaction::validate_with_now(
        &too_large,
        &test_network_id(),
        Duration::ZERO,
        limits,
        &crypto,
        too_large.creation_time(),
    )
    .expect_err("one additional signed byte must exceed the governed transaction cap");
    assert!(
        matches!(error, AcceptTransactionFail::TransactionLimit(limit)
        if limit.reason.contains("Transaction size"))
    );

    let (sender_key, target) = gossip_boundary_relay_keys();
    let sender = PeerId::new(sender_key.public_key().clone());
    let message = gossip_boundary_message(signed.into());
    let gossip_len = message.encode().len();
    assert!(gossip_len <= tx_gossip_frame_payload_cap(&config, &sender, &target));
    let payload = NetworkMessage::TransactionGossiper(Arc::new(message));
    for peer in [None, Some(&target)] {
        let materialized = iroha_p2p::network::materialized_signed_data_frame_len_for_test(
            &sender_key,
            peer.cloned(),
            payload.clone(),
        )
        .expect("real direct/broadcast relay must sign, encode and authenticate");
        assert_eq!(
            Some(materialized),
            tx_gossip_data_frame_len(&sender, peer, gossip_len)
        );
        assert_eq!(
            materialized,
            iroha_p2p::network::data_frame_wire_len(&sender, peer, &payload)
        );
        assert!(materialized <= config.max_frame_bytes_tx_gossip);
        assert!(materialized <= iroha_p2p::frame_plaintext_cap(config.max_frame_bytes));
        println!(
            "MAXIMUM_TRANSACTION_GOSSIP signed={transaction_cap} gossip={gossip_len} direct={} frame={materialized}",
            peer.is_some()
        );
    }
}
