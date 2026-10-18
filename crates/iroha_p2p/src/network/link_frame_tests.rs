// Link-local versus relayable frame regressions, included into `network::tests`.
//
// Direct-link frames carry no end-to-end origin signature: the authenticated,
// encrypted connection proves their sender. Only frames that a hop may forward
// to a third party are signed, and every present signature is verified.

/// Register `peer` as the authenticated owner of `connection_id`.
fn connect_link_test_peer<T: Pload>(
    network: &mut NetworkBase<T, ChaCha20Poly1305>,
    peer: &Peer,
    connection_id: ConnectionId,
    role: RelayRole,
) -> TestPeerReceivers<T> {
    let (handle, receivers) = test_wire_peer_handle::<T>(4);
    insert_ref_peer(
        network,
        peer.id().clone(),
        peer.address().clone(),
        connection_id,
        handle,
        true,
    );
    network
        .peers
        .get_mut(peer.id())
        .expect("inserted link peer")
        .relay_role = role;
    receivers
}
#[test]
fn only_forwarding_hops_require_an_origin_signature() {
    let next_hop = random_peer_id();
    let other = random_peer_id();
    for role in [RelayRole::Disabled, RelayRole::Spoke, RelayRole::Hub] {
        assert!(
            !hop_requires_origin_signature(&RelayTarget::Direct(next_hop.clone()), &next_hop, role),
            "a direct target consumes its own frame"
        );
        assert!(
            hop_requires_origin_signature(&RelayTarget::Direct(other.clone()), &next_hop, role),
            "a direct frame for another peer is relayed by the hop"
        );
    }
    assert!(hop_requires_origin_signature(
        &RelayTarget::Broadcast,
        &next_hop,
        RelayRole::Hub
    ));
    for role in [RelayRole::Disabled, RelayRole::Spoke] {
        assert!(!hop_requires_origin_signature(
            &RelayTarget::Broadcast,
            &next_hop,
            role
        ));
    }
}

#[test]
fn streamed_relay_digest_matches_the_materialized_preimage() {
    let origin = random_peer_id();
    for target in [
        RelayTarget::Broadcast,
        RelayTarget::Direct(random_peer_id()),
    ] {
        for payload in [Vec::new(), vec![0x5a; 3], vec![0xc3; 70_000]] {
            let encoded_origin = origin.encode();
            let encoded_target = target.encode();
            let encoded_payload = payload.encode();
            let le = |len: usize| (len as u64).to_le_bytes();
            let materialized = Hash::new_from_chunks(&[
                RELAY_ORIGIN_SIGNATURE_DOMAIN,
                &le(encoded_origin.len()),
                &encoded_origin,
                &le(encoded_target.len()),
                &encoded_target,
                &le(encoded_payload.len()),
                &encoded_payload,
            ]);
            assert_eq!(
                relay_origin_signature_digest(&origin, &target, &payload),
                materialized,
                "streaming must not change the signed relay preimage"
            );
        }
    }
}

#[test]
fn signing_requires_the_origin_key_and_produces_a_verifiable_frame() {
    let origin_key = random_node_key_pair();
    let origin = PeerId::from(origin_key.public_key().clone());
    let mut frame = RelayMessage::new_link(
        origin,
        RelayTarget::Direct(random_peer_id()),
        DEFAULT_RELAY_TTL,
        DummyMsg,
    );
    assert!(!frame.is_relay_signed());
    assert!(
        frame.verify_origin_signature().is_err(),
        "a link-local frame has no end-to-end proof to verify"
    );
    assert!(
        frame.try_sign_in_place(&random_node_key_pair()).is_err(),
        "only the origin can sign its frame"
    );
    assert!(!frame.is_relay_signed());
    frame.sign_in_place(&origin_key);
    assert!(frame.is_relay_signed());
    frame
        .verify_origin_signature()
        .expect("the origin signature verifies");
    let signature = frame.origin_signature.clone();
    frame.sign_in_place(&origin_key);
    assert_eq!(frame.origin_signature, signature, "signing is idempotent");
}

#[test]
fn link_local_frame_is_smaller_than_the_relayable_admission_charge() {
    let origin_key = random_node_key_pair();
    let origin = PeerId::from(origin_key.public_key().clone());
    let target = random_peer_id();
    let payload = vec![0x11_u8; 512];
    let link = RelayMessage::new_link(
        origin.clone(),
        RelayTarget::Direct(target.clone()),
        DEFAULT_RELAY_TTL,
        payload.clone(),
    );
    let link_len = crate::peer::materialized_data_message_wire_len(link.clone()).unwrap();
    let mut signed = link;
    signed.sign_in_place(&origin_key);
    let signed_len = crate::peer::materialized_data_message_wire_len(signed).unwrap();
    let charged = data_frame_wire_len(&origin, Some(&target), &payload);
    assert_eq!(
        signed_len, charged,
        "admission charges the relayable frame exactly"
    );
    assert!(
        link_len + RELAY_ORIGIN_SIGNATURE_BYTES <= charged,
        "a link-local frame omits the origin signature but stays within its charge"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn link_local_frame_from_authenticated_sender_is_delivered_without_signature() {
    let_test_network!(network, DummyMsg);
    let (tx, mut rx) = mpsc::channel(2);
    network.subscribe_to_peers_messages(Subscriber::new(tx, SubscriberFilter::All, 2));
    let peer = test_peer(socket_addr!(127.0.0.1:47_001));
    let _peer_receivers = connect_link_test_peer(&mut network, &peer, 47_001, RelayRole::Disabled);
    for target in [
        RelayTarget::Direct(network.self_id.clone()),
        RelayTarget::Broadcast,
    ] {
        let frame = RelayMessage::new_link(peer.id().clone(), target, DEFAULT_RELAY_TTL, DummyMsg);
        network
            .peer_message(PeerMessage::new_for_connection(
                peer.clone(),
                frame,
                1,
                47_001,
            ))
            .await;
        let delivered = rx
            .try_recv()
            .expect("the authenticated link proves a link-local frame's sender");
        assert_eq!(delivered.peer.id(), peer.id());
    }
    assert!(!network.protocol_rejected_connections.contains(&47_001));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsigned_frame_claiming_another_origin_is_rejected_even_from_the_hub() {
    let_test_network!(network, DummyMsg);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
    let hub = test_peer(socket_addr!(127.0.0.1:47_002));
    let _hub_receivers = connect_link_test_peer(&mut network, &hub, 47_002, RelayRole::Hub);
    network.relay_hub_peer = Some(hub.id().clone());
    let (tx, mut rx) = mpsc::channel(1);
    network.subscribe_to_peers_messages(Subscriber::new(tx, SubscriberFilter::All, 1));
    let forged = RelayMessage::new_link(
        random_peer_id(),
        RelayTarget::Direct(network.self_id.clone()),
        DEFAULT_RELAY_TTL,
        DummyMsg,
    );
    network
        .peer_message(PeerMessage::new_for_connection(hub, forged, 1, 47_002))
        .await;
    assert!(
        matches!(rx.try_recv(), Err(TryRecvError::Empty)),
        "a hub cannot speak for another origin without that origin's signature"
    );
    assert!(network.protocol_rejected_connections.contains(&47_002));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_or_tampered_relayed_frame_from_the_hub_is_rejected() {
    for tamper in [false, true] {
        let_test_network!(network, SafetyMsg);
        network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
        let hub_key = random_node_key_pair();
        let hub = Peer::new(socket_addr!(127.0.0.1:47_003), hub_key.public_key().clone());
        let _hub_receivers = connect_link_test_peer(&mut network, &hub, 47_003, RelayRole::Hub);
        network.relay_hub_peer = Some(hub.id().clone());
        let (tx, mut rx) = mpsc::channel(1);
        network.subscribe_to_peers_messages(Subscriber::new(tx, SubscriberFilter::All, 1));
        let origin_key = random_node_key_pair();
        let mut frame = if tamper {
            let mut frame = RelayMessage::new_signed(
                &origin_key,
                RelayTarget::Direct(network.self_id.clone()),
                DEFAULT_RELAY_TTL,
                SafetyMsg(1),
            );
            frame.payload = SafetyMsg(2);
            frame
        } else {
            // The hub signs with its own key but claims another origin.
            let mut frame = RelayMessage::new_signed(
                &hub_key,
                RelayTarget::Direct(network.self_id.clone()),
                DEFAULT_RELAY_TTL,
                SafetyMsg(1),
            );
            frame.origin = PeerId::from(origin_key.public_key().clone());
            frame
        };
        frame.ttl = DEFAULT_RELAY_TTL - 1;
        network
            .peer_message(PeerMessage::new_for_connection(hub, frame, 1, 47_003))
            .await;
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
        assert!(network.protocol_rejected_connections.contains(&47_003));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hub_never_forwards_link_local_frames() {
    let_test_network!(network, DummyMsg);
    network.relay_role = RelayRole::Hub;
    let incoming = test_peer(socket_addr!(127.0.0.1:47_004));
    let _incoming_receivers =
        connect_link_test_peer(&mut network, &incoming, 47_004, RelayRole::Disabled);
    let other_id = random_peer_id();
    let (other_handle, mut other_receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(
        &mut network,
        other_id.clone(),
        socket_addr!(127.0.0.1:47_005),
        47_005,
        other_handle,
    );
    let (tx, mut rx) = mpsc::channel(1);
    network.subscribe_to_peers_messages(Subscriber::new(tx, SubscriberFilter::All, 1));
    let broadcast = RelayMessage::new_link(
        incoming.id().clone(),
        RelayTarget::Broadcast,
        DEFAULT_RELAY_TTL,
        DummyMsg,
    );
    network
        .peer_message(PeerMessage::new_for_connection(
            incoming.clone(),
            broadcast,
            1,
            47_004,
        ))
        .await;
    rx.try_recv()
        .expect("the hub still consumes a link-local broadcast itself");
    assert!(
        matches!(other_receivers.try_recv_any(), Err(TryRecvError::Empty)),
        "a third party cannot authenticate a link-local frame, so it is never forwarded"
    );
    let misdirected = RelayMessage::new_link(
        incoming.id().clone(),
        RelayTarget::Direct(other_id),
        DEFAULT_RELAY_TTL,
        DummyMsg,
    );
    network
        .peer_message(PeerMessage::new_for_connection(
            incoming,
            misdirected,
            1,
            47_004,
        ))
        .await;
    assert!(matches!(
        other_receivers.try_recv_any(),
        Err(TryRecvError::Empty)
    ));
    assert!(
        network.protocol_rejected_connections.contains(&47_004),
        "an unsigned frame for another target is a protocol violation"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hub_forwards_signed_frames_with_their_verified_origin_signature() {
    let_test_network!(network, DummyMsg);
    network.relay_role = RelayRole::Hub;
    let incoming_key = random_node_key_pair();
    let incoming = Peer::new(
        socket_addr!(127.0.0.1:47_006),
        incoming_key.public_key().clone(),
    );
    let _incoming_receivers =
        connect_link_test_peer(&mut network, &incoming, 47_006, RelayRole::Spoke);
    let (other_handle, mut other_receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(
        &mut network,
        random_peer_id(),
        socket_addr!(127.0.0.1:47_007),
        47_007,
        other_handle,
    );
    let signed = RelayMessage::new_signed(&incoming_key, RelayTarget::Broadcast, 2, DummyMsg);
    let signature = signed.origin_signature.clone();
    network
        .peer_message(PeerMessage::new_for_connection(incoming, signed, 1, 47_006))
        .await;
    let forwarded = other_receivers
        .try_recv_any()
        .expect("a verified relayable broadcast is forwarded");
    assert_eq!(forwarded.origin_signature, signature);
    forwarded
        .verify_origin_signature()
        .expect("forwarding preserves the origin's proof");
}

#[test]
fn best_effort_post_to_its_own_target_stays_link_local() {
    let_test_network!(network, DummyMsg);
    let peer = random_peer_id();
    let (handle, mut receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(
        &mut network,
        peer.clone(),
        socket_addr!(127.0.0.1:47_008),
        47_008,
        handle,
    );
    network.current_topology.insert(peer.clone());
    assert!(network.try_post(Post {
        data: DummyMsg,
        peer_id: peer.clone(),
        priority: Priority::Low,
    }));
    let frame = receivers
        .try_recv_any()
        .expect("direct post reaches its peer");
    assert!(matches!(&frame.target, RelayTarget::Direct(target) if target == &peer));
    assert_eq!(frame.origin, network.self_id);
    assert!(
        !frame.is_relay_signed(),
        "the direct target needs no end-to-end signature"
    );
}

#[test]
fn broadcast_signs_once_only_when_a_relay_hub_receives_it() {
    for with_hub in [false, true] {
        let_test_network!(network, DummyMsg);
        let mut receivers = Vec::new();
        for (index, port) in [47_010_u16, 47_011].into_iter().enumerate() {
            let peer = random_peer_id();
            let (handle, peer_receivers) = test_wire_peer_handle::<DummyMsg>(4);
            insert_dummy_ref_peer(
                &mut network,
                peer.clone(),
                SocketAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], port))),
                u64::from(port),
                handle,
            );
            if with_hub && index == 0 {
                network
                    .peers
                    .get_mut(&peer)
                    .expect("inserted peer")
                    .relay_role = RelayRole::Hub;
            }
            receivers.push(peer_receivers);
        }
        assert!(network.try_broadcast(&Broadcast {
            data: DummyMsg,
            priority: Priority::Low,
        }));
        let frames: Vec<_> = receivers
            .iter_mut()
            .map(|receivers| {
                receivers
                    .try_recv_any()
                    .expect("broadcast reaches every peer")
            })
            .collect();
        for frame in &frames {
            assert_eq!(frame.is_relay_signed(), with_hub);
            if with_hub {
                frame
                    .verify_origin_signature()
                    .expect("a hub-forwardable broadcast carries a valid origin signature");
            }
        }
        assert_eq!(
            frames[0].origin_signature, frames[1].origin_signature,
            "one signature (or none) serves the whole fan-out"
        );
    }
}

#[test]
fn hub_routed_best_effort_post_is_signed_at_the_hub_hand_off() {
    let_test_network!(network, DummyMsg);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
    let hub = random_peer_id();
    let hub_addr = socket_addr!(127.0.0.1:47_012);
    let (handle, mut hub_receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(&mut network, hub.clone(), hub_addr.clone(), 47_012, handle);
    network
        .peers
        .get_mut(&hub)
        .expect("connected hub")
        .relay_role = RelayRole::Hub;
    network.relay_hub_addresses.push(hub_addr.clone());
    network
        .current_peers_addresses
        .push((hub.clone(), hub_addr));
    network.relay_trusted_peers.insert(hub.clone());
    network.current_topology.insert(hub.clone());
    network.relay_hub_peer = Some(hub.clone());
    let target = random_peer_id();
    assert!(network.try_post(Post {
        data: DummyMsg,
        peer_id: target.clone(),
        priority: Priority::Low,
    }));
    let frame = hub_receivers
        .try_recv_any()
        .expect("an unconnected target routes through the hub");
    assert!(matches!(&frame.target, RelayTarget::Direct(peer) if peer == &target));
    frame
        .verify_origin_signature()
        .expect("the hub relays the frame, so its hand-off signs it");
}

#[test]
fn refused_deferred_hub_hand_off_restores_the_charged_link_shape() {
    let_deferred_test_network!(network, DummyMsg);
    let hub = random_peer_id();
    let (handle, mut hub_receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(
        &mut network,
        hub.clone(),
        socket_addr!(127.0.0.1:47_013),
        47_013,
        handle,
    );
    network
        .peers
        .get_mut(&hub)
        .expect("connected hub")
        .relay_role = RelayRole::Hub;
    let link = RelayMessage::new_link(
        network.self_id.clone(),
        RelayTarget::Broadcast,
        DEFAULT_RELAY_TTL,
        DummyMsg,
    );
    // Occupy the hub's single class slot so the deferred hand-off is refused.
    network
        .peers
        .get(&hub)
        .expect("connected hub")
        .handle
        .post(link.clone())
        .expect("first post fills the bounded class channel");
    let now = tokio::time::Instant::now();
    let outcome =
        network
            .deferred_send_queue
            .enqueue(hub.clone(), link, message::Topic::Other, None, now);
    assert!(outcome.enqueued);
    assert!(matches!(
        network.flush_deferred_frames_for_peer_once(&hub),
        DeferredFlushOutcome::Backpressured(_)
    ));
    let (retained, _) = network.deferred_send_queue.take_peer(&hub, now);
    let entry = retained.front().expect("refused frame stays deferred");
    assert!(
        !entry.frame.is_relay_signed(),
        "the deferred owner charged the link-local shape, so a refused hand-off restores it"
    );
    assert_eq!(
        Some(entry.wire_bytes),
        crate::peer::checked_data_message_wire_len(&entry.frame)
            .ok()
            .map(|bytes| bytes + network.deferred_send_queue.frame_queue_overhead_bytes)
    );
    // Once capacity opens, the hub hand-off signs the frame.
    hub_receivers
        .try_recv_any()
        .expect("drain the occupying post");
    network
        .deferred_send_queue
        .restore_peer(hub.clone(), retained);
    assert!(matches!(
        network.flush_deferred_frames_for_peer_once(&hub),
        DeferredFlushOutcome::Flushed
    ));
    hub_receivers
        .try_recv_any()
        .expect("deferred broadcast reaches the hub")
        .verify_origin_signature()
        .expect("a hub may forward the broadcast, so the hand-off signs it");
}
