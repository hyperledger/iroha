// Reliable actor window, class split, flush-notice and lazy-digest regressions,
// included into `network::tests`.

fn lane_post(peer: &PeerId, tag: u8) -> NetworkMessage<DeferredProgressMsg> {
    NetworkMessage::Post(Post {
        data: DeferredProgressMsg::Lane(tag),
        peer_id: peer.clone(),
        priority: Priority::High,
    })
}

fn lane_source(peer: &PeerId) -> ActorProgressSource {
    ActorProgressSource {
        target: Some(peer.clone()),
        class: ActorProgressClass::Lane,
    }
}

fn shipping_shaped_budget(per_source_bytes: usize) -> Arc<NetworkActorProgressBudget> {
    NetworkActorProgressBudget::new_classed(
        ActorProgressByteLimits::uniform(per_source_bytes),
        1,
        ActorProgressClass::COUNT * RELIABLE_PROGRESS_WAITERS_PER_SOURCE,
    )
    .expect("one target with shipping class geometry")
}

fn lane_shape(tag: u8) -> ProgressTicketShape {
    ProgressTicketShape {
        topic: message::Topic::Consensus,
        stream_wire_bytes: 1,
        broadcast: false,
        reply_writer_timeout_attempt: None,
        request_digest: Hash::new([tag]),
        authority: None,
    }
}

#[test]
fn shipping_progress_geometry_pipelines_a_bounded_window_per_source() {
    let budget = shipping_shaped_budget(1024);
    assert_eq!(budget.max_items_per_source, RELIABLE_ACTOR_SOURCE_WINDOW);
    let target = random_peer_id();
    let source = lane_source(&target);
    let mut leases = Vec::new();
    for tag in 0..RELIABLE_ACTOR_SOURCE_WINDOW {
        let ProgressLeaseAttempt::Ready {
            lease,
            ticket: mut admitted,
        } = budget.try_reserve_for_source(
            1,
            lane_shape(u8::try_from(tag).unwrap()),
            source.clone(),
            None,
            None,
        )
        else {
            panic!("every item inside the window must be admitted at once");
        };
        admitted.commit();
        leases.push(lease);
    }
    let ProgressLeaseAttempt::Waiting {
        ticket: Some(waiter),
        rank: 1,
    } = budget.try_reserve_for_source(1, lane_shape(200), source.clone(), None, None)
    else {
        panic!("the per-source window is bounded");
    };
    // Every other class of the same target keeps independent ownership.
    for class in [
        ActorProgressClass::Safety,
        ActorProgressClass::Payload,
        ActorProgressClass::BlockSync,
    ] {
        let ProgressLeaseAttempt::Ready {
            lease,
            ticket: mut admitted,
        } = budget.try_reserve_for_source(
            1,
            lane_shape(201),
            ActorProgressSource {
                target: Some(target.clone()),
                class,
            },
            None,
            None,
        )
        else {
            panic!("a saturated lane window must not block {class:?} to the same peer");
        };
        admitted.commit();
        leases.push(lease);
    }
    drop(leases.remove(0));
    let ProgressLeaseAttempt::Ready {
        lease,
        ticket: mut admitted,
    } = budget.try_reserve_for_source(1, lane_shape(200), source, None, Some(waiter))
    else {
        panic!("a released window slot admits the head waiter");
    };
    admitted.commit();
    leases.push(lease);
    drop(leases);
    let state = budget
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(state.retained_items, 0);
    assert_eq!(state.retained_bytes, 0);
    assert!(state.retained_by_source.is_empty());
    assert_eq!(
        state.retained_sources_by_class,
        [0; ActorProgressClass::COUNT]
    );
}

#[test]
fn source_window_never_exceeds_the_single_frame_byte_cap() {
    let budget = shipping_shaped_budget(10);
    let source = lane_source(&random_peer_id());
    let ProgressLeaseAttempt::Ready {
        lease: first,
        ticket: mut admitted,
    } = budget.try_reserve_for_source(6, lane_shape(1), source.clone(), None, None)
    else {
        panic!("first item fits the source cap");
    };
    admitted.commit();
    let ProgressLeaseAttempt::Waiting {
        ticket: Some(waiter),
        rank: 1,
    } = budget.try_reserve_for_source(5, lane_shape(2), source.clone(), None, None)
    else {
        panic!("the window may not exceed the source's single-frame byte cap");
    };
    assert!(
        matches!(
            budget.try_reserve_for_source(4, lane_shape(3), source.clone(), None, None),
            ProgressLeaseAttempt::Waiting { rank: 2, .. }
        ),
        "a smaller fresh request cannot overtake the head waiter"
    );
    drop(first);
    let ProgressLeaseAttempt::Ready {
        lease,
        ticket: mut admitted,
    } = budget.try_reserve_for_source(5, lane_shape(2), source, None, Some(waiter))
    else {
        panic!("released bytes admit the head waiter");
    };
    admitted.commit();
    drop(lease);
    assert_eq!(budget.retained(), 0);
}

#[test]
fn removed_membership_cancels_its_items_without_touching_other_window_slots() {
    let budget = shipping_shaped_budget(1024);
    let target = random_peer_id();
    let source = lane_source(&target);
    let membership = Arc::new(ReliableProgressMembership {
        peer_id: target,
        generation: 3,
        active: AtomicBool::new(true),
    });
    let authority = ProgressDeliveryAuthority::Topology(Arc::clone(&membership));
    let mut shapes = Vec::new();
    let mut leases = Vec::new();
    for tag in 0..2_u8 {
        let shape = ProgressTicketShape {
            authority: Some(authority.identity()),
            ..lane_shape(tag)
        };
        let ProgressLeaseAttempt::Ready {
            lease,
            ticket: mut admitted,
        } = budget.try_reserve_for_source(1, shape, source.clone(), Some(&authority), None)
        else {
            panic!("two membership items share one window");
        };
        admitted.commit();
        shapes.push(shape);
        leases.push(lease);
    }
    // Releasing the older lease leaves the newer item exactly retained.
    drop(leases.remove(0));
    {
        let state = budget
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let retained = &state.retained_by_source[&source];
        assert_eq!(retained.items.len(), 1);
        assert_eq!(retained.bytes, 1);
    }
    membership.cancel();
    assert!(matches!(
        budget.try_reserve_for_source(1, shapes[0], source, Some(&authority), None),
        ProgressLeaseAttempt::CancelledMembership
    ));
    drop(leases);
    assert_eq!(budget.retained(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn first_attempt_direct_post_needs_no_waiter_ticket_or_request_digest() {
    let (handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let peer = random_peer_id();
    reconcile_test_topology!(
        handle.reliable_direct_topology,
        &HashSet::from([peer.clone()])
    );
    let post = |tag| Post {
        data: DeferredProgressMsg::Lane(tag),
        peer_id: peer.clone(),
        priority: Priority::High,
    };
    handle
        .post_recoverable(post(1), None)
        .expect("an idle source admits a direct post at once");
    {
        let state = handle
            .network_actor_progress_budget
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.waiter_count, 0, "no waiter ticket was registered");
        let retained = &state.retained_by_source[&lane_source(&peer)];
        assert_eq!(retained.items.len(), 1);
        assert!(
            retained.items[0].request_digest.is_none(),
            "a direct post admitted on its first attempt is never hashed"
        );
    }
    // The fixture budget holds one item per source, so the next post must
    // wait and therefore binds a ticket to its exact canonical request.
    let Err(NetworkActorAdmissionError::Backpressured {
        message,
        ticket: Some(ticket),
        rank: 1,
    }) = handle.post_recoverable(post(2), None)
    else {
        panic!("an occupied source returns a ranked ticket");
    };
    let canonical = NetworkMessage::Post(Post {
        priority: Priority::High,
        ..message.clone()
    });
    assert_eq!(
        ticket.shape.request_digest,
        progress_ticket_request_digest(&canonical)
    );
    drop(
        progress_rx
            .try_recv()
            .expect("the first post entered the actor queue"),
    );
    handle
        .post_recoverable(message, Some(ticket))
        .expect("the released slot admits the ticketed retry");
}

#[test]
fn streamed_request_digest_matches_the_materialized_preimage() {
    const DOMAIN: &[u8] = b"iroha:p2p-progress-admission-ticket:v1\n";
    let peer = random_peer_id();
    let post = lane_post(&peer, 7);
    let NetworkMessage::Post(inner) = &post else {
        unreachable!("lane_post builds a post")
    };
    assert_eq!(
        progress_ticket_request_digest(&post),
        Hash::new_from_chunks(&[DOMAIN, &[0, 0], &peer.encode(), &inner.data.encode()])
    );
    let broadcast = NetworkMessage::Broadcast(Broadcast {
        data: DeferredProgressMsg::Lane(7),
        priority: Priority::Low,
    });
    assert_eq!(
        progress_ticket_request_digest(&broadcast),
        Hash::new_from_chunks(&[DOMAIN, &[1, 1], &DeferredProgressMsg::Lane(7).encode()])
    );
}

#[test]
fn writer_flush_notice_retires_the_lease_without_the_retry_tick() {
    let_deferred_test_network!(network, DeferredProgressMsg);
    let peer = random_peer_id();
    let_deferred_peer!(mut receivers = &mut network; peer.clone(), socket_addr!(127.0.0.1:47_101), 47_101; capacity 4);
    let (admitted, actor_budget, _retained_bytes) =
        admitted_with_exact_actor_bytes(&network, lane_post(&peer, 1));
    let mut safety_pending = ReliableActorPending::new(4);
    let mut pending = ReliableActorPending::new(4);
    network.accept_reliable_actor_message(&mut pending, admitted);
    assert_eq!(pending.len(), 1, "writer admission is not yet a flush");
    assert!(
        network.reliable_flush_notice_receiver.try_recv().is_err(),
        "nothing settled yet"
    );
    assert_lane_flushed!(consensus receivers, 1, "the post entered its writer");
    let source = network
        .reliable_flush_notice_receiver
        .try_recv()
        .expect("the writer's flush wakes the actor");
    assert_eq!(source, lane_source(&peer));
    network.service_reliable_flush_notice(&mut safety_pending, &mut pending, &source);
    assert_eq!(pending.len(), 0);
    assert_eq!(
        actor_budget.retained().total,
        0,
        "the flush retires the actor lease at once"
    );
}

#[test]
fn abandoned_writer_occurrence_wakes_the_actor_for_its_retry() {
    let_deferred_test_network!(network, DeferredProgressMsg);
    let peer = random_peer_id();
    let_deferred_peer!(mut receivers = &mut network; peer.clone(), socket_addr!(127.0.0.1:47_102), 47_102; capacity 4);
    let (admitted, actor_budget, _retained_bytes) =
        admitted_with_exact_actor_bytes(&network, lane_post(&peer, 2));
    let mut pending = ReliableActorPending::new(4);
    network.accept_reliable_actor_message(&mut pending, admitted);
    // The writer drops the post without acknowledging it.
    drop(
        receivers
            .try_recv_any()
            .expect("the post entered its writer"),
    );
    assert_eq!(
        network.reliable_flush_notice_receiver.try_recv().ok(),
        Some(lane_source(&peer)),
        "an abandoned occurrence also wakes the actor"
    );
    assert_eq!(network.retry_reliable_actor_messages(&mut pending, 1), 0);
    assert_lane_flushed!(consensus receivers, 2, "the retry re-enters the writer");
    assert_eq!(network.retry_reliable_actor_messages(&mut pending, 1), 1);
    assert_eq!(actor_budget.retained().total, 0);
}

#[test]
fn refused_writer_post_never_wakes_the_actor() {
    let_deferred_test_network!(network, DeferredProgressMsg);
    network.disconnect_on_post_overflow = false;
    let peer = random_peer_id();
    let_deferred_peer!(mut receivers = &mut network; peer.clone(), socket_addr!(127.0.0.1:47_103), 47_103; capacity 1);
    let mut pending = ReliableActorPending::new(4);
    let mut budgets = Vec::new();
    for tag in [3, 4] {
        let (admitted, budget, _bytes) =
            admitted_with_exact_actor_bytes(&network, lane_post(&peer, tag));
        budgets.push(budget);
        network.accept_reliable_actor_message(&mut pending, admitted);
    }
    assert_eq!(pending.len(), 2);
    assert!(
        network.reliable_flush_notice_receiver.try_recv().is_err(),
        "a full writer class refuses the second post without a wake-up"
    );
    assert_lane_flushed!(consensus receivers, 3, "the first post entered its writer");
    let source = network
        .reliable_flush_notice_receiver
        .try_recv()
        .expect("the first flush wakes the actor");
    let mut safety_pending = ReliableActorPending::new(4);
    network.service_reliable_flush_notice(&mut safety_pending, &mut pending, &source);
    assert_eq!(
        pending.len(),
        1,
        "the refused post entered the freed writer slot"
    );
    assert_lane_flushed!(consensus receivers, 4, "the refused post follows in order");
}

#[test]
fn same_source_items_pipeline_into_the_writer_in_admission_order() {
    let_deferred_test_network!(network, DeferredProgressMsg);
    network.disconnect_on_post_overflow = false;
    let peer = random_peer_id();
    let_deferred_peer!(mut receivers = &mut network; peer.clone(), socket_addr!(127.0.0.1:47_104), 47_104; capacity 2);
    let mut pending = ReliableActorPending::new(8);
    let mut budgets = Vec::new();
    for tag in 10..14 {
        let (admitted, budget, _bytes) =
            admitted_with_exact_actor_bytes(&network, lane_post(&peer, tag));
        budgets.push(budget);
        network.accept_reliable_actor_message(&mut pending, admitted);
    }
    // Two items fit the writer class without any flush; the third was
    // refused and therefore holds the fourth back to preserve order.
    assert_eq!(pending.len(), 4);
    let first = receivers.try_recv_any().expect("first item in writer");
    let second = receivers.try_recv_any().expect("second item pipelined");
    assert_eq!(first.payload, DeferredProgressMsg::Lane(10));
    assert_eq!(second.payload, DeferredProgressMsg::Lane(11));
    assert!(matches!(receivers.try_recv_any(), Err(TryRecvError::Empty)));
    // Both abandoned occurrences retry ahead of the held items, in order.
    let mut safety_pending = ReliableActorPending::new(4);
    while let Ok(source) = network.reliable_flush_notice_receiver.try_recv() {
        network.service_reliable_flush_notice(&mut safety_pending, &mut pending, &source);
    }
    let mut order = Vec::new();
    while let Ok(frame) = receivers.try_recv_any() {
        order.push(frame.payload);
    }
    assert_eq!(
        order,
        [DeferredProgressMsg::Lane(10), DeferredProgressMsg::Lane(11)],
        "retries keep admission order and later items stay behind them"
    );
}

#[test]
fn block_sync_backlog_never_holds_payload_to_the_same_peer() {
    let_deferred_test_network!(network, DeferredProgressMsg);
    network.disconnect_on_post_overflow = false;
    let peer = random_peer_id();
    let_deferred_peer!(mut receivers = &mut network; peer.clone(), socket_addr!(127.0.0.1:47_105), 47_105; capacity 1);
    let mut pending = ReliableActorPending::new(8);
    let mut budgets = Vec::new();
    for data in [
        DeferredProgressMsg::BlockSync(1),
        DeferredProgressMsg::BlockSync(2),
        DeferredProgressMsg::Chunk(3),
    ] {
        let (admitted, budget, _bytes) = admitted_with_exact_actor_bytes(
            &network,
            NetworkMessage::Post(Post {
                data,
                peer_id: peer.clone(),
                priority: Priority::High,
            }),
        );
        budgets.push(budget);
        network.accept_reliable_actor_message(&mut pending, admitted);
    }
    assert_eq!(
        receivers
            .try_recv_block_sync()
            .expect("first block-sync row entered its writer")
            .payload,
        DeferredProgressMsg::BlockSync(1)
    );
    assert_eq!(
        receivers
            .try_recv_any()
            .expect("the payload chunk owns an independent actor source")
            .payload,
        DeferredProgressMsg::Chunk(3),
        "a refused block-sync row must not hold a payload chunk behind it"
    );
}

#[test]
fn every_reliable_topology_input_change_marks_memberships_for_republication() {
    let_test_network!(network, DeferredProgressMsg);
    let (removed, _cancelled) = network.reconcile_reliable_progress_topologies();
    assert_eq!(removed, 0);
    network.reliable_topology_dirty = false;
    let peer = random_peer_id();
    network.set_current_topology(UpdateTopology(HashSet::from([peer.clone()])));
    assert!(
        network.reliable_topology_dirty,
        "a staged or applied topology must republish memberships"
    );
    network.reliable_topology_dirty = false;
    network.set_reply_source_trusted(UpdateTrustedPeers(HashSet::from([peer.clone()])));
    assert!(
        network.reliable_topology_dirty,
        "trusted-source changes stage authority"
    );
    network.reliable_topology_dirty = false;
    let (handle, _receivers) = test_wire_peer_handle::<DeferredProgressMsg>(1);
    insert_ref_peer(
        &mut network,
        peer.clone(),
        socket_addr!(127.0.0.1:47_120),
        47_120,
        handle,
        true,
    );
    network.disconnect_peer(&peer);
    assert!(
        network.reliable_topology_dirty,
        "removing an authenticated peer changes direct authority"
    );
}
