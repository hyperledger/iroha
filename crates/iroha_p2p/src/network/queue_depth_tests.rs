#[test]
fn subscriber_unrouted_counts_increment_by_topic() {
    let before = subscriber_unrouted_count();
    let before_safety = subscriber_unrouted_consensus_safety_count();
    let before_peer = subscriber_unrouted_peer_gossip_count();
    let before_chunks = subscriber_unrouted_consensus_chunk_count();
    inc_subscriber_unrouted_for_test(message::Topic::ConsensusSafety, 1);
    inc_subscriber_unrouted_for_test(message::Topic::TrustGossip, 3);
    inc_subscriber_unrouted_for_test(message::Topic::ConsensusChunk, 1);
    let after = subscriber_unrouted_count();
    let after_safety = subscriber_unrouted_consensus_safety_count();
    let after_peer = subscriber_unrouted_peer_gossip_count();
    let after_chunks = subscriber_unrouted_consensus_chunk_count();
    assert!(
        after >= before + 5,
        "increment helper should increase subscriber unrouted count"
    );
    assert!(
        after_safety > before_safety,
        "unrouted safety traffic must have a distinct counter"
    );
    assert!(
        after_peer >= before_peer + 3,
        "trust-gossip should be grouped under peer gossip counters"
    );
    assert!(
        after_chunks > before_chunks,
        "consensus chunk drops should be tracked separately"
    );
}
#[test]
fn network_queue_depth_tracks_updates() {
    let _guard = queue_depth_test_guard();
    set_network_safety_queue_depth_for_test(0);
    set_network_queue_depth_for_test(true, 0);
    set_network_queue_depth_for_test(false, 0);
    set_network_safety_queue_depth_for_test(3);
    set_network_queue_depth_for_test(true, 12);
    set_network_queue_depth_for_test(false, 7);
    assert_eq!(network_queue_depth_safety(), 3);
    assert_eq!(network_queue_depth_high(), 12);
    assert_eq!(network_queue_depth_low(), 7);
}
