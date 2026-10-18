//! Network actor admission, retry, transport, and custody regressions.

use super::handle_update_tests::handle_with_network_receivers;
use super::*;
use iroha_crypto::{KeyPair, encryption::ChaCha20Poly1305};
use iroha_primitives::addr::socket_addr;
use norito::codec::DecodeAll;
use std::collections::{BTreeSet, HashSet};
use std::sync::{Mutex, OnceLock};
use tokio::sync::mpsc::error::TryRecvError;

#[test]
fn captured_original_test_payload_identities() {
    crate::frame_identity_tests::test_payload_identity::<DummyMsg>(
        "iroha_p2p::network::tests::DummyMsg",
    );
    crate::frame_identity_tests::test_payload_identity::<TamperableMsg>(
        "iroha_p2p::network::tests::TamperableMsg",
    );
    crate::frame_identity_tests::test_payload_identity::<SafetyMsg>(
        "iroha_p2p::network::tests::SafetyMsg",
    );
    crate::frame_identity_tests::test_payload_identity::<TrustGossipMsg>(
        "iroha_p2p::network::tests::TrustGossipMsg",
    );
    crate::frame_identity_tests::test_payload_identity::<PeerGossipMsg>(
        "iroha_p2p::network::tests::PeerGossipMsg",
    );
    crate::frame_identity_tests::test_payload_identity::<TopicMsg>(
        "iroha_p2p::network::tests::TopicMsg",
    );
    crate::frame_identity_tests::test_payload_identity::<RouteMsg>(
        "iroha_p2p::network::tests::RouteMsg",
    );
    crate::frame_identity_tests::test_payload_identity::<DeferredProgressMsg>(
        "iroha_p2p::network::tests::DeferredProgressMsg",
    );
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_p2p::network::tests::DummyMsg")]
#[derive(Clone, Debug, Decode, Encode)]
struct DummyMsg;
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_p2p::network::tests::TamperableMsg")]
#[derive(Clone, Debug, Decode, Encode)]
struct TamperableMsg {
    tag: u8,
}
impl message::ClassifyTopic for DummyMsg {
    fn progress_reconstruction(&self) -> message::ProgressReconstruction {
        message::ProgressReconstruction::Retransmit
    }
}
impl message::ClassifyTopic for Vec<u8> {}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_p2p::network::tests::SafetyMsg")]
#[derive(Clone, Copy, Debug, Decode, Encode, PartialEq, Eq)]
struct SafetyMsg(u8);
impl message::ClassifyTopic for SafetyMsg {
    fn topic(&self) -> message::Topic {
        message::Topic::ConsensusSafety
    }
    fn progress_reconstruction(&self) -> message::ProgressReconstruction {
        message::ProgressReconstruction::Retransmit
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_p2p::network::tests::TrustGossipMsg")]
#[derive(Clone, Copy, Debug, Decode, Encode)]
struct TrustGossipMsg;
impl message::ClassifyTopic for TrustGossipMsg {
    fn topic(&self) -> message::Topic {
        message::Topic::TrustGossip
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_p2p::network::tests::PeerGossipMsg")]
#[derive(Clone, Copy, Debug, Decode, Encode)]
struct PeerGossipMsg;
impl message::ClassifyTopic for PeerGossipMsg {
    fn topic(&self) -> message::Topic {
        message::Topic::PeerGossip
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_p2p::network::tests::TopicMsg")]
#[derive(Clone, Copy, Debug, Decode, Encode)]
enum TopicMsg {
    Trust,
    Peer,
}
impl message::ClassifyTopic for TopicMsg {
    fn topic(&self) -> message::Topic {
        match self {
            Self::Trust => message::Topic::TrustGossip,
            Self::Peer => message::Topic::PeerGossip,
        }
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_p2p::network::tests::RouteMsg")]
#[derive(Clone, Copy, Debug, Decode, Encode, PartialEq, Eq)]
enum RouteMsg {
    Control,
    Lane,
}
impl message::ClassifyTopic for RouteMsg {
    fn topic(&self) -> message::Topic {
        match self {
            Self::Control => message::Topic::Control,
            Self::Lane => message::Topic::Consensus,
        }
    }
    fn progress_reconstruction(&self) -> message::ProgressReconstruction {
        match self {
            Self::Lane => message::ProgressReconstruction::Retransmit,
            Self::Control => message::ProgressReconstruction::Exact,
        }
    }
}
#[test]
fn semantic_topics_define_local_scheduler_priority() {
    use message::{Priority, Topic};

    for topic in [
        Topic::ConsensusSafety,
        Topic::Consensus,
        Topic::ConsensusChunk,
        Topic::ConsensusPayload,
        Topic::Control,
    ] {
        assert_eq!(topic.scheduling_priority(), Priority::High);
    }
    for topic in [
        Topic::BlockSync,
        Topic::TxGossip,
        Topic::TxGossipRestricted,
        Topic::PeerGossip,
        Topic::TrustGossip,
        Topic::Health,
        Topic::Connect,
        Topic::Other,
    ] {
        assert_eq!(topic.scheduling_priority(), Priority::Low);
    }
}
#[test]
fn connect_has_a_separate_reliable_low_priority_frame_bound() {
    use message::{Priority, Topic};
    let mut caps = TopicFrameCaps::uniform(32_768);
    caps.connect = 8 * 1024 * 1024;
    assert_eq!(caps.for_topic(Topic::Connect), 8 * 1024 * 1024);
    assert_eq!(caps.for_topic(Topic::Health), 32_768);
    assert_eq!(caps.for_topic(Topic::Other), 32_768);
    assert_eq!(Topic::Connect.scheduling_priority(), Priority::Low);
    assert!(
        !Topic::Connect.is_best_effort(),
        "wallet relay messages require a reliable stream"
    );
}
#[test]
fn reliable_progress_class_matches_actor_reservations_exactly() {
    use message::{SubscriberRoute as Route, Topic};
    for (topic, route, expected) in [
        (
            Topic::ConsensusSafety,
            Route::General,
            Some(ReliableProgressClass::Safety),
        ),
        (
            Topic::Consensus,
            Route::General,
            Some(ReliableProgressClass::Lane),
        ),
        (
            Topic::ConsensusPayload,
            Route::General,
            Some(ReliableProgressClass::Bulk),
        ),
        (
            Topic::ConsensusChunk,
            Route::General,
            Some(ReliableProgressClass::Bulk),
        ),
        (
            Topic::BlockSync,
            Route::General,
            Some(ReliableProgressClass::Bulk),
        ),
        (Topic::Control, Route::General, None),
        (Topic::Health, Route::General, None),
        (Topic::Connect, Route::Connect, None),
        (Topic::Other, Route::General, None),
    ] {
        assert_eq!(reliable_progress_class(topic, route), expected);
        assert_eq!(is_reliable_progress_route(topic, route), expected.is_some());
        // The actor splits bulk progress by its peer-writer class, so block
        // sync responses never hold proposals or chunks behind them.
        assert_eq!(
            ActorProgressClass::for_route(topic, route),
            expected.map(|class| match (class, topic) {
                (ReliableProgressClass::Safety, _) => ActorProgressClass::Safety,
                (ReliableProgressClass::Lane, _) => ActorProgressClass::Lane,
                (ReliableProgressClass::Bulk, Topic::BlockSync) => ActorProgressClass::BlockSync,
                (ReliableProgressClass::Bulk, _) => ActorProgressClass::Payload,
            })
        );
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_p2p::network::tests::DeferredProgressMsg")]
#[derive(Clone, Copy, Debug, Decode, Encode, PartialEq, Eq)]
enum DeferredProgressMsg {
    Safety(u8),
    BlockSync(u8),
    Lane(u8),
    Chunk(u8),
}
impl message::ClassifyTopic for DeferredProgressMsg {
    fn topic(&self) -> message::Topic {
        match self {
            Self::Safety(_) => message::Topic::ConsensusSafety,
            Self::BlockSync(_) => message::Topic::BlockSync,
            Self::Lane(_) => message::Topic::Consensus,
            Self::Chunk(_) => message::Topic::ConsensusChunk,
        }
    }
    fn progress_reconstruction(&self) -> message::ProgressReconstruction {
        message::ProgressReconstruction::Retransmit
    }
}
macro_rules! impl_decode_from_slice_via_codec {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
                fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                    let mut slice = bytes;
                    let value = <Self as DecodeAll>::decode_all(&mut slice).map_err(|error| {
                        norito::core::Error::Message(format!("codec decode error: {error}"))
                    })?;
                    Ok((value, bytes.len() - slice.len()))
                }
            }
        )+
    };
}
impl_decode_from_slice_via_codec!(
    DummyMsg,
    SafetyMsg,
    TrustGossipMsg,
    PeerGossipMsg,
    TopicMsg,
    RouteMsg,
    DeferredProgressMsg
);
macro_rules! let_test_network {
    ($network:ident) => {
        let Some(mut $network) = bare_network() else {
            return;
        };
    };
    ($network:ident, $payload:ty) => {
        let Some(mut $network) = bare_network_with::<$payload>() else {
            return;
        };
    };
}
macro_rules! let_deferred_test_network {
    ($network:ident) => {
        let _guard = deferred_send_test_guard();
        let_test_network!($network);
    };
    ($network:ident, $payload:ty) => {
        let _guard = deferred_send_test_guard();
        let_test_network!($network, $payload);
    };
}
macro_rules! defer_frame {
    (
        $queue:expr,
        $peer:expr,
        $frame:expr,
        $topic:ident,
        $binding:expr,
        $now:expr,
        $delay_ms:expr
    ) => {
        defer_frame!(
            $queue,
            $peer,
            $frame,
            $topic,
            $binding,
            $now + Duration::from_millis($delay_ms)
        )
    };
    ($queue:expr, $peer:expr, $frame:expr, $topic:ident, $binding:expr, $when:expr) => {
        $queue.enqueue(
            ($peer).clone(),
            $frame,
            message::Topic::$topic,
            $binding,
            $when,
        )
    };
}
/// Logical actor fixture: no socket/reader exists. Hold the synthetic permit
/// through the real authenticated/Connected handoff, then release it. Native
/// arbitration tests below exercise actual delayed physical reader ownership.
fn connect_authenticated_fixture(
    network: &mut NetworkBase<DummyMsg, ChaCha20Poly1305>,
    connected: Connected<WireMessage<DummyMsg>>,
) {
    let mut session = [0; iroha_crypto::Hash::LENGTH];
    session[..8].copy_from_slice(&connected.disambiguator.to_be_bytes());
    let (reply, mut receiver) = oneshot::channel();
    network.peer_authenticated(Authenticated {
        peer: connected.peer.clone(),
        connection_id: connected.connection_id,
        session,
        relay_role: connected.relay_role,
        cancel: connected.ready_peer_handle.termination_sender_for_test(),
        reply,
    });
    if let Ok(permit) = receiver.try_recv() {
        network.peer_connected(connected);
        drop(permit);
    } else {
        connected.ready_peer_handle.request_termination();
        drop(connected.peer_message_sender);
    }
}
include!("connection_lifecycle_tests.rs");
macro_rules! connect_test_peer {
    (
        $network:ident,
        $peer:expr,
        $connection_id:expr,
        $disambiguator:expr,
        $relay_role:ident => $receivers:pat_param,
        $receiver:pat_param
    ) => {
        let (peer_handle, $receivers) = test_wire_peer_handle::<DummyMsg>(1);
        let (peer_message_sender, $receiver) = tokio::sync::oneshot::channel();
        connect_authenticated_fixture(
            &mut $network,
            Connected {
                peer: ($peer).clone(),
                connection_id: $connection_id,
                ready_peer_handle: peer_handle,
                peer_message_sender,
                delivery_drain: InboundDeliveryDrain::completed_for_test(),
                disambiguator: $disambiguator,
                relay_role: RelayRole::$relay_role,
                scion_supported: false,
                trust_gossip: true,
            },
        );
    };
}
macro_rules! admit_lane_reply {
    (
        $handle:ident,
        $progress_rx:ident => $completion:ident,
        $admitted:ident;
        $tag:expr,
        $target:expr,
        $route:ident
    ) => {
        let mut $completion = $handle
            .post_reply_recoverable_with_flush_ack(
                Post {
                    data: DeferredProgressMsg::Lane($tag),
                    peer_id: $target,
                    priority: Priority::High,
                },
                &$route,
                None,
            )
            .expect("reply enters actor ownership")
            .expect("new reply admission returns one completion");
        let $admitted = $progress_rx.try_recv().expect("admitted reply actor item");
    };
}
macro_rules! direct_frame {
    ($origin:expr, $target:expr, $payload:expr $(,)?) => {
        RelayMessage::new(
            $origin,
            RelayTarget::Direct(($target).clone()),
            DEFAULT_RELAY_TTL,
            $payload,
        )
    };
}
macro_rules! let_deferred_queue_clock {
    ($peer:ident, $now:ident) => {
        let _guard = deferred_send_test_guard();
        let $peer = random_peer_id();
        let $now = tokio::time::Instant::now();
    };
}
macro_rules! let_reply_handle {
    ($network:ident, $handle:ident, $progress_rx:ident) => {
        let (mut $handle, _safety_rx, mut $progress_rx, _high_rx, _low_rx) =
            handle_with_network_receivers::<DeferredProgressMsg>();
        $handle.reply_route_owner = Arc::clone(&$network.reply_route_owner);
    };
}
macro_rules! let_deferred_peer {
    ($receivers:pat_param = $network:expr; $peer:expr, $address:expr, $connection:expr) => {
        let (peer_handle, $receivers) = test_wire_peer_handle::<DeferredProgressMsg>(1);
        insert_ref_peer($network, $peer, $address, $connection, peer_handle, true);
    };
    (
        $receivers:pat_param = $network:expr;
        $peer:expr,
        $address:expr,
        $connection:expr;
        capacity $capacity:expr
    ) => {
        let (peer_handle, $receivers) = test_wire_peer_handle::<DeferredProgressMsg>($capacity);
        insert_ref_peer($network, $peer, $address, $connection, peer_handle, true);
    };
}
macro_rules! reconcile_test_topology {
    ($handle:ident.$field:ident, $topology:expr) => {
        let _ = $handle
            .$field
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reconcile($topology, &$handle.self_id);
    };
}
macro_rules! assert_lane_flushed {
    ($receivers:ident, $tag:expr, $message:literal) => {
        assert_eq!(
            $receivers
                .try_recv_any_and_acknowledge_flush()
                .expect($message)
                .payload,
            DeferredProgressMsg::Lane($tag)
        );
    };
    (consensus $receivers:ident, $tag:expr, $message:literal) => {
        assert_eq!(
            $receivers
                .try_recv_consensus_and_acknowledge_flush()
                .expect($message)
                .payload,
            DeferredProgressMsg::Lane($tag)
        );
    };
}
macro_rules! assert_deferred_flushed {
    ($network:ident, $peer:ident) => {
        assert!(matches!(
            $network.flush_deferred_frames_for_peer(&$peer),
            DeferredFlushOutcome::Flushed
        ));
    };
}
macro_rules! reserve_direct_lane_lease {
    ($handle:ident, $target:expr, $tag:expr => $lease:ident; $failure:literal) => {
        let direct = NetworkMessage::Post(Post {
            data: DeferredProgressMsg::Lane($tag),
            peer_id: $target,
            priority: Priority::High,
        });
        let direct_bytes = $handle
            .outbound_actor_wire_bytes_recoverable(&direct, message::Topic::Consensus)
            .expect("count direct fixture");
        let direct_source =
            ActorProgressSource::for_message(&direct).expect("direct target source");
        let ProgressLeaseAttempt::Ready {
            lease: $lease,
            ticket: mut direct_admission,
        } = $handle
            .network_actor_progress_budget
            .try_reserve_for_source(
                direct_bytes,
                ProgressTicketShape {
                    topic: message::Topic::Consensus,
                    stream_wire_bytes: direct_bytes,
                    broadcast: false,
                    reply_writer_timeout_attempt: None,
                    request_digest: progress_ticket_request_digest(&direct),
                    authority: None,
                },
                direct_source,
                None,
                None,
            )
        else {
            panic!($failure);
        };
        direct_admission.commit();
    };
}
type TestPeerReceivers<T> = crate::peer::handles::TestPeerHandleReceivers<WireMessage<T>>;
fn random_node_key_pair() -> KeyPair {
    KeyPair::random_with_algorithm(Algorithm::BlsNormal)
}
fn random_peer_id() -> PeerId {
    PeerId::from(random_node_key_pair().public_key().clone())
}
fn test_peer(address: SocketAddr) -> Peer {
    Peer::new(address, random_node_key_pair().public_key().clone())
}
fn test_wire_peer_handle<T: Pload>(
    capacity: usize,
) -> (PeerHandle<WireMessage<T>>, TestPeerReceivers<T>) {
    crate::peer::handles::test_peer_handle(capacity)
}
fn admitted_test_network_message<T>(message: NetworkMessage<T>) -> AdmittedNetworkMessage<T> {
    let budget = NetworkActorByteBudget::new(1, 0).expect("test actor budget");
    let lease = budget
        .try_reserve(1, false)
        .expect("fresh test actor budget must admit one byte");
    AdmittedNetworkMessage::new(message, lease)
}
fn admitted_with_exact_actor_bytes<T: Pload + message::ClassifyTopic>(
    network: &NetworkBase<T, ChaCha20Poly1305>,
    message: NetworkMessage<T>,
) -> (
    AdmittedNetworkMessage<T>,
    Arc<NetworkActorByteBudget>,
    usize,
) {
    let topic = match &message {
        NetworkMessage::Post(post) => post.data.topic(),
        NetworkMessage::Broadcast(broadcast) => broadcast.data.topic(),
    };
    let plaintext_frame_bytes =
        outbound_actor_message_wire_bytes(&message, &network.self_id, network.relay_ttl)
            .expect("test message must have canonical actor wire geometry");
    let topic_cap = match topic {
        message::Topic::ConsensusSafety | message::Topic::Control => network.cap_control,
        message::Topic::Consensus => network.cap_consensus,
        message::Topic::ConsensusPayload
        | message::Topic::ConsensusChunk
        | message::Topic::BlockSync => network.cap_block_sync,
        message::Topic::TxGossip | message::Topic::TxGossipRestricted => network.cap_tx_gossip,
        message::Topic::PeerGossip | message::Topic::TrustGossip => network.cap_peer_gossip,
        message::Topic::Health => network.cap_health,
        message::Topic::Connect => network.cap_connect,
        message::Topic::Other => network.cap_other,
    };
    assert!(
        plaintext_frame_bytes <= topic_cap,
        "test message must fit its production topic cap"
    );
    let retained_bytes = crate::frame_queue_charge_for::<ChaCha20Poly1305>(plaintext_frame_bytes)
        .expect("test message must have a bounded stream charge");
    let budget = NetworkActorByteBudget::new(retained_bytes, 0)
        .expect("one exact test actor owner must fit");
    let lease = budget
        .try_reserve(retained_bytes, false)
        .expect("exact test actor bytes must be available");
    (
        AdmittedNetworkMessage::new(message, lease),
        budget,
        retained_bytes,
    )
}
#[test]
fn connect_attempt_jitter_is_stable_and_bounded() {
    let self_id = random_peer_id();
    let peer_id = random_peer_id();
    let addr = socket_addr!(127.0.0.1:34567);
    let upper_ms = 25;
    let jitter = connect_attempt_jitter_ms(
        &self_id,
        &peer_id,
        &addr,
        3,
        Duration::from_millis(50),
        upper_ms,
    );
    assert_eq!(
        jitter,
        connect_attempt_jitter_ms(
            &self_id,
            &peer_id,
            &addr,
            3,
            Duration::from_millis(50),
            upper_ms,
        )
    );
    assert!(jitter <= upper_ms);
    assert_eq!(
        connect_attempt_jitter_ms(&self_id, &peer_id, &addr, 3, Duration::from_millis(50), 0,),
        0
    );
}
#[test]
fn reconnect_backoff_jitter_is_stable_and_bounded() {
    let self_id = random_peer_id();
    let peer_id = random_peer_id();
    let addr = socket_addr!(127.0.0.1:45678);
    let upper_ms = 250;
    let jitter = reconnect_backoff_jitter_ms(
        &self_id,
        &peer_id,
        &addr,
        Duration::from_millis(100),
        Duration::from_millis(200),
        upper_ms,
    );
    assert_eq!(
        jitter,
        reconnect_backoff_jitter_ms(
            &self_id,
            &peer_id,
            &addr,
            Duration::from_millis(100),
            Duration::from_millis(200),
            upper_ms,
        )
    );
    assert!(jitter >= 100);
    assert!(jitter <= upper_ms);
    assert_eq!(
        reconnect_backoff_jitter_ms(
            &self_id,
            &peer_id,
            &addr,
            Duration::from_millis(100),
            Duration::from_millis(200),
            0,
        ),
        0
    );
}
#[test]
fn reconnect_backoff_at_cap_cannot_repeat_a_near_zero_delay() {
    let self_id = random_peer_id();
    let peer_id = random_peer_id();
    let addr = socket_addr!(127.0.0.1:45679);
    let capped = Duration::from_secs(5);
    assert_eq!(
        reconnect_backoff_jitter_ms(&self_id, &peer_id, &addr, capped, capped, 5_000),
        5_000,
        "a capped deterministic backoff must retain its configured floor"
    );
}
fn deterministic_validator_roster(count: u8) -> Vec<PeerId> {
    let mut roster: Vec<_> = (1..=count)
        .map(|seed| {
            let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                .expect("derive deterministic BLS validator fixture");
            PeerId::from(key_pair.public_key().clone())
        })
        .collect();
    roster.sort();
    roster
}
fn validator_scheduler(roster: &[PeerId], takeover_delay: Duration) -> ValidatorDialScheduler {
    ValidatorDialScheduler::new(roster.iter().cloned().collect(), takeover_delay)
}
#[test]
fn outbound_authentication_lifetime_rejects_unrepresentable_budgets() {
    use iroha_config::parameters::defaults::network::{DIAL_TIMEOUT, PREAUTH_TIMEOUT};

    assert_eq!(
        checked_outbound_authentication_timeout(DIAL_TIMEOUT, PREAUTH_TIMEOUT),
        Some(Duration::from_secs(35))
    );
    assert!(
        checked_outbound_authentication_timeout(Duration::MAX, Duration::from_secs(1)).is_none(),
        "an overflowing budget must fail before spawning transport work"
    );
    assert!(
        checked_outbound_authentication_timeout(Duration::MAX, Duration::ZERO).is_none(),
        "a duration that does not fit the monotonic clock must fail closed"
    );
}
#[test]
fn four_validator_full_mesh_has_exactly_six_balanced_initial_dial_owners() {
    let roster = deterministic_validator_roster(4);
    let now = tokio::time::Instant::now();
    let mut total_immediate = 0usize;
    let mut out_degrees = vec![0usize; roster.len()];
    for (self_rank, self_id) in roster.iter().enumerate() {
        let mut scheduler = validator_scheduler(&roster, Duration::from_secs(30));
        for peer_id in roster.iter().filter(|peer_id| *peer_id != self_id) {
            match scheduler.role(self_id, peer_id) {
                ValidatorDialRole::Preferred => {
                    assert_eq!(scheduler.not_before(self_id, peer_id, now, now), None);
                    total_immediate += 1;
                    out_degrees[self_rank] += 1;
                }
                ValidatorDialRole::Standby => {
                    assert_eq!(
                        scheduler.not_before(self_id, peer_id, now, now),
                        Some(now + Duration::from_secs(30))
                    );
                }
                ValidatorDialRole::Unmanaged => {
                    panic!("every distinct configured-validator pair must be managed")
                }
            }
        }
    }
    assert_eq!(
        total_immediate, 6,
        "four validators have six unordered pairs"
    );
    let min = *out_degrees.iter().min().expect("non-empty degrees");
    let max = *out_degrees.iter().max().expect("non-empty degrees");
    assert!(
        max - min <= 1,
        "pair ownership must remain balanced: {out_degrees:?}"
    );
}
#[test]
fn standby_takes_over_once_after_bounded_owner_unavailability() {
    let roster = deterministic_validator_roster(2);
    let now = tokio::time::Instant::now();
    let delay = Duration::from_secs(17);
    let (preferred, standby) = if validator_scheduler(&roster, delay).role(&roster[0], &roster[1])
        == ValidatorDialRole::Preferred
    {
        (&roster[0], &roster[1])
    } else {
        (&roster[1], &roster[0])
    };
    let mut preferred_scheduler = validator_scheduler(&roster, delay);
    let mut standby_scheduler = validator_scheduler(&roster, delay);
    assert_eq!(
        preferred_scheduler.not_before(preferred, standby, now, now),
        None
    );
    let deadline = standby_scheduler
        .not_before(standby, preferred, now, now)
        .expect("backup endpoint has a takeover deadline");
    assert_eq!(deadline, now + delay);
    assert!(now + delay - Duration::from_nanos(1) < deadline);
    assert_eq!(
        standby_scheduler.not_before(standby, preferred, deadline, now),
        Some(deadline),
        "takeover becomes eligible without minting another retry epoch"
    );
}
#[tokio::test(start_paused = true)]
async fn validator_standby_dials_after_authentication_tenure_despite_long_idle_timeout() {
    let mut network = bare_network().expect("validator standby actor fixture must initialize");
    let roster = deterministic_validator_roster(2);
    network.self_id = roster[1].clone();
    network.idle_timeout = Duration::from_secs(300);
    network.dial_timeout = Duration::from_secs(5);
    network.outbound_authentication_timeout =
        checked_outbound_authentication_timeout(network.dial_timeout, Duration::from_secs(30))
            .expect("bounded authentication tenure");
    network.validator_dial_scheduler = ValidatorDialScheduler::new(
        roster.iter().cloned().collect(),
        network.outbound_authentication_timeout,
    );
    network.happy_eyeballs_stagger = Duration::ZERO;
    let peer = Peer::new(socket_addr!(127.0.0.1:12091), roster[0].clone());
    network.current_topology.insert(peer.id().clone());
    network
        .current_peers_addresses
        .push((peer.id().clone(), peer.address().clone()));
    let started = tokio::time::Instant::now();
    network.update_topology();
    assert_eq!(network.pending_connects.len(), 1);
    assert_eq!(
        network.pending_connects[0].0,
        started + network.outbound_authentication_timeout
    );

    tokio::time::advance(Duration::from_secs(34)).await;
    network.update_topology();
    network.process_pending_connects();
    assert!(network.connecting_peers.is_empty());
    assert_eq!(network.pending_connects.len(), 1);
    assert_eq!(
        network.pending_connects[0].0,
        started + network.outbound_authentication_timeout,
        "topology refresh must preserve the original takeover deadline"
    );

    tokio::time::advance(Duration::from_secs(1)).await;
    network.process_pending_connects();
    assert!(tokio::time::Instant::now() < started + network.idle_timeout);
    assert_eq!(network.connecting_peers.len(), 1);
    assert!(
        network
            .connecting_peers
            .values()
            .any(|active| active == &peer)
    );
    assert_eq!(network.outbound_connections.len(), 1);
    assert!(network.pending_connects.is_empty());
}
#[test]
fn simultaneous_restart_and_roster_iteration_order_choose_the_same_pair_owners() {
    let roster = deterministic_validator_roster(6);
    let reversed: HashSet<_> = roster.iter().rev().cloned().collect();
    let canonical: HashSet<_> = roster.iter().cloned().collect();
    let first = ValidatorDialScheduler::new(canonical, Duration::from_secs(5));
    let restarted = ValidatorDialScheduler::new(reversed, Duration::from_secs(5));
    for self_id in &roster {
        for peer_id in roster.iter().filter(|peer_id| *peer_id != self_id) {
            assert_eq!(
                first.role(self_id, peer_id),
                restarted.role(self_id, peer_id),
                "hash-map insertion order and simultaneous restart must not affect ownership"
            );
            assert_ne!(
                first.role(self_id, peer_id),
                first.role(peer_id, self_id),
                "each unordered pair has exactly one preferred endpoint"
            );
        }
    }
}
#[test]
fn address_order_and_malicious_gossip_cannot_change_validator_pair_ownership() {
    let roster = deterministic_validator_roster(4);
    let self_id = &roster[0];
    let peer_id = &roster[3];
    let outsider_key = KeyPair::try_from_seed(vec![99; 32], Algorithm::BlsNormal)
        .expect("derive deterministic outsider fixture");
    let outsider = PeerId::from(outsider_key.public_key().clone());
    let mut scheduler = validator_scheduler(&roster, Duration::from_secs(9));
    let role = scheduler.role(self_id, peer_id);
    let now = tokio::time::Instant::now();
    let first_deadline = scheduler.not_before(self_id, peer_id, now, now);
    // Address ordering and gossip source identities are intentionally absent
    // from the scheduler input. Re-observing a validator through arbitrary
    // gossip cannot reset its retained failover epoch.
    for _untrusted_address in [
        socket_addr!(203.0.113.9:1),
        socket_addr!(127.0.0.1:65_000),
        socket_addr!(192.0.2.1:2),
    ] {
        assert_eq!(scheduler.role(self_id, peer_id), role);
        assert_eq!(
            scheduler.not_before(self_id, peer_id, now, now),
            first_deadline
        );
    }
    assert_eq!(
        scheduler.role(self_id, &outsider),
        ValidatorDialRole::Unmanaged,
        "malicious gossip cannot promote an outsider into validator dial authority"
    );
    let mut forged_roster: HashSet<_> = roster.iter().cloned().collect();
    forged_roster.insert(outsider.clone());
    scheduler.replace_roster(forged_roster, self_id);
    assert_eq!(
        scheduler.role(self_id, &outsider),
        ValidatorDialRole::Unmanaged,
        "runtime updates cannot expand the startup-authenticated configured subset"
    );
}
#[test]
fn dynamic_validator_add_remove_preserves_non_validator_dial_behavior() {
    let roster = deterministic_validator_roster(5);
    let initial: HashSet<_> = roster[..4].iter().cloned().collect();
    let self_id = &roster[0];
    let removed = &roster[1];
    let added = &roster[4];
    let now = tokio::time::Instant::now();
    let mut scheduler = validator_scheduler(&roster, Duration::from_secs(13));
    scheduler.replace_roster(initial, self_id);
    let _ = scheduler.not_before(self_id, removed, now, now);
    let updated: HashSet<_> = [
        roster[0].clone(),
        roster[2].clone(),
        roster[3].clone(),
        added.clone(),
    ]
    .into_iter()
    .collect();
    scheduler.replace_roster(updated, self_id);
    assert_eq!(
        scheduler.role(self_id, removed),
        ValidatorDialRole::Unmanaged,
        "a removed validator immediately returns to ordinary dynamic-peer policy"
    );
    assert_eq!(scheduler.not_before(self_id, removed, now, now), None);
    assert_ne!(
        scheduler.role(self_id, added),
        ValidatorDialRole::Unmanaged,
        "a configured validator added by authority enters pair ownership"
    );
}
#[test]
fn live_validator_membership_commits_with_pair_ownership_and_prunes_outsiders() {
    let_test_network!(network);
    let self_id = network.self_id.clone();
    let peer_id = random_peer_id();
    let outsider = random_peer_id();
    let configured = HashSet::from([self_id.clone(), peer_id.clone(), outsider.clone()]);
    network.validator_dial_scheduler =
        ValidatorDialScheduler::new(configured, Duration::from_secs(11));
    network
        .validator_dial_scheduler
        .replace_roster(HashSet::from([self_id.clone()]), &self_id);
    assert_eq!(
        network.validator_dial_scheduler.role(&self_id, &peer_id),
        ValidatorDialRole::Unmanaged
    );
    network.set_validator_topology(message::UpdateValidatorTopology {
        topology: HashSet::from([self_id.clone(), peer_id.clone()]),
        validator_dial_roster: HashSet::from([self_id.clone(), peer_id.clone(), outsider.clone()]),
    });
    assert!(network.current_topology.contains(&peer_id));
    assert_ne!(
        network.validator_dial_scheduler.role(&self_id, &peer_id),
        ValidatorDialRole::Unmanaged,
        "membership must never commit without pair ownership"
    );
    assert_eq!(
        network.validator_dial_scheduler.role(&self_id, &outsider),
        ValidatorDialRole::Unmanaged,
        "an identity outside the same topology snapshot cannot gain dial authority"
    );
}
#[test]
fn authenticated_session_restart_has_one_immediate_reconnector_and_stable_backup_deadline() {
    let roster = deterministic_validator_roster(4);
    let now = tokio::time::Instant::now();
    let delay = Duration::from_secs(23);
    let mut immediate = 0usize;
    let mut standby_deadlines = Vec::new();
    for self_id in &roster {
        let mut scheduler = validator_scheduler(&roster, delay);
        for peer_id in roster.iter().filter(|peer_id| *peer_id != self_id) {
            scheduler.note_session_established(self_id, peer_id, now, now);
            match scheduler.not_before(self_id, peer_id, now, now) {
                None => immediate += 1,
                Some(deadline) => {
                    assert_eq!(deadline, now + delay);
                    assert_eq!(
                        scheduler.not_before(self_id, peer_id, now, now),
                        Some(deadline),
                        "repeated reconnect triggers must coalesce on one deadline"
                    );
                    standby_deadlines.push(deadline);
                }
            }
        }
    }
    assert_eq!(
        immediate, 6,
        "only one endpoint per pair reconnects immediately"
    );
    assert_eq!(standby_deadlines.len(), 6);
}
#[test]
fn trust_gossip_allowed_blocks_when_disabled() {
    assert!(trust_gossip_allowed(
        message::Topic::PeerGossip,
        /*trust_gossip=*/ false
    ));
    assert!(trust_gossip_allowed(
        message::Topic::PeerGossip,
        /*trust_gossip=*/ true
    ));
    assert!(trust_gossip_allowed(
        message::Topic::TrustGossip,
        /*trust_gossip=*/ true
    ));
    assert!(!trust_gossip_allowed(
        message::Topic::TrustGossip,
        /*trust_gossip=*/ false
    ));
}
#[test]
fn subscriber_filter_routes_topics() {
    let_test_network!(network, TopicMsg);
    let (trust_tx, mut trust_rx) = mpsc::channel(1);
    let (peer_tx, mut peer_rx) = mpsc::channel(1);
    network.subscribe_to_peers_messages(Subscriber::new(
        trust_tx,
        SubscriberFilter::topics([message::Topic::TrustGossip]),
        1,
    ));
    network.subscribe_to_peers_messages(Subscriber::new(
        peer_tx,
        SubscriberFilter::topics([message::Topic::PeerGossip]),
        1,
    ));
    let peer = test_peer(socket_addr!(127.0.0.1:202));
    network.dispatch_to_subscribers(PeerMessage::new(peer.clone(), TopicMsg::Trust, 1));
    assert!(matches!(trust_rx.try_recv(), Ok(msg) if matches!(msg.payload, TopicMsg::Trust)));
    assert!(matches!(peer_rx.try_recv(), Err(TryRecvError::Empty)));
    network.dispatch_to_subscribers(PeerMessage::new(peer, TopicMsg::Peer, 1));
    assert!(matches!(peer_rx.try_recv(), Ok(msg) if matches!(msg.payload, TopicMsg::Peer)));
    assert!(matches!(trust_rx.try_recv(), Err(TryRecvError::Empty)));
}
#[test]
fn peer_message_channel_honors_capacity() {
    let cap = core::num::NonZeroUsize::new(2).expect("nonzero");
    let (tx, _rx) = peer_message_channel::<DummyMsg>(cap);
    let peer = test_peer(socket_addr!(127.0.0.1:0));
    let origin = random_peer_id();
    let payload = RelayMessage::new(origin, RelayTarget::Broadcast, DEFAULT_RELAY_TTL, DummyMsg);
    let msg = PeerMessage::new(peer, payload, 1);
    assert!(
        tx.try_send(msg.try_clone_retained().expect("synthetic clone"))
            .is_ok()
    );
    assert!(
        tx.try_send(msg.try_clone_retained().expect("synthetic clone"))
            .is_ok()
    );
    assert!(matches!(
        tx.try_send(msg),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_))
    ));
}
#[test]
fn reply_route_survives_peer_message_clone_mapping_and_split() {
    let owner = Arc::new(());
    let transport = test_peer(socket_addr!(127.0.0.1:12001));
    let semantic_origin = test_peer(socket_addr!(127.0.0.1:12002));
    let tenure = test_reply_tenure(&owner, transport.id().clone(), 17, 3);
    let route = NetworkReplyRoute::new(semantic_origin.id().clone(), tenure, 9);
    let mut message = PeerMessage::new_for_connection(transport.clone(), DummyMsg, 19, 17);
    message.set_reply_route(route.clone());
    let cloned = message
        .try_clone_retained()
        .expect("an unretained authenticated test message can be cloned");
    let cloned_route = cloned
        .reply_route()
        .expect("subscriber clone preserves the exact reply route");
    assert!(cloned_route.same_tenure(&route));
    assert!(cloned_route.same_delivery(&route));
    assert_eq!(cloned_route.source_key(), route.source_key());
    let mapped = message.map_payload(semantic_origin.clone(), |DummyMsg| DummyMsg);
    let (mapped_peer, authenticated_via, DummyMsg, payload_bytes, mapped_route, guard) =
        mapped.into_parts_with_reply_route();
    assert_eq!(mapped_peer.id(), semantic_origin.id());
    assert_eq!(&authenticated_via, transport.id());
    assert_eq!(guard.authenticated_via(), transport.id());
    assert_eq!(payload_bytes, 19);
    let mapped_route = mapped_route.expect("payload mapping and split preserve the route");
    assert!(mapped_route.is_authenticated_via(transport.id()));
    assert!(!mapped_route.is_authenticated_via(semantic_origin.id()));
    assert!(mapped_route.same_delivery(&route));
    assert_eq!(mapped_route.source_key(), route.source_key());
    let mut released = PeerMessage::new(semantic_origin.clone(), DummyMsg, 19);
    released
        .reattach_reply_route(mapped_route.clone())
        .expect("bounded release restores the opaque live route");
    assert_eq!(released.authenticated_via(), transport.id());
    mapped_route.tenure.cancel();
    let mut stale_release = PeerMessage::new(semantic_origin, DummyMsg, 19);
    assert!(
        stale_release.reattach_reply_route(mapped_route).is_err(),
        "a retired transport tenure cannot cross a local hold/release boundary"
    );
    let synthetic = PeerMessage::new(transport, DummyMsg, 1);
    assert!(synthetic.reply_route().is_none());
}
#[test]
fn peer_message_rehydration_rejects_second_reply_route_without_retargeting() {
    let owner = Arc::new(());
    let transport_a = test_peer(socket_addr!(127.0.0.1:12003));
    let transport_b = test_peer(socket_addr!(127.0.0.1:12004));
    let semantic_origin = test_peer(socket_addr!(127.0.0.1:12005));
    let original = NetworkReplyRoute::new(
        semantic_origin.id().clone(),
        test_reply_tenure(&owner, transport_a.id().clone(), 31, 7),
        41,
    );
    let candidate = NetworkReplyRoute::new(
        semantic_origin.id().clone(),
        test_reply_tenure(&owner, transport_b.id().clone(), 32, 8),
        42,
    );
    let mut released = PeerMessage::new(semantic_origin, DummyMsg, 23);
    released
        .reattach_reply_route(original.clone())
        .expect("first bounded rehydration attaches the exact capability");
    let returned = released
        .reattach_reply_route(candidate.clone())
        .expect_err("rehydration cannot overwrite an attached capability");
    let retained = released
        .reply_route()
        .expect("failed replacement preserves the original capability");
    assert!(retained.same_delivery(&original));
    assert!(retained.same_tenure(&original));
    assert_eq!(released.authenticated_via(), transport_a.id());
    assert!(returned.same_delivery(&candidate));
    assert!(returned.same_tenure(&candidate));
    assert!(returned.is_authenticated_via(transport_b.id()));
    assert!(!returned.same_delivery(retained));
}
#[tokio::test(flavor = "current_thread")]
async fn peer_message_mints_actor_global_delivery_ordinals_across_connection_tenures() {
    let_test_network!(network, SafetyMsg);
    let (subscriber_tx, mut subscriber_rx) = mpsc::channel(2);
    network.subscribe_to_peers_messages(Subscriber::new(subscriber_tx, SubscriberFilter::All, 2));
    let source_key_pair = random_node_key_pair();
    let source = Peer::new(
        socket_addr!(127.0.0.1:12003),
        source_key_pair.public_key().clone(),
    );
    let retired_connection = 501;
    let current_connection = 502;
    let (current_handle, _current_receivers) = test_wire_peer_handle::<SafetyMsg>(1);
    insert_ref_peer(
        &mut network,
        source.id().clone(),
        source.address().clone(),
        current_connection,
        current_handle,
        true,
    );
    let retired_tenure = test_reply_tenure(
        &network.reply_route_owner,
        source.id().clone(),
        retired_connection,
        2,
    );
    let current_tenure = test_reply_tenure(
        &network.reply_route_owner,
        source.id().clone(),
        current_connection,
        3,
    );
    assert!(
        network
            .reply_route_tenures
            .insert(retired_connection, retired_tenure)
            .is_none()
    );
    assert!(
        network
            .reply_route_tenures
            .insert(current_connection, current_tenure)
            .is_none()
    );
    network.next_reply_delivery_ordinal = 40;
    let local_target = network.self_id.clone();
    network
        .peer_message(PeerMessage::new_for_connection(
            source.clone(),
            RelayMessage::new_signed(
                &source_key_pair,
                RelayTarget::Direct(local_target.clone()),
                DEFAULT_RELAY_TTL,
                SafetyMsg(1),
            ),
            1,
            retired_connection,
        ))
        .await;
    let retired_delivery = subscriber_rx
        .try_recv()
        .expect("draining authenticated tenure reaches its subscriber");
    let retired_route = retired_delivery
        .reply_route()
        .expect("draining authenticated tenure receives a reply capability")
        .clone();
    network
        .peer_message(PeerMessage::new_for_connection(
            source.clone(),
            RelayMessage::new_signed(
                &source_key_pair,
                RelayTarget::Direct(local_target),
                DEFAULT_RELAY_TTL,
                SafetyMsg(2),
            ),
            1,
            current_connection,
        ))
        .await;
    let current_delivery = subscriber_rx
        .try_recv()
        .expect("current authenticated tenure reaches its subscriber");
    let current_route = current_delivery
        .reply_route()
        .expect("current authenticated tenure receives a reply capability")
        .clone();
    assert_eq!(retired_route.delivery_ordinal, 40);
    assert_eq!(current_route.delivery_ordinal, 41);
    assert_eq!(network.next_reply_delivery_ordinal, 42);
    assert_eq!(retired_route.tenure.connection_ordinal, 2);
    assert_eq!(current_route.tenure.connection_ordinal, 3);
    assert!(!retired_route.same_tenure(&current_route));
    assert_eq!(retired_route.source_key(), current_route.source_key());
}
#[test]
fn reply_source_key_groups_relay_origins_and_orders_actor_instances() {
    let owner = Arc::new(());
    let other_owner = Arc::new(());
    let delivery_peer = random_peer_id();
    let other_delivery_peer = random_peer_id();
    let origin_a = random_peer_id();
    let origin_b = random_peer_id();
    let shared_tenure = test_reply_tenure(&owner, delivery_peer.clone(), 21, 7);
    let route_a = NetworkReplyRoute::new(origin_a, Arc::clone(&shared_tenure), 0);
    let route_b = NetworkReplyRoute::new(origin_b, shared_tenure, 1);
    let other_source = NetworkReplyRoute::new(
        route_a.semantic_target().clone(),
        test_reply_tenure(&owner, other_delivery_peer, 22, 8),
        2,
    );
    let other_actor = NetworkReplyRoute::new(
        route_a.semantic_target().clone(),
        test_reply_tenure(&other_owner, delivery_peer, 23, 0),
        0,
    );
    assert_eq!(
        route_a.source_key(),
        route_b.source_key(),
        "many semantic origins behind one authenticated hub share fairness"
    );
    assert!(
        route_a.same_tenure(&route_b),
        "one relay tenure may authenticate several semantic origins"
    );
    assert_ne!(route_a.source_key(), other_source.source_key());
    assert_ne!(route_a.source_key(), other_actor.source_key());
    let hash_keys = HashSet::from([
        route_a.source_key(),
        route_b.source_key(),
        other_source.source_key(),
        other_actor.source_key(),
    ]);
    let tree_keys = BTreeSet::from([
        route_a.source_key(),
        route_b.source_key(),
        other_source.source_key(),
        other_actor.source_key(),
    ]);
    assert_eq!(hash_keys.len(), 3);
    assert_eq!(tree_keys.len(), 3);
    assert_eq!(
        format!("{:?}", route_a.source_key()),
        "NetworkReplySourceKey(..)",
        "debug output must not reveal actor or connection internals"
    );
}
#[test]
fn reply_source_key_shares_identity_without_retaining_delivery_tenure() {
    use std::hash::{Hash as _, Hasher as _};
    fn table_hash(key: &NetworkReplySourceKey) -> u64 {
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hash);
        hash.finish()
    }
    assert_eq!(
        std::mem::size_of::<NetworkReplySourceKey>(),
        std::mem::size_of::<usize>(),
        "a frequently cloned fairness key retains one shared source pointer"
    );
    let owner = Arc::new(());
    let delivery_peer = random_peer_id();
    let semantic_target = random_peer_id();
    let tenure = test_reply_tenure(&owner, delivery_peer.clone(), 31, 9);
    let retired_tenure = Arc::downgrade(&tenure);
    let route = NetworkReplyRoute::new(semantic_target.clone(), tenure, 0);
    let key = route.source_key();
    assert!(Arc::ptr_eq(&key.identity, &route.source_key().identity));
    assert!(Arc::ptr_eq(
        &key.identity,
        &route.clone().source_key().identity
    ));
    let reconnect = NetworkReplyRoute::new(
        semantic_target,
        test_reply_tenure(&owner, delivery_peer.clone(), 32, 10),
        1,
    );
    let later_key = reconnect.source_key();
    assert!(!Arc::ptr_eq(&key.identity, &later_key.identity));
    assert_eq!(
        key, later_key,
        "source equality is independent of backing allocation"
    );
    assert_eq!(key.cmp(&later_key), std::cmp::Ordering::Equal);
    assert_eq!(table_hash(&key), table_hash(&later_key));
    assert_eq!(
        key.process_local_identity_hash(),
        later_key.process_local_identity_hash()
    );
    drop(route);
    assert!(
        retired_tenure.upgrade().is_none(),
        "a source key cannot extend a delivery tenure"
    );
    assert_eq!(key.authenticated_source_peer(), &delivery_peer);
    assert_eq!(
        key, later_key,
        "retiring the delivery does not mutate its source identity"
    );
}
#[test]
fn reply_route_source_updates_are_ordinal_monotonic_and_target_scoped() {
    let owner = Arc::new(());
    let other_owner = Arc::new(());
    let delivery_peer = random_peer_id();
    let semantic_target = random_peer_id();
    let other_target = random_peer_id();
    let prior = NetworkReplyRoute::new(
        semantic_target.clone(),
        test_reply_tenure(&owner, delivery_peer.clone(), 30, 10),
        10,
    );
    let reconnect = NetworkReplyRoute::new(
        semantic_target.clone(),
        test_reply_tenure(&owner, delivery_peer.clone(), 31, 11),
        11,
    );
    let delayed_prior_delivery =
        NetworkReplyRoute::new(semantic_target.clone(), Arc::clone(&prior.tenure), 13);
    let equal_connection_ordinal_different_tenure = NetworkReplyRoute::new(
        semantic_target.clone(),
        test_reply_tenure(&owner, delivery_peer.clone(), 36, 11),
        14,
    );
    let equal_but_distinct = NetworkReplyRoute::new(
        semantic_target.clone(),
        test_reply_tenure(&owner, delivery_peer.clone(), 32, 12),
        10,
    );
    let retargeted = NetworkReplyRoute::new(
        other_target,
        test_reply_tenure(&owner, delivery_peer.clone(), 33, 12),
        12,
    );
    let different_source = NetworkReplyRoute::new(
        prior.semantic_target.clone(),
        test_reply_tenure(&owner, random_peer_id(), 34, 12),
        12,
    );
    let foreign = NetworkReplyRoute::new(
        semantic_target,
        test_reply_tenure(&other_owner, delivery_peer, 35, 12),
        12,
    );
    assert_eq!(
        prior.clone().source_update_from(&prior),
        Ok(NetworkReplyRouteSourceUpdate::Exact)
    );
    assert!(prior.same_tenure(&prior.clone()));
    assert!(!reconnect.same_tenure(&prior));
    assert_eq!(
        reconnect.source_update_from(&prior),
        Ok(NetworkReplyRouteSourceUpdate::Reconnected)
    );
    assert_eq!(
        prior.source_update_from(&reconnect),
        Err(NetworkReplyRouteError::Stale)
    );
    assert_eq!(
        delayed_prior_delivery.source_update_from(&reconnect),
        Err(NetworkReplyRouteError::Stale),
        "a larger delivery ordinal cannot roll connection tenure backward"
    );
    assert_eq!(
        reconnect.source_update_from(&delayed_prior_delivery),
        Err(NetworkReplyRouteError::Stale),
        "reconnect freshness requires both actor-global ordinals to advance"
    );
    assert_eq!(
        equal_connection_ordinal_different_tenure.source_update_from(&reconnect),
        Err(NetworkReplyRouteError::EqualConnectionOrdinalDifferentTenure),
        "one actor-global connection ordinal cannot name two tenures"
    );
    assert_eq!(
        equal_but_distinct.source_update_from(&prior),
        Err(NetworkReplyRouteError::EqualOrdinalDifferentTenure)
    );
    assert_eq!(
        retargeted.source_update_from(&prior),
        Err(NetworkReplyRouteError::Retargeted)
    );
    assert_eq!(
        different_source.source_update_from(&prior),
        Err(NetworkReplyRouteError::DifferentSource)
    );
    assert_eq!(
        foreign.source_update_from(&prior),
        Err(NetworkReplyRouteError::ForeignOwner)
    );
    reconnect.tenure.cancel();
    assert_eq!(
        reconnect.source_update_from(&prior),
        Err(NetworkReplyRouteError::Inactive)
    );
}
#[test]
fn dependent_test_fixture_mints_opaque_tenures_and_delivery_ordinals() {
    let delivery_peer = random_peer_id();
    let semantic_target = random_peer_id();
    let other_target = random_peer_id();
    let mut fixture = NetworkReplyRouteTestFixture::new(delivery_peer);
    let prior = fixture.mint(semantic_target.clone());
    let exact_clone = prior.clone();
    let later = fixture
        .redeliver(&prior)
        .expect("mint a later delivery on the same tenure");
    let reconnected = fixture.mint(semantic_target);
    let retargeted = fixture.mint(other_target);
    assert!(prior.is_active());
    assert_eq!(
        prior.process_local_identity_hash(),
        exact_clone.process_local_identity_hash(),
        "an exact clone retains the immutable delivery identity"
    );
    assert_ne!(
        prior.process_local_identity_hash(),
        later.process_local_identity_hash(),
        "a same-tenure redelivery receives another actor-global ordinal"
    );
    assert_ne!(
        later.process_local_identity_hash(),
        reconnected.process_local_identity_hash(),
        "a reconnect receives another immutable delivery identity"
    );
    let prior_identity = prior.process_local_identity_hash();
    assert_eq!(
        reconnected.source_update_from(&prior),
        Ok(NetworkReplyRouteSourceUpdate::Reconnected)
    );
    assert_eq!(reconnected.source_key(), prior.source_key());
    assert_eq!(
        reconnected.source_key().process_local_identity_hash(),
        prior.source_key().process_local_identity_hash(),
        "a reconnect under one actor owner preserves the source projection"
    );
    assert_eq!(
        retargeted.source_update_from(&reconnected),
        Err(NetworkReplyRouteError::Retargeted)
    );
    assert!(fixture.mark_reply_unwritable_while_delivery_active(&prior));
    assert!(prior.is_active());
    assert!(
        !prior.is_reply_writable(),
        "draining test fixture preserves delivery authority but closes its writer"
    );
    assert!(fixture.retire(&prior));
    assert!(!prior.is_active());
    assert_eq!(
        prior.process_local_identity_hash(),
        prior_identity,
        "retirement cannot rewrite immutable delivery identity"
    );
    let foreign_delivery = random_peer_id();
    let mut foreign_fixture = NetworkReplyRouteTestFixture::new(foreign_delivery);
    let foreign = foreign_fixture.mint(reconnected.semantic_target().clone());
    assert!(!fixture.mark_reply_unwritable_while_delivery_active(&foreign));
    assert!(!fixture.retire(&foreign));
    assert!(foreign.is_active());
    let mut same_peer_foreign_fixture =
        NetworkReplyRouteTestFixture::new(prior.authenticated_via().clone());
    let same_peer_foreign = same_peer_foreign_fixture.mint(prior.semantic_target().clone());
    assert_ne!(
        prior.source_key(),
        same_peer_foreign.source_key(),
        "two actor owners must not alias even for the same authenticated peer"
    );
    assert_ne!(
        prior.source_key().process_local_identity_hash(),
        same_peer_foreign.source_key().process_local_identity_hash(),
        "the fixed-width source projection must retain opaque actor ownership"
    );
}
#[test]
fn reply_route_history_projection_tracks_live_and_retired_transitions() {
    // Reconstruct the full documented preimage independently of the sealed
    // projections, so cached identity cannot hide a substituted tuple.
    fn fresh_route_hash(route: &NetworkReplyRoute) -> Hash {
        let actor = (Arc::as_ptr(&route.tenure.owner) as usize as u128).to_le_bytes();
        let tenure = (Arc::as_ptr(&route.tenure) as usize as u128).to_le_bytes();
        let connection = route.tenure.connection_ordinal.to_le_bytes();
        let delivery = route.delivery_ordinal.to_le_bytes();
        let capacity = u64::try_from(route.tenure.source_capacity)
            .unwrap()
            .to_le_bytes();
        let source = route.tenure.delivery_peer.encode();
        let target = route.semantic_target.encode();
        let source_hash = Hash::new_from_chunks(&[
            b"iroha:p2p:reply-source-process-local-identity:v1\n",
            &actor,
            &source,
        ]);
        assert_eq!(
            route.source_key().process_local_identity_hash(),
            source_hash
        );
        let hash = Hash::new_from_chunks(&[
            b"iroha:p2p:reply-route-process-local-identity:v1\n",
            &actor,
            &tenure,
            &connection,
            &delivery,
            &capacity,
            &source,
            &target,
        ]);
        assert_eq!(route.process_local_identity_hash(), hash);
        hash
    }
    fn exact_history(routes: &NetworkReplyRoutes) -> Hash {
        let mut bytes = b"iroha:p2p:reply-route-history-process-local:v1\n".to_vec();
        bytes.extend_from_slice(&(Arc::as_ptr(&routes.owner) as usize as u128).to_le_bytes());
        bytes.extend_from_slice(&u64::try_from(routes.source_capacity).unwrap().to_le_bytes());
        bytes.extend_from_slice(&routes.semantic_target.encode());
        for (marker, members) in [(0, &routes.attempts), (1, &routes.retired_attempts)] {
            bytes.extend_from_slice(&u64::try_from(members.len()).unwrap().to_le_bytes());
            for route in members.values() {
                bytes.push(marker);
                bytes.extend_from_slice(fresh_route_hash(route).as_ref());
            }
        }
        let hash = Hash::new(bytes);
        assert_eq!(routes.process_local_exact_history_hash(), hash);
        assert_eq!(routes.clone().process_local_exact_history_hash(), hash);
        hash
    }

    let hub_a = random_peer_id();
    let hub_b = random_peer_id();
    let target = random_peer_id();
    let mut fixture = NetworkReplyRouteTestFixture::with_source_capacity(hub_a.clone(), 2);
    let first = fixture.mint(target.clone());
    let first_set = NetworkReplyRoutes::try_from_route(first.clone()).expect("source A");
    let mut routes = first_set.clone();
    let initial = exact_history(&routes);
    let later = fixture
        .redeliver(&first)
        .expect("same-tenure later delivery");
    routes
        .merge(&NetworkReplyRoutes::try_from_route(later.clone()).unwrap())
        .unwrap();
    let redelivered = exact_history(&routes);
    assert_ne!(
        redelivered, initial,
        "the later delivery and its tombstone both enter history"
    );
    let second = fixture.mint_via(target.clone(), hub_b.clone());
    routes
        .merge(&NetworkReplyRoutes::try_from_route(second.clone()).unwrap())
        .unwrap();
    let two_sources = exact_history(&routes);
    assert_ne!(two_sources, redelivered);
    assert!(fixture.mark_reply_unwritable_while_delivery_active(&second));
    assert_eq!(
        exact_history(&routes),
        two_sources,
        "writer liveness is not identity"
    );
    assert!(fixture.retire(&second));
    assert_eq!(
        exact_history(&routes),
        two_sources,
        "retirement awaits the owned pruning snapshot"
    );
    let before_prune = routes.clone();
    let (_, receipt) = routes.retain_active_with_receipt();
    routes = receipt
        .into_output(&before_prune)
        .expect("exact pruning receipt");
    let pruned = exact_history(&routes);
    assert_ne!(
        pruned, two_sources,
        "active-to-retired placement changes the preimage"
    );
    routes
        .merge_observed(&first_set)
        .expect("a stale same-source observation is inert");
    assert_eq!(exact_history(&routes), pruned);
    let reconnected = fixture.mint_via(target.clone(), hub_b);
    routes
        .merge_observed(&NetworkReplyRoutes::try_from_route(reconnected).unwrap())
        .unwrap();
    let rejoined = exact_history(&routes);
    assert_ne!(rejoined, pruned);
    assert!(routes.remove_completed_source(&first.source_key()));
    let completed = exact_history(&routes);
    assert_ne!(
        completed, rejoined,
        "completion removes active and retired source history"
    );

    let mut foreign_fixture = NetworkReplyRouteTestFixture::new(hub_a.clone());
    let foreign = NetworkReplyRoutes::try_from_route(foreign_fixture.mint(target.clone())).unwrap();
    assert_eq!(
        routes.merge(&foreign),
        Err(NetworkReplyRouteError::ForeignOwner)
    );
    assert_eq!(
        exact_history(&routes),
        completed,
        "failed merges retain the exact preimage"
    );
    let forged = fixture
        .forge_equal_ordinal_different_tenure(&later, target, hub_a)
        .unwrap();
    assert_ne!(fresh_route_hash(&forged), fresh_route_hash(&later));
    assert!(
        !forged.is_active(),
        "sealed projections cannot authenticate a substituted binding"
    );
    assert!(matches!(
        NetworkReplyRoutes::try_from_route(forged),
        Err(NetworkReplyRouteError::EqualOrdinalDifferentTenure)
    ));
}
#[test]
fn cancelled_newer_hub_cannot_erase_older_independent_route_attempt() {
    let owner = Arc::new(());
    let older_hub = random_peer_id();
    let newer_hub = random_peer_id();
    let semantic_target = random_peer_id();
    let older = NetworkReplyRoute::new(
        semantic_target.clone(),
        test_reply_tenure(&owner, older_hub, 40, 20),
        20,
    );
    let newer = NetworkReplyRoute::new(
        semantic_target,
        test_reply_tenure(&owner, newer_hub, 41, 21),
        21,
    );
    assert_ne!(older.source_key(), newer.source_key());
    let mut routes = NetworkReplyRoutes::try_from_route(older.clone()).expect("older route");
    routes
        .merge(&NetworkReplyRoutes::try_from_route(newer.clone()).expect("newer route"))
        .expect("alternate hub owns an independent attempt");
    assert_eq!(routes.len(), 2);
    newer.tenure.cancel();
    assert!(routes.iter().any(|route| route.same_delivery(&older)));
    assert!(older.is_active());
}
#[test]
fn dependent_fixture_models_bounded_actor_global_multi_hub_ownership() {
    let older_hub = random_peer_id();
    let newer_hub = random_peer_id();
    let semantic_target = random_peer_id();
    let mut fixture = NetworkReplyRouteTestFixture::new(older_hub.clone());
    let older = fixture.mint_via(semantic_target.clone(), older_hub);
    let newer = fixture.mint_via(semantic_target, newer_hub);
    let mut set = NetworkReplyRoutes::try_from_route(older.clone()).expect("older route");
    set.merge(&NetworkReplyRoutes::try_from_route(newer.clone()).expect("newer route"))
        .expect("alternate hub route");
    assert_eq!(set.len(), 2);
    assert!(fixture.retire(&newer));
    assert!(set.iter().any(|route| route.same_delivery(&older)));
    assert!(older.is_active());
}
#[test]
fn reply_route_pruning_retains_equal_ordinal_tenure_tombstone() {
    let hub = random_peer_id();
    let target = random_peer_id();
    let mut fixture = NetworkReplyRouteTestFixture::with_source_capacity(hub.clone(), 2);
    let retired = fixture.mint_via(target.clone(), hub.clone());
    let mut routes =
        NetworkReplyRoutes::try_from_route(retired.clone()).expect("initial live route");
    let before_pruning = routes.clone();
    let mut forged_live_omission = before_pruning.clone();
    assert!(forged_live_omission.remove_completed_source(&retired.source_key()));
    let mut no_op_snapshot = before_pruning.clone();
    let (retained_count, no_op_receipt) = no_op_snapshot.retain_active_with_receipt();
    assert_eq!(retained_count, 1);
    assert!(
        no_op_receipt.into_output(&forged_live_omission).is_none(),
        "a receipt cannot be consumed against a caller-invented input omission"
    );
    let mut no_op_snapshot = before_pruning.clone();
    let (_, no_op_receipt) = no_op_snapshot.retain_active_with_receipt();
    let exact_no_op = no_op_receipt
        .into_output(&before_pruning)
        .expect("the receipt returns its operation-owned no-op output");
    assert!(
        exact_no_op.has_same_exact_history(&before_pruning),
        "the no-op snapshot retains every exact live delivery"
    );
    let (retained_count, prune_receipt) =
        routes.retain_active_with_receipt_after_snapshot(|| assert!(fixture.retire(&retired)));
    assert_eq!(
        retained_count, 1,
        "a route retiring after the snapshot must remain for the next bounded pass"
    );
    routes = prune_receipt
        .into_output(&before_pruning)
        .expect("consume the exact first-snapshot receipt");
    assert!(!retired.is_active());
    assert!(routes.iter().any(|route| route.same_delivery(&retired)));
    assert!(
        routes.retired_attempts.is_empty(),
        "the first pass must neither remove nor tombstone an unsnapshotted retirement"
    );
    let before_second_pruning = routes.clone();
    let (retained_count, prune_receipt) = routes.retain_active_with_receipt();
    assert_eq!(retained_count, 0);
    routes = prune_receipt
        .into_output(&before_second_pruning)
        .expect("consume the exact second-snapshot receipt");
    assert!(
        routes
            .retired_attempts
            .get(&retired.source_key())
            .is_some_and(|route| route.same_delivery(&retired)),
        "the next pass must remove and tombstone the exact retired delivery"
    );
    let collision = fixture
        .forge_equal_ordinal_different_tenure(&retired, target.clone(), hub.clone())
        .expect("forge an active capability with the retired delivery ordinal");
    assert!(matches!(
        NetworkReplyRoutes::try_from_route(collision),
        Err(NetworkReplyRouteError::EqualOrdinalDifferentTenure)
    ));
    assert!(routes.is_empty());
    let reconnected = fixture.mint_via(target, hub);
    routes
        .merge(
            &NetworkReplyRoutes::try_from_route(reconnected.clone())
                .expect("later reconnect route"),
        )
        .expect("a genuinely later delivery remains admissible");
    assert!(routes.iter().any(|route| route.same_delivery(&reconnected)));
}
#[test]
fn delayed_superseded_tenure_cannot_replace_or_tombstone_newer_same_source_writer() {
    let hub = random_peer_id();
    let target = random_peer_id();
    let mut fixture = NetworkReplyRouteTestFixture::with_source_capacity(hub.clone(), 1);
    let old_route = fixture.mint_via(target.clone(), hub.clone());
    let current_route = fixture.mint_via(target.clone(), hub);
    let delayed_old_route = fixture
        .redeliver(&old_route)
        .expect("old tenure can deliver after the replacement was observed");
    assert!(delayed_old_route.delivery_ordinal > current_route.delivery_ordinal);
    assert!(delayed_old_route.tenure.connection_ordinal < current_route.tenure.connection_ordinal);
    let current = NetworkReplyRoutes::try_from_route(current_route.clone())
        .expect("current writer route set");
    let delayed = NetworkReplyRoutes::try_from_route(delayed_old_route.clone())
        .expect("delayed old-tenure observation");
    let mut strict_live = current.clone();
    assert_eq!(
        strict_live.merge(&delayed),
        Err(NetworkReplyRouteError::Stale),
        "strict attachment rejects a superseded tenure even at a larger delivery ordinal"
    );
    assert!(
        strict_live
            .iter()
            .any(|route| route.same_delivery(&current_route))
    );
    let mut observed_live = current.clone();
    observed_live
        .merge_observed(&delayed)
        .expect("observed stale delivery is a source-local no-op");
    assert!(observed_live.has_same_exact_history(&current));
    assert!(fixture.retire(&old_route));
    let mut delayed_tombstone = delayed;
    assert_eq!(delayed_tombstone.retain_active(), 0);
    assert!(
        delayed_tombstone
            .retired_attempts
            .get(&delayed_old_route.source_key())
            .is_some_and(|route| route.same_delivery(&delayed_old_route))
    );
    let mut strict_tombstone = current.clone();
    strict_tombstone
        .merge(&delayed_tombstone)
        .expect("a stale tombstone preserves collision history without retiring the writer");
    assert!(
        strict_tombstone
            .iter()
            .any(|route| route.same_delivery(&current_route)),
        "a lower-tenure tombstone must not erase the responsive replacement writer"
    );
    assert!(strict_tombstone.has_valid_container_shape());
    let mut observed_tombstone = current;
    observed_tombstone
        .merge_observed(&delayed_tombstone)
        .expect("observed tombstone uses the same joint tenure/delivery ordering");
    assert!(
        observed_tombstone
            .iter()
            .any(|route| route.same_delivery(&current_route))
    );
    assert!(observed_tombstone.has_valid_container_shape());
    assert!(strict_tombstone.has_same_exact_history(&observed_tombstone));
}
#[test]
fn reply_route_binding_rejects_evicted_tombstone_collision() {
    let hub_a = random_peer_id();
    let hub_b = random_peer_id();
    let hub_c = random_peer_id();
    let target = random_peer_id();
    let mut fixture = NetworkReplyRouteTestFixture::with_source_capacity(hub_a.clone(), 2);
    let route_a = fixture.mint_via(target.clone(), hub_a.clone());
    let source_a = route_a.source_key();
    let mut history = NetworkReplyRoutes::try_from_route(route_a.clone()).expect("source A route");
    assert!(fixture.retire(&route_a));
    assert_eq!(history.retain_active(), 0);
    let route_b = fixture.mint_via(target.clone(), hub_b);
    history
        .merge(&NetworkReplyRoutes::try_from_route(route_b.clone()).expect("source B route"))
        .expect("source B follows retired source A");
    assert!(fixture.retire(&route_b));
    assert_eq!(history.retain_active(), 0);
    let route_c = fixture.mint_via(target.clone(), hub_c);
    history
        .merge(&NetworkReplyRoutes::try_from_route(route_c.clone()).expect("source C route"))
        .expect("source C follows retired source B");
    assert!(fixture.retire(&route_c));
    assert_eq!(history.retain_active(), 0);
    assert_eq!(history.retired_attempts.len(), 2);
    assert!(
        !history.retired_attempts.contains_key(&source_a),
        "capacity-two A/B/C churn must evict the oldest source-A tombstone"
    );
    let collision = fixture
        .forge_equal_ordinal_different_tenure(&route_a, target, hub_a)
        .expect("forge tenure substitution after source-A history eviction");
    assert!(route_a.equal_ordinal_different_tenure(&collision));
    assert!(!collision.is_active());
    assert!(matches!(
        NetworkReplyRoutes::try_from_route(collision.clone()),
        Err(NetworkReplyRouteError::EqualOrdinalDifferentTenure)
    ));
    let collision_source = collision.source_key();
    let unchecked_candidate = NetworkReplyRoutes {
        semantic_target: history.semantic_target.clone(),
        owner: Arc::clone(&history.owner),
        source_capacity: history.source_capacity,
        process_local_identity_prefix: Arc::clone(&history.process_local_identity_prefix),
        attempts: BTreeMap::from([(collision_source, collision)]),
        retired_attempts: BTreeMap::new(),
    };
    assert!(matches!(
        history.merge(&unchecked_candidate),
        Err(NetworkReplyRouteError::EqualOrdinalDifferentTenure)
    ));
    assert!(history.is_empty());
}
#[test]
fn reply_route_set_isolates_sources_preserves_cursors_and_prunes_retired_capacity() {
    let hub_a = random_peer_id();
    let hub_b = random_peer_id();
    let hub_c = random_peer_id();
    let target = random_peer_id();
    let mut fixture = NetworkReplyRouteTestFixture::with_source_capacity(hub_a.clone(), 2);
    let route_a = fixture.mint_via(target.clone(), hub_a.clone());
    let route_b = fixture.mint_via(target.clone(), hub_b.clone());
    let route_c = fixture.mint_via(target.clone(), hub_c);
    let mut routes =
        NetworkReplyRoutes::try_from_route(route_a.clone()).expect("first source route");
    routes
        .merge(&NetworkReplyRoutes::try_from_route(route_a.clone()).expect("exact duplicate"))
        .expect("an exact duplicate must not consume another source slot");
    assert_eq!(routes.len(), 1);
    let later_a = fixture
        .redeliver(&route_a)
        .expect("same-tenure later delivery");
    routes
        .merge(&NetworkReplyRoutes::try_from_route(later_a.clone()).expect("later A"))
        .expect("later delivery updates only source A");
    assert_eq!(routes.len(), 1);
    assert!(routes.iter().any(|route| route.same_delivery(&later_a)));
    assert!(matches!(
        routes
            .merge(&NetworkReplyRoutes::try_from_route(route_a.clone()).expect("stale live route")),
        Err(NetworkReplyRouteError::Stale)
    ));
    assert!(fixture.retire(&route_a));
    let equal_ordinal_different_tenure = fixture
        .forge_equal_ordinal_different_tenure(&later_a, target.clone(), hub_a.clone())
        .expect("adversarial fixture reuses an opaque delivery ordinal");
    assert!(later_a.equal_ordinal_different_tenure(&equal_ordinal_different_tenure));
    assert!(matches!(
        NetworkReplyRoutes::try_from_route(equal_ordinal_different_tenure.clone()),
        Err(NetworkReplyRouteError::EqualOrdinalDifferentTenure)
    ));
    assert_eq!(routes.len(), 1);
    assert!(routes.iter().any(|route| route.same_delivery(&later_a)));
    let reconnected_a = fixture.mint_via(target.clone(), hub_a);
    routes
        .merge(
            &NetworkReplyRoutes::try_from_route(reconnected_a.clone())
                .expect("reconnected source A"),
        )
        .expect("a reconnect updates only its authenticated source");
    assert_eq!(routes.len(), 1);
    assert!(
        routes
            .iter()
            .any(|route| route.same_delivery(&reconnected_a))
    );
    routes
        .merge(&NetworkReplyRoutes::try_from_route(route_b.clone()).expect("source B"))
        .expect("alternate source starts an independent attempt");
    assert_eq!(routes.len(), 2);
    assert!(matches!(
        routes.merge(&NetworkReplyRoutes::try_from_route(route_c.clone()).expect("source C")),
        Err(NetworkReplyRouteError::Capacity)
    ));
    assert!(fixture.retire(&route_b));
    assert_eq!(
        routes.retain_active(),
        1,
        "owned maintenance prunes only the retired source tenure"
    );
    routes
        .merge(&NetworkReplyRoutes::try_from_route(route_c.clone()).expect("source C"))
        .expect("retired source capacity is released before adding C");
    assert_eq!(routes.len(), 2);
    assert!(
        routes
            .iter()
            .any(|route| route.same_delivery(&reconnected_a))
    );
    assert!(routes.iter().any(|route| route.same_delivery(&route_c)));
    let later_reconnected_a = fixture
        .redeliver(&reconnected_a)
        .expect("same-tenure source A redelivery");
    let foreign_hub = random_peer_id();
    let mut foreign_fixture = NetworkReplyRouteTestFixture::new(foreign_hub);
    let foreign = foreign_fixture.mint(target.clone());
    let mut invalid = NetworkReplyRoutes::try_from_route(later_reconnected_a.clone())
        .expect("valid member of adversarial candidate");
    assert!(
        invalid
            .attempts
            .insert(foreign.source_key(), foreign.clone())
            .is_none()
    );
    assert!(matches!(
        routes.merge(&invalid),
        Err(NetworkReplyRouteError::ForeignOwner)
    ));
    assert_eq!(routes.len(), 2);
    assert!(
        routes
            .iter()
            .any(|route| route.same_delivery(&reconnected_a))
    );
    assert!(routes.iter().any(|route| route.same_delivery(&route_c)));
    assert!(
        !routes
            .iter()
            .any(|route| route.same_delivery(&later_reconnected_a)),
        "an invalid multi-member merge must be atomic"
    );
    routes
        .merge(
            &NetworkReplyRoutes::try_from_route(later_reconnected_a.clone())
                .expect("later source A delivery"),
        )
        .expect("install later source A before observed-history merge");
    assert!(fixture.retire(&route_c));
    assert_eq!(routes.retain_active(), 1);
    let fresh_b = fixture.mint_via(target.clone(), hub_b);
    let mut mixed_observation = NetworkReplyRoutes::try_from_route(reconnected_a.clone())
        .expect("stale source A observation remains independently live");
    assert!(
        mixed_observation
            .attempts
            .insert(fresh_b.source_key(), fresh_b.clone())
            .is_none()
    );
    assert!(
        mixed_observation
            .retired_attempts
            .insert(route_a.source_key(), route_a.clone())
            .is_none()
    );
    routes
        .merge_observed(&mixed_observation)
        .expect("stale or inactive A history must not poison fresh sibling B");
    assert_eq!(routes.len(), 2);
    assert!(
        routes
            .iter()
            .any(|route| route.same_delivery(&later_reconnected_a))
    );
    assert!(routes.iter().any(|route| route.same_delivery(&fresh_b)));
    assert!(
        !routes
            .iter()
            .any(|route| route.same_delivery(&reconnected_a)),
        "observed merging must not roll source A back"
    );
    let capacity_route = fixture.mint_via(target.clone(), random_peer_id());
    assert!(matches!(
        routes.merge_observed(
            &NetworkReplyRoutes::try_from_route(capacity_route.clone())
                .expect("third observed source")
        ),
        Err(NetworkReplyRouteError::Capacity)
    ));
    assert!(
        !routes
            .iter()
            .any(|route| route.same_delivery(&capacity_route)),
        "observed capacity failure must be atomic"
    );
    let newer_a = fixture
        .redeliver(&later_reconnected_a)
        .expect("newer source A delivery");
    let mut foreign_observation = NetworkReplyRoutes::try_from_route(newer_a.clone())
        .expect("valid member before foreign observed member");
    assert!(
        foreign_observation
            .attempts
            .insert(foreign.source_key(), foreign)
            .is_none()
    );
    assert!(matches!(
        routes.merge_observed(&foreign_observation),
        Err(NetworkReplyRouteError::ForeignOwner)
    ));
    assert!(
        !routes.iter().any(|route| route.same_delivery(&newer_a)),
        "foreign observed member must reject every sibling atomically"
    );
    let collision = fixture
        .forge_equal_ordinal_different_tenure(
            &later_reconnected_a,
            target,
            reconnected_a.authenticated_via().clone(),
        )
        .expect("forge inactive collision for observed-history preflight");
    collision.tenure.cancel();
    let later_b = fixture
        .redeliver(&fresh_b)
        .expect("later source B delivery");
    let mut collision_observation = NetworkReplyRoutes::try_from_route(later_b.clone())
        .expect("valid member before inactive collision tombstone");
    assert!(
        collision_observation
            .retired_attempts
            .insert(collision.source_key(), collision)
            .is_none()
    );
    assert!(matches!(
        routes.merge_observed(&collision_observation),
        Err(NetworkReplyRouteError::EqualOrdinalDifferentTenure)
    ));
    assert!(
        !routes.iter().any(|route| route.same_delivery(&later_b)),
        "inactive collision history must reject every sibling atomically"
    );
    let retired_newer_b = fixture
        .redeliver(&fresh_b)
        .expect("newer source B observation later retires live B");
    let mut retirement_observation =
        NetworkReplyRoutes::try_from_route(later_reconnected_a.clone())
            .expect("source A keeps the observed set nonempty");
    assert!(
        retirement_observation
            .attempts
            .insert(capacity_route.source_key(), capacity_route.clone())
            .is_none()
    );
    assert!(
        retirement_observation
            .retired_attempts
            .insert(retired_newer_b.source_key(), retired_newer_b)
            .is_none()
    );
    let mut strict_reconciliation = routes.clone();
    strict_reconciliation
        .merge(&retirement_observation)
        .expect("strict history merge must release tombstone capacity first");
    assert!(
        strict_reconciliation
            .iter()
            .any(|route| route.same_delivery(&capacity_route))
    );
    assert!(
        !strict_reconciliation
            .iter()
            .any(|route| route.same_delivery(&fresh_b))
    );
    routes
        .merge_observed(&retirement_observation)
        .expect("tombstone capacity release must precede a fresh sibling");
    assert_eq!(routes.len(), 2);
    assert!(
        routes
            .iter()
            .any(|route| route.same_delivery(&later_reconnected_a))
    );
    assert!(
        !routes.iter().any(|route| route.same_delivery(&fresh_b)),
        "a later retired observation must prevent dispatch on stale live B"
    );
    assert!(
        routes
            .iter()
            .any(|route| route.same_delivery(&capacity_route)),
        "fresh sibling must consume capacity released by the tombstone"
    );
}
#[test]
fn route_cancelled_between_preflight_and_admission_retires_without_queue_ownership() {
    let (handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let delivery_peer = random_peer_id();
    let semantic_target = random_peer_id();
    let tenure = test_reply_tenure(&handle.reply_route_owner, delivery_peer, 35, 13);
    let route = NetworkReplyRoute::new(semantic_target.clone(), Arc::clone(&tenure), 13);
    assert!(
        route.is_active(),
        "preflight observes the live request tenure"
    );
    tenure.cancel();
    assert!(matches!(
        handle.post_reply_recoverable(
            Post {
                data: DeferredProgressMsg::Lane(7),
                peer_id: semantic_target,
                priority: Priority::High,
            },
            &route,
            None,
        ),
        Err(NetworkActorAdmissionError::Rejected {
            reason: NetworkActorAdmissionRejection::InactiveReplyRoute,
            ..
        })
    ));
    assert!(
        progress_rx.try_recv().is_err(),
        "the canceled occurrence must not consume actor queue or byte ownership"
    );
}
#[test]
fn reply_actor_admission_does_not_complete_writer_flush_ack() {
    let (handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let delivery_peer = random_peer_id();
    let semantic_target = random_peer_id();
    let tenure = test_reply_tenure(&handle.reply_route_owner, delivery_peer, 36, 14);
    let route = NetworkReplyRoute::new(semantic_target.clone(), tenure, 14);
    let mut completion = handle
        .post_reply_recoverable_with_flush_ack(
            Post {
                data: DeferredProgressMsg::Lane(8),
                peer_id: semantic_target,
                priority: Priority::High,
            },
            &route,
            None,
        )
        .expect("live reply route admits one actor item")
        .expect("new actor admission returns one completion");
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Pending);
    let admitted = progress_rx
        .try_recv()
        .expect("reply crossed actor admission");
    assert_eq!(
        completion.poll(),
        NetworkReplyFlushAckStatus::Pending,
        "actor admission is not peer-writer completion"
    );
    drop(admitted);
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Closed);
    assert_eq!(
        completion.poll(),
        NetworkReplyFlushAckStatus::Closed,
        "closed completion is terminal"
    );
}
#[test]
fn reply_timeout_attempt_is_retained_by_actor_admission_ticket() {
    let (handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let delivery_peer = random_peer_id();
    let semantic_target = random_peer_id();
    let tenure = test_reply_tenure(&handle.reply_route_owner, delivery_peer, 45, 25);
    let route = NetworkReplyRoute::new(semantic_target.clone(), tenure, 25);
    let post = |marker| Post {
        data: DeferredProgressMsg::Lane(marker),
        peer_id: semantic_target.clone(),
        priority: Priority::High,
    };
    let _first_completion = handle
        .post_reply_recoverable_with_flush_ack_at_attempt(post(90), &route, None, 0)
        .expect("first reply occupies the source lane")
        .expect("first reply owns one completion");
    let first_actor_item = progress_rx.try_recv().expect("first reply actor item");
    let (second, second_ticket) =
        match handle.post_reply_recoverable_with_flush_ack_at_attempt(post(91), &route, None, 2) {
            Err(NetworkActorAdmissionError::Backpressured {
                message,
                ticket: Some(ticket),
                rank: 1,
            }) => (message, ticket),
            other => panic!("second reply must retain its adaptive-attempt ticket: {other:?}"),
        };
    drop(first_actor_item);
    let second_completion = handle
        .post_reply_recoverable_with_flush_ack_at_attempt(second, &route, Some(second_ticket), 2)
        .expect("the unchanged adaptive attempt keeps its actor ticket")
        .expect("the retried reply owns one completion");
    assert_eq!(
        second_completion.identity().reply_writer_timeout_attempt(),
        2,
        "actor admission must retain the requested timeout generation in its completion identity"
    );
    let second_actor_item = progress_rx.try_recv().expect("second reply actor item");
    let (third, third_ticket) =
        match handle.post_reply_recoverable_with_flush_ack_at_attempt(post(92), &route, None, 4) {
            Err(NetworkActorAdmissionError::Backpressured {
                message,
                ticket: Some(ticket),
                rank: 1,
            }) => (message, ticket),
            other => panic!("third reply must retain its adaptive-attempt ticket: {other:?}"),
        };
    assert!(matches!(
        handle.post_reply_recoverable_with_flush_ack_at_attempt(
            third,
            &route,
            Some(third_ticket),
            5,
        ),
        Err(NetworkActorAdmissionError::Rejected {
            reason: NetworkActorAdmissionRejection::InvalidTicket,
            ..
        })
    ));
    drop(second_actor_item);
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[test]
fn reply_flush_identity_binds_ticket_tenure_source_payload_and_delivery_occurrence() {
    let (handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let authenticated_source_a = random_peer_id();
    let authenticated_source_b = random_peer_id();
    let semantic_target = random_peer_id();
    let tenure_a = test_reply_tenure(
        &handle.reply_route_owner,
        authenticated_source_a.clone(),
        51,
        31,
    );
    let first_route = NetworkReplyRoute::new(semantic_target.clone(), Arc::clone(&tenure_a), 70);
    let later_route = NetworkReplyRoute::new(semantic_target.clone(), Arc::clone(&tenure_a), 71);
    let reconnected_route = NetworkReplyRoute::new(
        semantic_target.clone(),
        test_reply_tenure(
            &handle.reply_route_owner,
            authenticated_source_a.clone(),
            52,
            32,
        ),
        72,
    );
    let other_source_route = NetworkReplyRoute::new(
        semantic_target.clone(),
        test_reply_tenure(
            &handle.reply_route_owner,
            authenticated_source_b.clone(),
            53,
            33,
        ),
        73,
    );
    let first = handle
        .post_reply_recoverable_with_flush_ack(
            Post {
                data: DeferredProgressMsg::Lane(80),
                peer_id: semantic_target.clone(),
                priority: Priority::Low,
            },
            &first_route,
            None,
        )
        .expect("first reply identity fixture must cross actor admission")
        .expect("first reply occurrence must mint one flush identity");
    let first_actor_item = progress_rx
        .try_recv()
        .expect("first identity fixture must retain the admitted actor item");
    let (later_post, later_ticket) = match handle.post_reply_recoverable_with_flush_ack(
        Post {
            data: DeferredProgressMsg::Lane(80),
            peer_id: semantic_target.clone(),
            priority: Priority::Low,
        },
        &first_route,
        None,
    ) {
        Err(NetworkActorAdmissionError::Backpressured {
            message,
            ticket: Some(ticket),
            rank: 1,
        }) => (message, ticket),
        other => panic!("same-source reply must retain its rank-one ticket: {other:?}"),
    };
    drop(first_actor_item);
    let later = handle
        .post_reply_recoverable_with_flush_ack(later_post, &later_route, Some(later_ticket))
        .expect("same-tenure later delivery must retain the exact admission ticket")
        .expect("later delivery must mint one distinct flush occurrence");
    drop(
        progress_rx
            .try_recv()
            .expect("later delivery must retain the admitted actor item"),
    );
    let mut admit = |route: &NetworkReplyRoute, marker: u8| {
        let completion = handle
            .post_reply_recoverable_with_flush_ack(
                Post {
                    data: DeferredProgressMsg::Lane(marker),
                    peer_id: semantic_target.clone(),
                    priority: Priority::Low,
                },
                route,
                None,
            )
            .expect("live reply identity fixture must cross actor admission")
            .expect("a fresh reply occurrence must mint one flush identity");
        drop(
            progress_rx
                .try_recv()
                .expect("identity fixture must retain the admitted actor item"),
        );
        completion
    };
    let reconnected = admit(&reconnected_route, 80);
    let other_source = admit(&other_source_route, 80);
    let other_payload = admit(
        &NetworkReplyRoute::new(semantic_target.clone(), Arc::clone(&tenure_a), 74),
        81,
    );
    let first_identity = first.identity();
    let later_identity = later.identity();
    assert_eq!(first_identity.semantic_target(), &semantic_target);
    assert_eq!(
        first_identity.authenticated_source_peer(),
        &authenticated_source_a
    );
    assert!(first_identity.is_authenticated_via(&authenticated_source_a));
    assert_eq!(first_identity.connection_tenure_ordinal(), 31);
    assert_eq!(first_identity.delivery_ordinal(), 70);
    assert_eq!(later_identity.delivery_ordinal(), 71);
    assert_eq!(first_identity.ticket_rank(), 1);
    assert_eq!(first_identity.ticket_topic(), message::Topic::Consensus);
    assert!(first_identity.ticket_stream_wire_bytes() > 0);
    assert!(first_identity.is_bound_to_tenure(&first_route));
    assert!(first_identity.is_bound_to_delivery(&first_route));
    assert!(first_identity.is_bound_to_tenure(&later_route));
    assert!(!first_identity.is_bound_to_delivery(&later_route));
    assert!(!first_identity.is_bound_to_tenure(&reconnected_route));
    assert!(!first_identity.is_bound_to_tenure(&other_source_route));
    assert!(first_identity.is_bound_to_canonical_reply(&Post {
        data: DeferredProgressMsg::Lane(80),
        peer_id: semantic_target.clone(),
        priority: Priority::Low,
    }));
    assert!(!first_identity.is_bound_to_canonical_reply(&Post {
        data: DeferredProgressMsg::Lane(81),
        peer_id: semantic_target.clone(),
        priority: Priority::Low,
    }));
    assert_eq!(first_identity.ticket_id(), later_identity.ticket_id());
    assert_eq!(
        first_identity.canonical_request_digest(),
        later_identity.canonical_request_digest()
    );
    assert!(first_identity.same_ticket_identity(later_identity));
    assert!(later_identity.same_ticket_identity(first_identity));
    assert!(!first_identity.same_delivery_occurrence(later_identity));
    assert_eq!(first_identity.source_key(), later_identity.source_key());
    assert_eq!(
        first_identity.source_key().process_local_identity_hash(),
        later_identity.source_key().process_local_identity_hash(),
        "later deliveries retain one opaque authenticated-source owner"
    );
    assert_ne!(
        first_identity.process_local_route_identity_hash(),
        later_identity.process_local_route_identity_hash(),
        "later deliveries must retain distinct exact-route identities"
    );
    assert_eq!(
        first_identity.source_key(),
        reconnected.identity().source_key(),
        "a reconnect keeps source fairness identity while changing ticket tenure"
    );
    assert_eq!(
        first_identity.source_key().process_local_identity_hash(),
        reconnected
            .identity()
            .source_key()
            .process_local_identity_hash(),
        "a reconnect preserves the process-local source projection"
    );
    assert_ne!(
        first_identity.process_local_route_identity_hash(),
        reconnected.identity().process_local_route_identity_hash(),
        "a reconnect replaces the exact admitted route projection"
    );
    assert!(!first_identity.same_ticket_identity(reconnected.identity()));
    assert!(!first_identity.same_ticket_identity(other_source.identity()));
    assert!(!first_identity.same_ticket_identity(other_payload.identity()));
    let mut foreign_budget_only = first_identity.clone();
    foreign_budget_only.ticket.budget = NetworkActorProgressBudget::new(1, 1, 1)
        .expect("foreign identity budget geometry must be valid");
    assert!(foreign_budget_only.is_bound_to_delivery(&first_route));
    assert_eq!(first_identity.ticket_id(), foreign_budget_only.ticket_id());
    assert_eq!(
        first_identity.canonical_request_digest(),
        foreign_budget_only.canonical_request_digest()
    );
    assert!(
        !first_identity.same_ticket_identity(&foreign_budget_only),
        "equal ticket facts under another opaque budget owner must not alias"
    );
    assert_ne!(
        first_identity.process_local_writer_occurrence_identity_hash(),
        foreign_budget_only.process_local_writer_occurrence_identity_hash(),
        "the writer occurrence must retain the opaque ticket-budget owner"
    );
    let (
        foreign_handle,
        _foreign_safety_rx,
        mut foreign_progress_rx,
        _foreign_high_rx,
        _foreign_low_rx,
    ) = handle_with_network_receivers::<DeferredProgressMsg>();
    let foreign_route = NetworkReplyRoute::new(
        semantic_target.clone(),
        test_reply_tenure(
            &foreign_handle.reply_route_owner,
            authenticated_source_a,
            51,
            31,
        ),
        70,
    );
    let foreign = foreign_handle
        .post_reply_recoverable_with_flush_ack(
            Post {
                data: DeferredProgressMsg::Lane(80),
                peer_id: semantic_target,
                priority: Priority::Low,
            },
            &foreign_route,
            None,
        )
        .expect("foreign actor admits its own exact reply")
        .expect("foreign actor mints its own flush identity");
    drop(
        foreign_progress_rx
            .try_recv()
            .expect("foreign actor retains its admitted reply"),
    );
    assert_eq!(first_identity.ticket_id(), foreign.identity().ticket_id());
    assert_eq!(
        first_identity.ticket_topic(),
        foreign.identity().ticket_topic()
    );
    assert_eq!(
        first_identity.ticket_stream_wire_bytes(),
        foreign.identity().ticket_stream_wire_bytes()
    );
    assert_eq!(
        first_identity.canonical_request_digest(),
        foreign.identity().canonical_request_digest()
    );
    assert!(!first_identity.same_ticket_identity(foreign.identity()));
    assert!(!first_identity.same_delivery_occurrence(foreign.identity()));
    assert_ne!(first_identity.source_key(), foreign.identity().source_key());
    assert_ne!(
        first_identity.source_key().process_local_identity_hash(),
        foreign
            .identity()
            .source_key()
            .process_local_identity_hash(),
        "the source projection must reject the same peer under another actor owner"
    );
    assert_ne!(
        first_identity.process_local_route_identity_hash(),
        foreign.identity().process_local_route_identity_hash(),
        "the exact route projection must reject another actor owner"
    );
    let cloned_first_identity = first_identity.clone();
    let rebuilt_first_identity =
        NetworkReplyFlushIdentity::from_admitted_ticket(first_identity.ticket.clone())
            .expect("the same admitted ticket can reproduce only its field projection");
    assert!(
        first_identity.same_delivery_occurrence(&rebuilt_first_identity),
        "ticket and delivery fields alone intentionally ignore completion-claim identity"
    );
    assert!(first_identity.same_writer_flush_occurrence(&cloned_first_identity));
    assert!(
        !first_identity.same_writer_flush_occurrence(&rebuilt_first_identity),
        "an independently allocated claim is not the actor's exact writer completion"
    );
    assert_eq!(
        first_identity.process_local_route_identity_hash(),
        rebuilt_first_identity.process_local_route_identity_hash(),
        "rebuilding from the same ticket preserves only the route projection"
    );
    assert_eq!(
        first_identity.process_local_writer_occurrence_identity_hash(),
        cloned_first_identity.process_local_writer_occurrence_identity_hash(),
        "exact clones share one writer-occurrence projection"
    );
    assert_ne!(
        first_identity.process_local_writer_occurrence_identity_hash(),
        rebuilt_first_identity.process_local_writer_occurrence_identity_hash(),
        "an independently rebuilt completion must not alias the actor's claim"
    );
    assert!(first_identity.claim_writer_flush_once());
    assert!(
        !cloned_first_identity.claim_writer_flush_once(),
        "a cloned exact completion cannot mint a second writer-flush claim"
    );
}
#[test]
fn reply_flush_ack_cancellation_between_precheck_and_budget_lock_returns_none() {
    let (handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let delivery_peer = random_peer_id();
    let semantic_target = random_peer_id();
    let tenure = test_reply_tenure(&handle.reply_route_owner, delivery_peer, 38, 16);
    let route = NetworkReplyRoute::new(semantic_target.clone(), Arc::clone(&tenure), 16);
    let completion = handle
        .post_reply_recoverable_with_flush_ack_inner(
            Post {
                data: DeferredProgressMsg::Lane(10),
                peer_id: semantic_target,
                priority: Priority::High,
            },
            &route,
            None,
            0,
            || tenure.cancel(),
        )
        .expect("a raced retirement preserves the existing no-op admission behavior");
    assert!(completion.is_none());
    assert!(!route.is_active());
    assert!(
        progress_rx.try_recv().is_err(),
        "cancelled occurrence transfers no actor item"
    );
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[test]
fn reply_wrapper_exposes_delivery_active_unwritable_no_ownership() {
    let (handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let delivery_peer = random_peer_id();
    let semantic_target = random_peer_id();
    let tenure = test_reply_tenure(&handle.reply_route_owner, delivery_peer, 39, 17);
    let route = NetworkReplyRoute::new(semantic_target.clone(), Arc::clone(&tenure), 17);
    tenure.mark_draining();
    assert_eq!(
        handle
            .post_reply_recoverable(
                Post {
                    data: DeferredProgressMsg::Lane(11),
                    peer_id: semantic_target,
                    priority: Priority::High,
                },
                &route,
                None,
            )
            .expect("draining reply writer is an explicit no-ownership outcome"),
        NetworkReplyAdmissionOutcome::ReplyWriterUnavailable,
    );
    assert!(route.is_active());
    assert!(!route.is_reply_writable());
    assert!(progress_rx.try_recv().is_err());
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[test]
fn retired_reply_tenure_closes_flush_ack_without_false_completion() {
    let (handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let delivery_peer = random_peer_id();
    let semantic_target = random_peer_id();
    let tenure = test_reply_tenure(&handle.reply_route_owner, delivery_peer, 37, 15);
    let route = NetworkReplyRoute::new(semantic_target.clone(), Arc::clone(&tenure), 15);
    let mut completion = handle
        .post_reply_recoverable_with_flush_ack(
            Post {
                data: DeferredProgressMsg::Lane(9),
                peer_id: semantic_target,
                priority: Priority::High,
            },
            &route,
            None,
        )
        .expect("live reply route admits one actor item")
        .expect("new actor admission returns one completion");
    let admitted = progress_rx.try_recv().expect("reply actor item");
    let mut pending = ReliableActorPending::new(1);
    pending.push_back(admitted);
    tenure.cancel();
    assert_eq!(pending.release_cancelled_targets(), 1);
    assert_eq!(pending.len(), 0);
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Closed);
    assert_ne!(completion.poll(), NetworkReplyFlushAckStatus::Flushed);
}
#[test]
fn reply_flush_test_fixture_distinguishes_success_timeout_and_close() {
    let (mut flushed_control, mut flushed) = NetworkReplyFlushAckTestFixture::new();
    let flushed_identity = flushed.identity().clone();
    assert_eq!(flushed.poll(), NetworkReplyFlushAckStatus::Pending);
    assert!(flushed_control.flush());
    assert!(!flushed_control.flush());
    assert_eq!(flushed.poll(), NetworkReplyFlushAckStatus::Flushed);
    assert_eq!(flushed.poll(), NetworkReplyFlushAckStatus::Flushed);
    assert!(
        flushed_identity.same_delivery_occurrence(flushed.identity()),
        "terminal polling must not mutate the immutable completion identity"
    );
    let (mut closed_control, mut closed) = NetworkReplyFlushAckTestFixture::new();
    let closed_identity = closed.identity().clone();
    assert_eq!(closed.poll(), NetworkReplyFlushAckStatus::Pending);
    assert!(closed_control.close());
    assert!(!closed_control.close());
    assert_eq!(closed.poll(), NetworkReplyFlushAckStatus::Closed);
    assert_eq!(closed.poll(), NetworkReplyFlushAckStatus::Closed);
    assert!(closed_identity.same_delivery_occurrence(closed.identity()));
    let (mut timeout_control, mut timed_out) = NetworkReplyFlushAckTestFixture::new();
    let timeout_identity = timed_out.identity().clone();
    assert_eq!(timed_out.poll(), NetworkReplyFlushAckStatus::Pending);
    assert!(timeout_control.timeout());
    assert!(!timeout_control.timeout());
    assert_eq!(timed_out.poll(), NetworkReplyFlushAckStatus::TimedOut);
    assert_eq!(timed_out.poll(), NetworkReplyFlushAckStatus::TimedOut);
    assert!(timeout_identity.same_delivery_occurrence(timed_out.identity()));
}
#[test]
fn reply_flush_test_fixture_binds_exact_canonical_post_and_opaque_actor() {
    let authenticated_source = random_peer_id();
    let semantic_target = random_peer_id();
    let mut routes = NetworkReplyRouteTestFixture::new(authenticated_source.clone());
    let route = routes.mint(semantic_target.clone());
    let post = Post {
        data: DeferredProgressMsg::Lane(91),
        peer_id: semantic_target,
        priority: Priority::Low,
    };
    let (mut first_control, first) = NetworkReplyFlushAckTestFixture::for_reply(&post, &route);
    let (mut second_control, second) = NetworkReplyFlushAckTestFixture::for_reply(&post, &route);
    assert!(first.identity().is_bound_to_canonical_reply(&post));
    assert!(first.identity().is_bound_to_delivery(&route));
    assert!(first.identity().is_authenticated_via(&authenticated_source));
    assert!(first.identity().ticket_rank() >= 1);
    assert_eq!(first.identity().reply_writer_timeout_attempt(), 0);
    assert_eq!(
        first.identity().ticket_stream_wire_bytes(),
        ncore::encoded_payload_len(&post.data)
            .expect("test reply payload must have a canonical Norito encoding")
            .max(1)
    );
    assert!(
        !first.identity().same_ticket_identity(second.identity()),
        "separate synthetic actors cannot alias an opaque ticket"
    );
    assert!(first_control.flush());
    assert!(second_control.close());
}
#[test]
fn reply_flush_identity_requires_and_exposes_timeout_attempt() {
    let authenticated_source = random_peer_id();
    let semantic_target = random_peer_id();
    let mut routes = NetworkReplyRouteTestFixture::new(authenticated_source);
    let route = routes.mint(semantic_target.clone());
    let post = Post {
        data: DeferredProgressMsg::Lane(92),
        peer_id: semantic_target,
        priority: Priority::High,
    };
    let (_control, completion) =
        NetworkReplyFlushAckTestFixture::for_reply_at_attempt(&post, &route, 7);
    assert_eq!(completion.identity().reply_writer_timeout_attempt(), 7);
    let mut missing_attempt_ticket = completion.identity().ticket.clone();
    missing_attempt_ticket.shape.reply_writer_timeout_attempt = None;
    assert!(
        NetworkReplyFlushIdentity::from_admitted_ticket(missing_attempt_ticket).is_none(),
        "reply flush identity construction must reject a missing timeout generation"
    );
    let mut broadcast_ticket = completion.identity().ticket.clone();
    broadcast_ticket.shape.broadcast = true;
    assert!(
        NetworkReplyFlushIdentity::from_admitted_ticket(broadcast_ticket).is_none(),
        "reply flush identity construction must reject a broadcast-shaped ticket"
    );
    let mut wrong_authority_ticket = completion.identity().ticket.clone();
    wrong_authority_ticket.shape.authority = Some(ProgressAuthorityIdentity::Reply(
        completion
            .identity()
            .connection_tenure_ordinal()
            .wrapping_add(1),
    ));
    assert!(
        NetworkReplyFlushIdentity::from_admitted_ticket(wrong_authority_ticket).is_none(),
        "reply flush identity construction must reject the wrong shape authority"
    );
    let mut wrong_source_ticket = completion.identity().ticket.clone();
    wrong_source_ticket.source.target = Some(random_peer_id());
    assert!(
        NetworkReplyFlushIdentity::from_admitted_ticket(wrong_source_ticket).is_none(),
        "reply flush identity construction must reject the wrong authenticated source"
    );
}
#[test]
fn reply_admission_rejects_retargeting_foreign_handles_and_wrong_tickets() {
    let (handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let (
        foreign_handle,
        _foreign_safety_rx,
        _foreign_progress_rx,
        _foreign_high_rx,
        _foreign_low_rx,
    ) = handle_with_network_receivers::<DeferredProgressMsg>();
    let delivery_peer = random_peer_id();
    let origin_a = random_peer_id();
    let origin_b = random_peer_id();
    let tenure = test_reply_tenure(&handle.reply_route_owner, delivery_peer.clone(), 40, 20);
    let route_a = NetworkReplyRoute::new(origin_a.clone(), Arc::clone(&tenure), 20);
    let route_b = NetworkReplyRoute::new(origin_b.clone(), tenure, 21);
    let equal_ordinal_different_tenure_b = NetworkReplyRoute::new(
        origin_b.clone(),
        test_reply_tenure(&handle.reply_route_owner, delivery_peer.clone(), 42, 20),
        22,
    );
    let reconnected_b = NetworkReplyRoute::new(
        origin_b.clone(),
        test_reply_tenure(&handle.reply_route_owner, delivery_peer, 41, 21),
        23,
    );
    let post = |peer_id, marker| Post {
        data: DeferredProgressMsg::Lane(marker),
        peer_id,
        priority: Priority::High,
    };
    assert!(matches!(
        handle.post_reply_recoverable(post(origin_b.clone(), 0), &route_a, None),
        Err(NetworkActorAdmissionError::Rejected {
            reason: NetworkActorAdmissionRejection::InvalidTicket,
            ..
        })
    ));
    assert!(matches!(
        foreign_handle.post_reply_recoverable(post(origin_a.clone(), 1), &route_a, None),
        Err(NetworkActorAdmissionError::Rejected {
            reason: NetworkActorAdmissionRejection::InvalidTicket,
            ..
        })
    ));
    handle
        .post_reply_recoverable(post(origin_a, 2), &route_a, None)
        .expect("first relayed origin owns the authenticated source lane");
    let ticket = match handle.post_reply_recoverable(post(origin_b.clone(), 3), &route_b, None) {
        Err(NetworkActorAdmissionError::Backpressured {
            ticket: Some(ticket),
            rank: 1,
            ..
        }) => ticket,
        other => panic!("second origin behind one hub must wait at rank one: {other:?}"),
    };
    assert_eq!(route_a.source_key(), route_b.source_key());
    assert!(matches!(
        handle.post_reply_recoverable(
            post(origin_b.clone(), 3),
            &equal_ordinal_different_tenure_b,
            Some(ticket),
        ),
        Err(NetworkActorAdmissionError::Rejected {
            reason: NetworkActorAdmissionRejection::InvalidTicket,
            ..
        })
    ));
    let reconnect_ticket =
        match handle.post_reply_recoverable(post(origin_b.clone(), 3), &route_b, None) {
            Err(NetworkActorAdmissionError::Backpressured {
                ticket: Some(ticket),
                rank: 1,
                ..
            }) => ticket,
            other => panic!("same source must regain rank one after collision: {other:?}"),
        };
    assert!(matches!(
        handle.post_reply_recoverable(
            post(origin_b.clone(), 3),
            &reconnected_b,
            Some(reconnect_ticket),
        ),
        Err(NetworkActorAdmissionError::Rejected {
            reason: NetworkActorAdmissionRejection::InvalidTicket,
            ..
        })
    ));
    let request_ticket =
        match handle.post_reply_recoverable(post(origin_b.clone(), 4), &route_b, None) {
            Err(NetworkActorAdmissionError::Backpressured {
                ticket: Some(ticket),
                rank: 1,
                ..
            }) => ticket,
            other => panic!("same source remains fairly queued: {other:?}"),
        };
    assert!(matches!(
        handle.post_reply_recoverable(post(origin_b, 5), &route_b, Some(request_ticket)),
        Err(NetworkActorAdmissionError::Rejected {
            reason: NetworkActorAdmissionRejection::InvalidTicket,
            ..
        })
    ));
    drop(
        progress_rx
            .try_recv()
            .expect("first reply remains actor-owned"),
    );
}
#[test]
fn subscribe_with_filter_returns_error_when_closed() {
    let handle = NetworkBaseHandle::<DummyMsg, ChaCha20Poly1305>::closed_for_tests();
    let (tx, _rx) = mpsc::channel(1);
    assert!(
        handle
            .subscribe_to_peers_messages_with_filter(tx, SubscriberFilter::All)
            .is_err()
    );
}
fn default_accept_params() -> AcceptThrottleParams {
    AcceptThrottleParams::new(
        AcceptRate {
            rate_per_sec: None,
            burst: None,
        },
        iroha_config::parameters::defaults::network::ACCEPT_PREFIX_V4_BITS,
        iroha_config::parameters::defaults::network::ACCEPT_PREFIX_V6_BITS,
        AcceptRate {
            rate_per_sec: None,
            burst: None,
        },
        iroha_config::parameters::defaults::network::MAX_ACCEPT_BUCKETS.get(),
        iroha_config::parameters::defaults::network::ACCEPT_BUCKET_IDLE,
    )
}
fn accept_params_with(
    max_buckets: usize,
    bucket_idle: Duration,
    prefix_rate: Option<f64>,
    ip_rate: Option<f64>,
) -> AcceptThrottleParams {
    AcceptThrottleParams::new(
        AcceptRate {
            rate_per_sec: prefix_rate,
            burst: None,
        },
        iroha_config::parameters::defaults::network::ACCEPT_PREFIX_V4_BITS,
        iroha_config::parameters::defaults::network::ACCEPT_PREFIX_V6_BITS,
        AcceptRate {
            rate_per_sec: ip_rate,
            burst: None,
        },
        max_buckets,
        bucket_idle,
    )
}
fn enter_test_runtime() -> Option<tokio::runtime::EnterGuard<'static>> {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    if tokio::runtime::Handle::try_current().is_ok() {
        return None;
    }
    let rt = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("test runtime should build")
    });
    Some(rt.enter())
}
async fn trust_gossip_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    // Receive tests retain this counter lease while awaiting message handling.
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}
fn queue_depth_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("queue depth test lock poisoned")
}
fn deferred_send_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("deferred send test lock poisoned")
}
fn dummy_relay_frame(origin: PeerId, target: &PeerId) -> WireMessage<DummyMsg> {
    relay_frame(origin, target, DummyMsg)
}
fn relay_frame<T: Pload>(origin: PeerId, target: &PeerId, payload: T) -> WireMessage<T> {
    RelayMessage::new(
        origin,
        RelayTarget::Direct(target.clone()),
        DEFAULT_RELAY_TTL,
        payload,
    )
}
fn insert_ref_peer<T: Pload>(
    network: &mut NetworkBase<T, ChaCha20Poly1305>,
    peer_id: PeerId,
    peer_addr: SocketAddr,
    conn_id: ConnectionId,
    handle: PeerHandle<WireMessage<T>>,
    trust_gossip: bool,
) {
    network.peers.insert(
        peer_id,
        RefPeer {
            handle,
            conn_id,
            p2p_addr: peer_addr,
            relay_role: RelayRole::Disabled,
            trust_gossip,
        },
    );
}
fn insert_dummy_ref_peer(
    network: &mut NetworkBase<DummyMsg, ChaCha20Poly1305>,
    peer_id: PeerId,
    peer_addr: SocketAddr,
    conn_id: ConnectionId,
    handle: PeerHandle<WireMessage<DummyMsg>>,
) {
    insert_ref_peer(network, peer_id, peer_addr, conn_id, handle, true);
}
fn test_reply_tenure(
    owner: &Arc<()>,
    delivery_peer: PeerId,
    connection_id: ConnectionId,
    connection_ordinal: u128,
) -> Arc<ReliableReplyRouteTenure> {
    Arc::new(ReliableReplyRouteTenure {
        owner: Arc::clone(owner),
        _source_credits: crate::peer::message::AuthenticatedSourceCredits::new(1),
        delivery_peer,
        connection_id,
        connection_ordinal,
        source_capacity: 8,
        delivery_active: AtomicBool::new(true),
        reply_writable: AtomicBool::new(true),
        delivery_drain: InboundDeliveryDrain::completed_for_test(),
        termination_seen: AtomicBool::new(false),
    })
}
fn install_test_reply_route(
    network: &mut NetworkBase<DeferredProgressMsg, ChaCha20Poly1305>,
    peer_addr: SocketAddr,
    connection_id: ConnectionId,
    connection_ordinal: u128,
    delivery_ordinal: u128,
    assert_vacant: bool,
) -> (
    PeerId,
    PeerId,
    crate::peer::handles::TestPeerHandleReceivers<WireMessage<DeferredProgressMsg>>,
    Arc<ReliableReplyRouteTenure>,
    NetworkReplyRoute,
) {
    let delivery_peer = random_peer_id();
    let semantic_target = random_peer_id();
    let_deferred_peer!(peer_receivers = network; delivery_peer.clone(), peer_addr, connection_id);
    let tenure = test_reply_tenure(
        &network.reply_route_owner,
        delivery_peer.clone(),
        connection_id,
        connection_ordinal,
    );
    if assert_vacant {
        assert!(
            network
                .reply_route_tenures
                .insert(connection_id, Arc::clone(&tenure))
                .is_none()
        );
    } else {
        network
            .reply_route_tenures
            .insert(connection_id, Arc::clone(&tenure));
    }
    let route = NetworkReplyRoute::new(
        semantic_target.clone(),
        Arc::clone(&tenure),
        delivery_ordinal,
    );
    (
        delivery_peer,
        semantic_target,
        peer_receivers,
        tenure,
        route,
    )
}
fn replace_test_authenticated_source_geometry(
    network: &mut NetworkBase<DummyMsg, ChaCha20Poly1305>,
    max_sources: usize,
    protected_sources: Option<HashSet<PeerId>>,
) {
    let geometry = crate::peer::AuthenticatedSourceGeometry::new(max_sources);
    network.inbound_frame_byte_budgets =
        crate::peer::InboundFrameByteBudgets::new_with_source_geometry(4, 4, 4, geometry.clone())
            .expect("test inbound source geometry");
    network.outbound_post_byte_budgets =
        crate::peer::OutboundPostByteBudgets::new_with_source_geometry(4, 4, 4, geometry)
            .expect("test outbound source geometry");
    network.max_total_connections = Some(max_sources);
    if let Some(protected_sources) = protected_sources {
        assert!(
            network
                .inbound_frame_byte_budgets
                .install_protected_sources(protected_sources)
        );
    }
}
fn reserve_test_incoming<T: Pload>(
    network: &mut NetworkBase<T, ChaCha20Poly1305>,
    conn_id: ConnectionId,
) {
    assert!(network.reserve_incoming_pending(conn_id));
}
#[allow(clippy::too_many_lines)]
fn bare_network() -> Option<NetworkBase<DummyMsg, ChaCha20Poly1305>> {
    bare_network_with::<DummyMsg>()
}
#[tokio::test]
async fn handshake_actor_ack_preserves_policy_on_rejection() {
    let Some(mut network) = bare_network() else {
        return;
    };
    let initial = network
        .soranet_handshake
        .snapshot()
        .expect("initial handshake policy");
    let replay_state_path = network
        .soranet_handshake
        .replay_state_path_for_tests()
        .to_string_lossy()
        .into_owned();
    let compatible_config = || {
        let mut handshake = test_soranet_handshake_config();
        handshake.pow.revocation_store_path = replay_state_path.clone().into();
        handshake
    };
    let initial_capacity = initial.puzzle_work_capacities().0;
    let changed_capacity = if initial_capacity.get() == 1 { 2 } else { 1 };
    let mut rejected = compatible_config();
    rejected.pow.outbound_mint_capacity =
        std::num::NonZeroUsize::new(changed_capacity).expect("non-zero capacity");
    let (rejected_response, rejected_result) = oneshot::channel();
    network.handle_soranet_handshake_update(message::UpdateHandshake {
        handshake: rejected,
        respond_to: rejected_response,
    });
    let error = rejected_result
        .await
        .expect("rejection acknowledgment")
        .expect_err("owner-changing update must be rejected");
    assert!(matches!(
        error,
        Error::HandshakeSoranet(message) if message.contains("restart required")
    ));
    assert!(Arc::ptr_eq(
        &initial,
        &network
            .soranet_handshake
            .snapshot()
            .expect("policy after rejection")
    ));

    let mut accepted = compatible_config();
    accepted.pow.difficulty = 6;
    let (accepted_response, accepted_result) = oneshot::channel();
    network.handle_soranet_handshake_update(message::UpdateHandshake {
        handshake: accepted,
        respond_to: accepted_response,
    });
    accepted_result
        .await
        .expect("acceptance acknowledgment")
        .expect("compatible update must be accepted");
    let active = network
        .soranet_handshake
        .snapshot()
        .expect("policy after acceptance");
    assert_eq!(active.puzzle_parameters().difficulty(), 6);
    assert!(!Arc::ptr_eq(&initial, &active));
}
fn bare_network_with<T: Pload + message::ClassifyTopic>() -> Option<NetworkBase<T, ChaCha20Poly1305>>
{
    let _guard = enter_test_runtime();
    let key_pair = KeyPair::try_from_seed(vec![0x42; 32], Algorithm::BlsNormal)
        .expect("test BLS-normal node key");
    network_fixture_with_listener(key_pair).map(|(network, _listener)| network)
}
pub(super) fn network_fixture_with_listener<T: Pload + message::ClassifyTopic>(
    key_pair: KeyPair,
) -> Option<(NetworkBase<T, ChaCha20Poly1305>, std::net::TcpListener)> {
    let std_listener = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(e) => panic!("listener bind failed: {e:?}"),
    };
    let listen_addr_std = std_listener.local_addr().unwrap();
    let (_subscribe_tx, subscribe_rx) = mpsc::channel::<Subscriber<T>>(1);
    let (_update_topology_tx, update_topology_rx) = control_update_channel();
    let (_update_peers_tx, update_peers_rx) = control_update_channel();
    let (_update_validator_dial_roster_tx, update_validator_dial_roster_receiver) =
        control_update_channel();
    let (_update_trusted_tx, update_trusted_peers_receiver) = control_update_channel();
    let (_update_acl_tx, update_acl_rx) = control_update_channel();
    let (_update_handshake_tx, update_handshake_rx) =
        mpsc::channel(HANDSHAKE_UPDATE_CHANNEL_CAPACITY);
    let (peer_message_hi_tx, peer_message_hi_rx) = mpsc::channel::<PeerMessage<WireMessage<T>>>(1);
    let (peer_message_safety_sender, peer_message_safety_receiver) =
        mpsc::channel::<PeerMessage<WireMessage<T>>>(1);
    let (peer_message_payload_sender, peer_message_payload_receiver) =
        mpsc::channel::<PeerMessage<WireMessage<T>>>(1);
    let (peer_message_block_sync_sender, peer_message_block_sync_receiver) =
        mpsc::channel::<PeerMessage<WireMessage<T>>>(1);
    let (peer_message_control_sender, peer_message_control_receiver) =
        mpsc::channel::<PeerMessage<WireMessage<T>>>(1);
    let (peer_message_lo_tx, peer_message_lo_rx) = mpsc::channel::<PeerMessage<WireMessage<T>>>(1);
    let (service_message_tx, service_message_rx) =
        mpsc::channel::<ServiceMessage<WireMessage<T>>>(4);
    let (_network_hi_tx, network_message_high_rx) = net_channel::channel_with_capacity(1);
    let (_network_lo_tx, network_message_low_rx) = net_channel::channel_with_capacity(1);
    let (reliable_flush_notice_sender, reliable_flush_notice_receiver) = mpsc::unbounded_channel();
    let (online_peers_tx, _online_peers_rx) = watch::channel(HashSet::new());
    let (online_peer_capabilities_tx, _online_peer_capabilities_rx) =
        watch::channel(HashMap::new());
    let (_update_peer_capabilities_tx, update_peer_capabilities_receiver) =
        control_update_channel();
    let soranet = test_soranet_handshake_runtime();
    // This bare actor fixture does not instantiate a native application
    // transport. Its explicit finite geometry remains shared by all owners.
    let inbound_frames = crate::peer::InboundFrameByteBudgets::default();
    assert!(inbound_frames.install_protected_sources(HashSet::new()));
    let inbound_dispatch = crate::peer::InboundDispatchByteBudgets::default();
    let receive_credit_pool = crate::peer::receive_credit::Pool::new(
        inbound_frames.clone(),
        inbound_dispatch.clone(),
        6,
        [1024; message::TransportAdmissionClass::COUNT],
    )
    .expect("explicit synthetic actor geometry");
    let network_id = test_network_id("test-chain");
    let self_id = PeerId::from(key_pair.public_key().clone());
    let key_pair = Arc::new(key_pair);
    Some((
        NetworkBase {
            listen_addr: listen_addr_std.into(),
            listener_tasks: Vec::new(),
            peer_tasks: Vec::new(),
            public_address: listen_addr_std.into(),
            relay_role: RelayRole::Disabled,
            relay_mode: iroha_config::parameters::actual::RelayMode::Disabled,
            relay_hub_addresses: Vec::new(),
            relay_hub_peer: None,
            relay_hub_candidates: HashSet::new(),
            relay_trusted_peers: HashSet::new(),
            relay_ttl: DEFAULT_RELAY_TTL,
            trust_gossip_config: true,
            trust_gossip: true,
            self_id,
            address_book: HashMap::new(),
            peer_reputations: PeerReputationBook::default(),
            soranet_handshake: soranet,
            peers: HashMap::new(),
            reader_arbitration: connection_arbitration::Arbitration::default(),
            connecting_peers: HashMap::new(),
            outbound_connections: HashSet::new(),
            key_pair,
            subscribers_to_peers_messages: Vec::new(),
            unrouted_reliable_deliveries: VecDeque::new(),
            subscribe_to_peers_messages_receiver: subscribe_rx,
            online_peers_sender: online_peers_tx,
            online_peer_capabilities_sender: online_peer_capabilities_tx,
            reliable_broadcast_topology: Arc::new(Mutex::new(ReliableProgressTopology::empty())),
            reliable_direct_topology: Arc::new(Mutex::new(ReliableProgressTopology::empty())),
            configured_peer_ids: Arc::new(Mutex::new(ConfiguredPeerState::default())),
            reply_route_owner: Arc::new(()),
            reply_route_tenures: HashMap::new(),
            next_reply_connection_ordinal: 0,
            next_reply_delivery_ordinal: 0,
            pending_reply_source_authority: PendingReplySourceAuthority::default(),
            pending_configured_hub_source: None,
            network_actor_progress_budget: test_network_actor_progress_budget(),
            reliable_flush_notice_sender,
            reliable_flush_notice_receiver,
            reliable_topology_dirty: true,
            update_topology_receiver: update_topology_rx,
            update_peers_receiver: update_peers_rx,
            update_validator_dial_roster_receiver,
            update_peer_capabilities_receiver,
            update_trusted_peers_receiver,
            update_acl_receiver: update_acl_rx,
            update_handshake_receiver: update_handshake_rx,
            network_message_high_receiver: network_message_high_rx,
            network_message_safety_receiver: super::net_channel::channel_with_capacity(1).1,
            network_message_progress_receiver: super::net_channel::channel_with_capacity(1).1,
            network_message_low_receiver: network_message_low_rx,
            peer_message_high_receiver: peer_message_hi_rx,
            peer_message_payload_sender,
            peer_message_payload_receiver,
            peer_message_block_sync_sender,
            peer_message_block_sync_receiver,
            peer_message_control_sender,
            peer_message_control_receiver,

            peer_message_safety_receiver,
            peer_message_low_receiver: peer_message_lo_rx,
            peer_message_high_sender: peer_message_hi_tx,
            peer_message_safety_sender,
            peer_message_low_sender: peer_message_lo_tx,
            service_message_receiver: service_message_rx,
            service_message_sender: service_message_tx,
            current_conn_id: 0,
            requested_topology: HashSet::new(),
            current_topology: HashSet::new(),
            validator_dial_scheduler: ValidatorDialScheduler::new(
                HashSet::new(),
                Duration::from_millis(50),
            ),
            current_peers_addresses: Vec::new(),
            network_id,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            peer_capabilities: HashMap::new(),
            post_queue_cap: 4,
            outbound_frame_queue_limits: OutboundFrameQueueLimits::default(),
            outbound_post_byte_budgets: OutboundPostByteBudgets::default(),
            inbound_frame_byte_budgets: inbound_frames,
            _receive_credit_pool: receive_credit_pool,
            _semantic_post_pool: None,
            inbound_dispatch_byte_budgets: inbound_dispatch,
            authenticated_source_credit_capacity: 5,
            dns_refresh_interval: None,
            dns_refresh_ttl: None,
            dns_last_refresh: HashMap::new(),
            topology_update_interval:
                iroha_config::parameters::defaults::network::PEER_GOSSIP_PERIOD,
            dns_pending_refresh: HashSet::new(),
            idle_timeout: Duration::from_millis(50),
            reply_writer_flush_timeout:
                iroha_config::parameters::defaults::network::REPLY_WRITER_FLUSH_TIMEOUT,
            dial_timeout: iroha_config::parameters::defaults::network::DIAL_TIMEOUT,
            outbound_authentication_timeout: Duration::from_millis(50),
            tcp_nodelay: true,
            tcp_keepalive: None,
            connect_startup_delay_until: tokio::time::Instant::now(),
            quic_enabled: false,
            quic_datagrams_enabled: false,
            quic_datagram_max_payload_bytes: 0,
            quic_dialer: None,
            local_scion_supported: false,
            proxy_policy: crate::transport::ProxyPolicy::disabled(),
            outbound_dial_policy: Arc::new(crate::dial_policy::OutboundDialPolicy::default()),
            proxy_tls_verify: true,
            proxy_tls_pinned_cert_der: None,
            allowlist_only: false,
            allow_keys: HashSet::new(),
            deny_keys: HashSet::new(),
            allow_nets: Vec::new(),
            deny_nets: Vec::new(),
            retry_backoff: HashMap::new(),
            pending_connects: Vec::new(),
            deferred_send_queue: DeferredPeerFrameQueue::new(
                iroha_config::parameters::defaults::network::DEFERRED_SEND_MAX_PER_PEER,
                iroha_config::parameters::defaults::network::DEFERRED_SEND_MAX_BYTES_PER_PEER,
                Duration::from_millis(
                    iroha_config::parameters::defaults::network::DEFERRED_SEND_TTL_MS,
                ),
            ),
            happy_eyeballs_stagger: Duration::from_millis(10),
            addr_ipv6_first: false,
            last_active: HashMap::new(),
            incoming_pending: HashSet::new(),
            incoming_active: HashSet::new(),
            terminating_connections: HashSet::new(),
            protocol_rejected_connections: HashSet::new(),
            max_incoming: None,
            max_total_connections: None,
            accept_params: AcceptThrottleParams::new(
                AcceptRate {
                    rate_per_sec: None,
                    burst: None,
                },
                iroha_config::parameters::defaults::network::ACCEPT_PREFIX_V4_BITS,
                iroha_config::parameters::defaults::network::ACCEPT_PREFIX_V6_BITS,
                AcceptRate {
                    rate_per_sec: None,
                    burst: None,
                },
                iroha_config::parameters::defaults::network::MAX_ACCEPT_BUCKETS.get(),
                iroha_config::parameters::defaults::network::ACCEPT_BUCKET_IDLE,
            ),
            accept_prefix_buckets: HashMap::new(),
            accept_ip_buckets: HashMap::new(),
            sampler_high_queue_warn: LogSampler::new(),
            sampler_low_queue_warn: LogSampler::new(),
            low_rate_per_sec: None,
            low_burst: None,
            low_buckets: HashMap::new(),
            low_bytes_per_sec: None,
            low_bytes_burst: 1.0,
            low_bytes_buckets: HashMap::new(),
            max_frame_bytes: 1024,
            cap_consensus: 1024,
            cap_control: 1024,
            cap_block_sync: 1024,
            cap_tx_gossip: 1024,
            cap_peer_gossip: 1024,
            cap_health: 1024,
            cap_connect: 1024,
            cap_other: 1024,
            disconnect_on_post_overflow: false,
            _encryptor: core::marker::PhantomData,
        },
        std_listener,
    ))
}
#[tokio::test(flavor = "current_thread")]
async fn safety_flood_cannot_starve_service_work_or_shutdown() {
    let_test_network!(network, SafetyMsg);
    let (subscriber_tx, subscriber_rx) = mpsc::channel(1);
    network.subscribe_to_peers_messages_receiver = subscriber_rx;
    let (high_tx, high_rx) = net_channel::channel_with_capacity(1);
    network.network_message_high_receiver = high_rx;
    let (low_tx, low_rx) = net_channel::channel_with_capacity(1);
    network.network_message_low_receiver = low_rx;
    let (safety_tx, safety_rx) = net_channel::channel_with_capacity(128);
    network.network_message_safety_receiver = safety_rx;
    let service_tx = network.service_message_sender.clone();
    // This white-box stress bypasses source admission to keep the safety
    // receiver continuously ready. Use a direct target because reliable
    // broadcasts may enter the actor only after targetized admission has
    // attached its exact topology-membership source.
    let flood_target = random_peer_id();
    for _ in 0..128 {
        safety_tx
            .try_send(admitted_test_network_message(NetworkMessage::Post(Post {
                data: SafetyMsg(0),
                peer_id: flood_target.clone(),
                priority: Priority::High,
            })))
            .expect("safety flood prefill should fit");
    }
    let shutdown = ShutdownSignal::new();
    let actor = tokio::spawn(network.run(shutdown.clone()));
    let flood_tx = safety_tx.clone();
    let flood_target = flood_target.clone();
    let flood = tokio::spawn(async move {
        loop {
            if flood_tx
                .send(admitted_test_network_message(NetworkMessage::Post(Post {
                    data: SafetyMsg(0),
                    peer_id: flood_target.clone(),
                    priority: Priority::High,
                })))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    service_tx
        .send(ServiceMessage::InboundAsk {
            conn_id: 900,
            remote_addr: "127.0.0.1:39000".parse().expect("valid loopback address"),
            reply: reply_tx,
        })
        .await
        .expect("service work should enter its bounded queue");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), reply_rx)
            .await
            .expect("safety flood must not starve service work")
            .expect("network actor must answer inbound admission"),
        "loopback admission should be allowed by the default test policy"
    );
    shutdown.send();
    tokio::time::timeout(Duration::from_secs(1), actor)
        .await
        .expect("safety flood must not starve shutdown")
        .expect("network actor must exit cleanly");
    flood
        .await
        .expect("flood task must exit after actor shutdown");
    drop((subscriber_tx, high_tx, low_tx, safety_tx));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn continuously_ready_topology_updates_do_not_starve_shutdown() {
    let_test_network!(network);
    let (subscriber_guard, subscriber_receiver) = mpsc::channel(1);
    network.subscribe_to_peers_messages_receiver = subscriber_receiver;
    let (network_high_guard, network_high_receiver) = net_channel::channel_with_capacity(1);
    network.network_message_high_receiver = network_high_receiver;
    let (network_low_guard, network_low_receiver) = net_channel::channel_with_capacity(1);
    network.network_message_low_receiver = network_low_receiver;
    let (topology_sender, topology_receiver) = control_update_channel();
    network.update_topology_receiver = topology_receiver;
    let shutdown = ShutdownSignal::new();
    let mut actor = tokio::spawn(network.run(shutdown.clone()));
    let flooding = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let flood_flag = Arc::clone(&flooding);
    let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
    let flood = std::thread::spawn(move || {
        send_control_update(
            &topology_sender,
            "topology",
            message::UpdateTopology(HashSet::new()),
        );
        let _ = started_sender.send(());
        while flood_flag.load(Ordering::Acquire) {
            send_control_update(
                &topology_sender,
                "topology",
                message::UpdateTopology(HashSet::new()),
            );
        }
    });
    tokio::time::timeout(Duration::from_secs(1), started_receiver)
        .await
        .expect("topology flood must start")
        .expect("topology flood task must stay alive");
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !actor.is_finished(),
        "network actor exited before shutdown was requested"
    );
    shutdown.send();
    let stopped_while_flooding = tokio::time::timeout(Duration::from_secs(5), &mut actor).await;
    flooding.store(false, Ordering::Release);
    flood.join().expect("topology flood thread must not panic");
    drop(subscriber_guard);
    drop(network_high_guard);
    drop(network_low_guard);
    if let Ok(actor_result) = stopped_while_flooding {
        actor_result.expect("network actor must not panic");
    } else {
        tokio::time::timeout(Duration::from_secs(1), actor)
            .await
            .expect("network actor must stop after the flood ends")
            .expect("network actor must not panic");
        panic!("a continuously ready topology slot starved network shutdown");
    }
}
#[test]
fn service_messages_are_pre_drained_ahead_of_saturated_high_queue() {
    let_test_network!(network);
    let (high_sender, high_receiver) =
        net_channel::channel_with_capacity(NETWORK_HIGH_ACTOR_DRAIN_SATURATED);
    network.network_message_high_receiver = high_receiver;
    for _ in 0..NETWORK_HIGH_ACTOR_DRAIN_SATURATED {
        high_sender
            .try_send(admitted_test_network_message(NetworkMessage::Broadcast(
                Broadcast {
                    data: DummyMsg,
                    priority: Priority::High,
                },
            )))
            .expect("high-priority saturation fixture must fit its queue");
    }
    let conn_id = 42;
    let (reply_sender, mut reply_receiver) = tokio::sync::oneshot::channel();
    network
        .service_message_sender
        .try_send(ServiceMessage::InboundAsk {
            conn_id,
            remote_addr: "127.0.0.1:12345".parse().expect("valid test address"),
            reply: reply_sender,
        })
        .expect("service fixture must fit its queue");
    assert_eq!(network.drain_service_messages(SERVICE_MESSAGE_BUDGET), 1);
    assert!(
        reply_receiver
            .try_recv()
            .expect("admission reply must be produced before bulk work")
    );
    assert!(network.incoming_pending.contains(&conn_id));
    assert_eq!(
        network.network_message_high_receiver.len(),
        NETWORK_HIGH_ACTOR_DRAIN_SATURATED,
        "service pre-drain must run before any saturated high-queue batch"
    );
}
#[test]
fn authenticated_rejection_releases_pending_connection_capacity() {
    let_test_network!(network);
    let conn_id = 73;
    let peer = test_peer(socket_addr!(127.0.0.1:12073));
    network.max_total_connections = Some(1);
    reserve_test_incoming(&mut network, conn_id);
    assert!(
        network.exceeds_caps(),
        "pending handshake must consume the cap"
    );
    network.peer_terminated(Terminated {
        peer: Some(peer),
        conn_id,
    });
    assert!(
        !network.incoming_pending.contains(&conn_id),
        "an authenticated connection rejected before activation must not leak its pending slot"
    );
    assert!(
        !network.exceeds_caps(),
        "the released pending slot must be available to a later connection"
    );
}
#[test]
fn failed_pre_handshake_dial_retains_exact_backoff_retry_owner() {
    let mut network = bare_network().expect("failed authentication actor fixture must initialize");
    let roster = deterministic_validator_roster(2);
    network.self_id = roster[0].clone();
    network.validator_dial_scheduler = ValidatorDialScheduler::new(
        roster.iter().cloned().collect(),
        network.outbound_authentication_timeout,
    );
    let peer = Peer::new(socket_addr!(127.0.0.1:12092), roster[1].clone());
    let conn_id = 92;
    network.max_total_connections = Some(1);
    network.current_topology.insert(peer.id().clone());
    network
        .current_peers_addresses
        .push((peer.id().clone(), peer.address().clone()));
    network.connecting_peers.insert(conn_id, peer.clone());
    network.outbound_connections.insert(conn_id);
    assert!(network.exceeds_caps());
    assert!(
        !network.trigger_reconnect_for_peer(peer.id()),
        "the unfinished authentication must retain exactly one dial owner"
    );

    network.peer_terminated(Terminated {
        peer: None,
        conn_id,
    });

    assert!(!network.connecting_peers.contains_key(&conn_id));
    assert!(!network.outbound_connections.contains(&conn_id));
    assert!(!network.exceeds_caps());
    assert_eq!(
        network
            .validator_dial_scheduler
            .role(&network.self_id, peer.id()),
        ValidatorDialRole::Preferred,
        "the failed preferred owner must remain eligible to retry"
    );
    let key = peer.address().to_string();
    let (retry_at, _) = network
        .retry_backoff
        .get(peer.id())
        .and_then(|by_address| by_address.get(&key))
        .copied()
        .expect("failed outbound dial installs its backoff deadline");
    assert_eq!(network.pending_connects.len(), 1);
    let (pending_at, pending_peer) = &network.pending_connects[0];
    assert_eq!(*pending_at, retry_at);
    assert_eq!(pending_peer.id(), peer.id());
    assert_eq!(pending_peer.address(), peer.address());

    network.peer_terminated(Terminated {
        peer: None,
        conn_id,
    });
    assert_eq!(network.pending_connects.len(), 1);
    assert_eq!(network.pending_connects[0].0, retry_at);
    assert_eq!(
        network.retry_backoff[peer.id()][&key].0,
        retry_at,
        "a duplicate authentication teardown must not postpone the retained retry"
    );
}
#[test]
fn address_snapshot_revokes_retained_retry_before_scheduling_replacement() {
    let_test_network!(network);
    let old_peer = test_peer(socket_addr!(127.0.0.1:12094));
    let replacement_addr = socket_addr!(127.0.0.1:12095);
    let conn_id = 94;
    network.current_topology.insert(old_peer.id().clone());
    network
        .current_peers_addresses
        .push((old_peer.id().clone(), old_peer.address().clone()));
    network.connecting_peers.insert(conn_id, old_peer.clone());
    network.outbound_connections.insert(conn_id);
    network.peer_terminated(Terminated {
        peer: None,
        conn_id,
    });
    assert!(network.is_scheduled(old_peer.id(), old_peer.address()));
    assert!(network.retry_backoff.contains_key(old_peer.id()));

    network.set_current_peers_addresses(UpdatePeers(vec![(
        old_peer.id().clone(),
        replacement_addr.clone(),
    )]));

    assert!(
        !network.retry_backoff.contains_key(old_peer.id()),
        "a replacing address snapshot must revoke the old backoff owner"
    );
    assert_eq!(network.pending_connects.len(), 1);
    assert_eq!(network.pending_connects[0].1.id(), old_peer.id());
    assert_eq!(
        network.pending_connects[0].1.address(),
        &replacement_addr,
        "only the replacement address may retain dial authority"
    );
}
#[test]
fn replaced_address_cannot_be_reintroduced_by_stale_pre_handshake_termination() {
    let_test_network!(network);
    let old_peer = test_peer(socket_addr!(127.0.0.1:12096));
    let replacement_addr = socket_addr!(127.0.0.1:12097);
    let conn_id = 96;
    network.current_topology.insert(old_peer.id().clone());
    network
        .current_peers_addresses
        .push((old_peer.id().clone(), old_peer.address().clone()));
    network.connecting_peers.insert(conn_id, old_peer.clone());
    network.outbound_connections.insert(conn_id);

    network.set_current_peers_addresses(UpdatePeers(vec![(
        old_peer.id().clone(),
        replacement_addr.clone(),
    )]));
    assert!(network.is_scheduled(old_peer.id(), &replacement_addr));

    network.peer_terminated(Terminated {
        peer: None,
        conn_id,
    });

    assert!(
        !network.is_scheduled(old_peer.id(), old_peer.address()),
        "a stale termination cannot restore revoked address authority"
    );
    assert!(
        network
            .retry_backoff
            .get(old_peer.id())
            .is_none_or(|by_address| !by_address.contains_key(&old_peer.address().to_string())),
        "a stale termination cannot restore revoked backoff state"
    );
    assert_eq!(network.pending_connects.len(), 1);
    assert_eq!(network.pending_connects[0].1.id(), old_peer.id());
    assert_eq!(network.pending_connects[0].1.address(), &replacement_addr);
}
#[test]
fn live_session_address_replacement_retries_current_endpoint() {
    for locally_initiated in [false, true] {
        let_test_network!(network);
        let old_peer = test_peer(socket_addr!(127.0.0.1:12098));
        let replacement_addr = socket_addr!(127.0.0.1:12099);
        let conn_id = 98;
        network.current_topology.insert(old_peer.id().clone());
        network
            .current_peers_addresses
            .push((old_peer.id().clone(), old_peer.address().clone()));
        let (handle, _receivers) = test_wire_peer_handle::<DummyMsg>(1);
        insert_dummy_ref_peer(
            &mut network,
            old_peer.id().clone(),
            old_peer.address().clone(),
            conn_id,
            handle,
        );
        if locally_initiated {
            network.outbound_connections.insert(conn_id);
        }

        network.set_current_peers_addresses(UpdatePeers(vec![(
            old_peer.id().clone(),
            replacement_addr.clone(),
        )]));
        assert!(
            network.pending_connects.is_empty(),
            "the replacement waits while the authenticated tenure is live"
        );

        network.peer_terminated(Terminated {
            peer: Some(old_peer.clone()),
            conn_id,
        });

        assert!(
            !network.is_scheduled(old_peer.id(), old_peer.address()),
            "the terminated address stays revoked"
        );
        assert!(
            network
                .retry_backoff
                .get(old_peer.id())
                .is_none_or(|by_address| {
                    !by_address.contains_key(&old_peer.address().to_string())
                }),
            "the terminated address cannot regain backoff authority"
        );
        assert_eq!(network.pending_connects.len(), 1);
        assert_eq!(network.pending_connects[0].1.id(), old_peer.id());
        assert_eq!(network.pending_connects[0].1.address(), &replacement_addr);
    }
}
#[tokio::test(flavor = "current_thread")]
async fn duplicate_configured_termination_does_not_advance_backoff_or_metrics() {
    let_test_network!(network);
    let peer = test_peer(socket_addr!(127.0.0.1:12093));
    let conn_id = 93;
    network.current_topology.insert(peer.id().clone());
    network
        .current_peers_addresses
        .push((peer.id().clone(), peer.address().clone()));
    let delivery_drain = Arc::new(InboundDeliveryDrain::new());
    let tenure = Arc::new(ReliableReplyRouteTenure {
        owner: Arc::clone(&network.reply_route_owner),
        _source_credits: crate::peer::message::AuthenticatedSourceCredits::new(1),
        delivery_peer: peer.id().clone(),
        connection_id: conn_id,
        connection_ordinal: 0,
        source_capacity: 8,
        delivery_active: AtomicBool::new(true),
        reply_writable: AtomicBool::new(true),
        delivery_drain: Arc::clone(&delivery_drain),
        termination_seen: AtomicBool::new(false),
    });
    network
        .reply_route_tenures
        .insert(conn_id, Arc::clone(&tenure));
    network.peer_terminated(Terminated {
        peer: Some(peer.clone()),
        conn_id,
    });
    assert!(tenure.termination_seen.load(Ordering::Acquire));
    let key = peer.address().to_string();
    let first_schedule = network
        .retry_backoff
        .get(peer.id())
        .and_then(|by_address| by_address.get(&key))
        .copied()
        .expect("configured dial target receives one reconnect schedule");
    assert_eq!(
        network.pending_connects.len(),
        1,
        "the backoff deadline must retain one runnable reconnect owner"
    );
    assert_eq!(network.pending_connects[0].0, first_schedule.0);
    assert_eq!(network.pending_connects[0].1.id(), peer.id());
    assert_eq!(network.pending_connects[0].1.address(), peer.address());
    network.peer_terminated(Terminated {
        peer: Some(peer.clone()),
        conn_id,
    });
    let after_duplicate = network
        .retry_backoff
        .get(peer.id())
        .and_then(|by_address| by_address.get(&key))
        .copied()
        .expect("the original reconnect schedule remains installed");
    assert_eq!(
        after_duplicate, first_schedule,
        "a duplicate configured-target notice must not invoke the scheduler again; that same scheduler call owns both backoff advancement and metrics"
    );
    assert_eq!(
        network.pending_connects.len(),
        1,
        "a duplicate notice must not mint another reconnect owner"
    );
    assert_eq!(network.pending_connects[0].0, first_schedule.0);
    assert!(
        network.reply_route_tenures.contains_key(&conn_id),
        "duplicate rejection is exercised while receiver ownership keeps the terminated tenure present"
    );
    delivery_drain.close_producer();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if network.drain_service_messages(SERVICE_MESSAGE_BUDGET) > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("producer close must release the synthetic draining tenure");
    assert!(!network.reply_route_tenures.contains_key(&conn_id));
}
#[test]
fn cancelled_inbound_ask_reply_rolls_back_the_reserved_slot() {
    let_test_network!(network);
    let conn_id = 731;
    let (reply, receiver) = tokio::sync::oneshot::channel();
    drop(receiver);
    network.handle_service_message(ServiceMessage::InboundAsk {
        conn_id,
        remote_addr: "127.0.0.1:12731".parse().expect("remote address"),
        reply,
    });
    assert!(
        !network.incoming_pending.contains(&conn_id),
        "a requester cancelled at the admission boundary must not leak capacity"
    );
}
#[test]
fn stale_inbound_cancellation_is_idempotent_and_never_deaccounts_active_state() {
    let_test_network!(network);
    let active_conn_id = 732;
    network.incoming_active.insert(active_conn_id);
    network.handle_service_message(ServiceMessage::InboundCancelled(active_conn_id));
    network.handle_service_message(ServiceMessage::InboundCancelled(active_conn_id));
    assert!(network.incoming_active.contains(&active_conn_id));
    assert!(!network.incoming_pending.contains(&active_conn_id));
}
#[tokio::test(flavor = "current_thread")]
async fn inbound_cancellation_retries_after_bounded_service_backpressure() {
    let (sender, mut receiver) = mpsc::channel::<ServiceMessage<WireMessage<DummyMsg>>>(1);
    sender
        .try_send(ServiceMessage::InboundCancelled(1))
        .expect("fill the bounded service queue");
    let guard = InboundReservationGuard::new(733, sender);
    drop(guard);
    assert!(matches!(
        receiver.recv().await,
        Some(ServiceMessage::InboundCancelled(1))
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), receiver.recv()).await,
        Ok(Some(ServiceMessage::InboundCancelled(733)))
    ));
}
#[test]
fn unauthenticated_cap_churn_cannot_displace_a_live_peer() {
    let_test_network!(network);
    network.max_total_connections = Some(1);
    let live_conn_id = 734;
    let live_peer = test_peer(socket_addr!(127.0.0.1:12734));
    let (live_handle, _live_receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(
        &mut network,
        live_peer.id().clone(),
        live_peer.address().clone(),
        live_conn_id,
        live_handle,
    );
    for offset in 0_u64..16 {
        let (reply, mut receiver) = tokio::sync::oneshot::channel();
        network.handle_service_message(ServiceMessage::InboundAsk {
            conn_id: 800 + offset,
            remote_addr: format!("127.0.0.1:{}", 12800 + offset)
                .parse()
                .expect("remote address"),
            reply,
        });
        assert!(!receiver.try_recv().expect("admission response"));
    }
    assert_eq!(network.peers.len(), 1);
    assert_eq!(
        network
            .peers
            .get(live_peer.id())
            .expect("the admitted peer must remain connected")
            .conn_id,
        live_conn_id
    );
    assert!(network.terminating_connections.is_empty());
    assert!(network.incoming_pending.is_empty());
}
#[test]
fn disconnected_connection_keeps_its_slot_until_matching_termination() {
    let_test_network!(network);
    network.max_total_connections = Some(1);
    let old_conn_id = 74;
    let new_conn_id = 75;
    let old_peer = test_peer(socket_addr!(127.0.0.1:12074));
    let (old_handle, old_receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(
        &mut network,
        old_peer.id().clone(),
        old_peer.address().clone(),
        old_conn_id,
        old_handle,
    );
    network.peer_reputations.record_connected(old_peer.id());
    network.disconnect_peer(old_peer.id());
    assert!(network.peers.is_empty());
    assert!(network.terminating_connections.contains(&old_conn_id));
    assert!(
        old_receivers.termination_requested(),
        "disconnect must explicitly cancel a writer that may be pinned by a non-reader"
    );
    assert_eq!(
        network.peer_reputations.score(old_peer.id()),
        0,
        "proactive disconnect must balance the accepted-generation reputation"
    );
    assert!(
        network.exceeds_caps(),
        "disconnect must not recycle a source-owner slot before actor teardown"
    );
    let (rejected_tx, mut rejected_rx) = tokio::sync::oneshot::channel();
    network.handle_service_message(ServiceMessage::InboundAsk {
        conn_id: new_conn_id,
        remote_addr: "127.0.0.1:12075".parse().expect("remote address"),
        reply: rejected_tx,
    });
    assert!(!rejected_rx.try_recv().expect("admission response"));
    assert!(!network.incoming_pending.contains(&new_conn_id));
    network.peer_terminated(Terminated {
        peer: Some(old_peer.clone()),
        conn_id: old_conn_id,
    });
    // A duplicate/stale notice must not consume or release another slot.
    network.peer_terminated(Terminated {
        peer: Some(old_peer),
        conn_id: old_conn_id,
    });
    assert!(network.terminating_connections.is_empty());
    assert!(!network.exceeds_caps());
    let (accepted_tx, mut accepted_rx) = tokio::sync::oneshot::channel();
    network.handle_service_message(ServiceMessage::InboundAsk {
        conn_id: new_conn_id,
        remote_addr: "127.0.0.1:12075".parse().expect("remote address"),
        reply: accepted_tx,
    });
    assert!(accepted_rx.try_recv().expect("admission response"));
    assert!(network.incoming_pending.contains(&new_conn_id));
}
#[test]
fn replacement_connection_tracks_predecessor_until_termination() {
    let_test_network!(network);
    network.max_total_connections = Some(2);
    let old_conn_id = 76;
    let new_conn_id = 77;
    let peer = test_peer(socket_addr!(127.0.0.1:12076));
    replace_test_authenticated_source_geometry(
        &mut network,
        2,
        Some(HashSet::from([peer.id().clone()])),
    );
    network.current_topology.insert(peer.id().clone());
    let (old_handle, old_receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(
        &mut network,
        peer.id().clone(),
        peer.address().clone(),
        old_conn_id,
        old_handle,
    );
    network.peer_reputations.record_connected(peer.id());
    network.incoming_active.insert(old_conn_id);
    network.outbound_connections.insert(old_conn_id);
    reserve_test_incoming(&mut network, new_conn_id);
    let semantic_origin = random_peer_id();
    let old_reply_tenure = test_reply_tenure(
        &network.reply_route_owner,
        peer.id().clone(),
        old_conn_id,
        0,
    );
    assert!(
        network
            .reply_route_tenures
            .insert(old_conn_id, Arc::clone(&old_reply_tenure))
            .is_none()
    );
    network.next_reply_connection_ordinal = 1;
    network.next_reply_delivery_ordinal = 1;
    let old_reply_route = NetworkReplyRoute::new(semantic_origin.clone(), old_reply_tenure, 0);
    let old_reply_authority = ProgressDeliveryAuthority::Reply(old_reply_route.clone());
    let old_reply_source = ActorProgressSource {
        target: Some(peer.id().clone()),
        class: ActorProgressClass::Lane,
    };
    let retained_shape = ProgressTicketShape {
        topic: message::Topic::Consensus,
        stream_wire_bytes: 1,
        broadcast: false,
        reply_writer_timeout_attempt: Some(0),
        request_digest: Hash::new(b"old-reply-retained"),
        authority: Some(old_reply_authority.identity()),
    };
    let ProgressLeaseAttempt::Ready {
        lease: old_reply_lease,
        ticket: mut retained_ticket,
    } = network
        .network_actor_progress_budget
        .try_reserve_for_source(
            1,
            retained_shape,
            old_reply_source.clone(),
            Some(&old_reply_authority),
            None,
        )
    else {
        panic!("old reply fixture must retain its source lane");
    };
    retained_ticket.commit();
    let waiting_shape = ProgressTicketShape {
        request_digest: Hash::new(b"old-reply-waiter"),
        ..retained_shape
    };
    let ProgressLeaseAttempt::Waiting {
        ticket: Some(old_reply_waiter),
        rank: 1,
    } = network
        .network_actor_progress_budget
        .try_reserve_for_source(
            1,
            waiting_shape,
            old_reply_source,
            Some(&old_reply_authority),
            None,
        )
    else {
        panic!("old reply fixture must retain one exact waiter");
    };
    let deferred = dummy_relay_frame(network.self_id.clone(), peer.id());
    let deferred_outcome = defer_frame!(
        network.deferred_send_queue,
        peer.id(),
        deferred,
        Other,
        Some(old_conn_id),
        tokio::time::Instant::now()
    );
    assert!(deferred_outcome.enqueued);
    connect_test_peer!(network, peer, new_conn_id, 1, Disabled => mut new_receivers, _peer_message_receiver);
    assert_eq!(network.peers[peer.id()].conn_id, new_conn_id);
    let new_reply_tenure = Arc::clone(
        network
            .reply_route_tenures
            .get(&new_conn_id)
            .expect("replacement installs its exact reply tenure"),
    );
    let new_reply_route = NetworkReplyRoute::new(
        semantic_origin,
        new_reply_tenure,
        network.next_reply_delivery_ordinal,
    );
    assert!(
        old_reply_route.is_active(),
        "replacement keeps authenticated local deliveries valid until termination drains"
    );
    assert!(
        !old_reply_route.is_reply_writable(),
        "replacement closes the predecessor writer immediately"
    );
    assert_eq!(
        old_reply_waiter.rank(),
        None,
        "replacement cancellation removes caller-held old-tenure ranks"
    );
    assert!(new_reply_route.is_active());
    assert_eq!(
        new_reply_route.source_update_from(&old_reply_route),
        Ok(NetworkReplyRouteSourceUpdate::Reconnected)
    );
    assert_eq!(new_reply_route.source_key(), old_reply_route.source_key());
    assert!(network.terminating_connections.contains(&old_conn_id));
    assert!(
        old_receivers.termination_requested(),
        "the replaced connection must release any blocked writer and its progress lease"
    );
    assert!(
        !new_receivers.termination_requested(),
        "replacement must not inherit its predecessor's cancellation"
    );
    assert!(
        new_receivers.try_recv_any().is_ok(),
        "peer-owned deferred progress must remain queued on the replacement connection"
    );
    assert_eq!(
        network.peer_reputations.score(peer.id()),
        1,
        "replacement must exchange, rather than accumulate, one live-connection score"
    );
    assert!(!network.incoming_active.contains(&old_conn_id));
    assert!(network.incoming_active.contains(&new_conn_id));
    assert!(network.exceeds_caps());
    network
        .low_buckets
        .insert(peer.id().clone(), TokenBucket::new(1.0, 1.0));
    network
        .low_bytes_buckets
        .insert(peer.id().clone(), TokenBucket::new(1.0, 1.0));
    network.peer_terminated(Terminated {
        peer: Some(peer.clone()),
        conn_id: old_conn_id,
    });
    assert!(!old_reply_route.is_active());
    assert!(network.terminating_connections.is_empty());
    assert_eq!(
        network.peers[peer.id()].conn_id,
        new_conn_id,
        "stale predecessor termination must not remove the replacement"
    );
    assert!(
        new_reply_route.is_active(),
        "stale connection termination must not cancel the replacement tenure's reply route"
    );
    assert!(
        network
            .reply_route_tenures
            .get(&new_conn_id)
            .is_some_and(|tenure| Arc::ptr_eq(tenure, &new_reply_route.tenure))
    );
    assert!(
        network.retry_backoff.is_empty(),
        "a retired outbound connection must not reintroduce backoff while its replacement is live"
    );
    assert!(network.low_buckets.contains_key(peer.id()));
    assert!(network.low_bytes_buckets.contains_key(peer.id()));
    assert!(!network.exceeds_caps());
    network.peer_terminated(Terminated {
        peer: Some(peer.clone()),
        conn_id: new_conn_id,
    });
    assert!(network.peers.is_empty());
    assert!(network.terminating_connections.is_empty());
    assert!(network.incoming_active.is_empty());
    assert!(
        !new_reply_route.is_active(),
        "replacement-connection termination cancels its exact reply route"
    );
    assert!(!network.reply_route_tenures.contains_key(&new_conn_id));
    assert_eq!(network.peer_reputations.score(peer.id()), 0);
    assert!(!network.low_buckets.contains_key(peer.id()));
    assert!(!network.low_bytes_buckets.contains_key(peer.id()));
    drop((old_reply_waiter, old_reply_lease));
}
#[tokio::test(flavor = "current_thread")]
async fn reply_route_tenure_retires_only_after_final_receiver_guard_drops() {
    let_test_network!(network);
    let peer = test_peer(socket_addr!(127.0.0.1:12087));
    network.max_total_connections = Some(2);
    // `peer_connected` acquires dispatch and reply-route ownership from
    // the protected authenticated-source geometry before publishing the
    // producer handles. Install the same frozen source set production
    // derives from topology before admitting this synthetic connection.
    replace_test_authenticated_source_geometry(
        &mut network,
        2,
        Some(HashSet::from([peer.id().clone()])),
    );
    network.current_topology.insert(peer.id().clone());
    let old_conn_id = 87;
    let new_conn_id = 88;
    let old_delivery_drain = Arc::new(InboundDeliveryDrain::new());
    reserve_test_incoming(&mut network, old_conn_id);
    let (old_handle, old_receivers) = test_wire_peer_handle::<DummyMsg>(1);
    let (old_sender_tx, mut old_sender_rx) = tokio::sync::oneshot::channel();
    connect_authenticated_fixture(
        &mut network,
        Connected {
            peer: peer.clone(),
            connection_id: old_conn_id,
            ready_peer_handle: old_handle,
            peer_message_sender: old_sender_tx,
            delivery_drain: Arc::clone(&old_delivery_drain),
            disambiguator: 0,
            relay_role: RelayRole::Disabled,
            scion_supported: false,
            trust_gossip: true,
        },
    );
    let old_senders = old_sender_rx
        .try_recv()
        .expect("authenticated connection receives its dispatch owners");
    let old_tenure = Arc::clone(
        network
            .reply_route_tenures
            .get(&old_conn_id)
            .expect("accepted connection installs its reply tenure"),
    );
    let old_route = NetworkReplyRoute::new(peer.id().clone(), old_tenure, 0);
    let frame = dummy_relay_frame(peer.id().clone(), peer.id());
    let mut delivered = PeerMessage::new_for_connection(peer.clone(), frame, 1, old_conn_id);
    assert!(
        old_senders
            .transfer_before_send_for_test(&mut delivered, message::Topic::Other, Priority::High,)
            .await
    );
    delivered.set_reply_route(old_route.clone());
    let (_origin, _authenticated_via, _payload, _bytes, retained_route, receiver_guard) =
        delivered.into_parts_with_reply_route();
    let retained_route = retained_route.expect("final consumer preserves its exact route");
    reserve_test_incoming(&mut network, new_conn_id);
    connect_test_peer!(network, peer, new_conn_id, 1, Disabled => _new_receivers, _new_sender_rx);
    assert!(old_receivers.termination_requested());
    assert!(retained_route.is_active());
    assert!(!retained_route.is_reply_writable());
    drop(old_senders);
    old_delivery_drain.close_producer();
    network.peer_terminated(Terminated {
        peer: Some(peer.clone()),
        conn_id: old_conn_id,
    });
    assert!(retained_route.is_active());
    assert!(!retained_route.is_reply_writable());
    assert!(network.reply_route_tenures.contains_key(&old_conn_id));
    assert!(network.terminating_connections.contains(&old_conn_id));
    assert_eq!(network.drain_service_messages(SERVICE_MESSAGE_BUDGET), 0);
    drop(receiver_guard);
    let drained = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let drained = network.drain_service_messages(SERVICE_MESSAGE_BUDGET);
            if drained > 0 {
                break drained;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("final receiver release must publish the delivery-drain fence");
    assert_eq!(drained, 1);
    assert!(!retained_route.is_active());
    assert!(!network.reply_route_tenures.contains_key(&old_conn_id));
    assert!(!network.terminating_connections.contains(&old_conn_id));
    assert_eq!(network.drain_service_messages(SERVICE_MESSAGE_BUDGET), 0);
    assert_eq!(network.peers[peer.id()].conn_id, new_conn_id);
}
#[test]
fn network_actor_drop_retires_routes_and_only_its_waiters() {
    let Some(mut first_actor) = bare_network() else {
        return;
    };
    let Some(mut independent_actor) = bare_network() else {
        return;
    };
    let prepare_waiter = |actor: &mut NetworkBase<DummyMsg, ChaCha20Poly1305>,
                          connection_id: ConnectionId,
                          connection_ordinal: u128,
                          label: &'static [u8]| {
        let delivery_peer = random_peer_id();
        let semantic_target = random_peer_id();
        let tenure = test_reply_tenure(
            &actor.reply_route_owner,
            delivery_peer.clone(),
            connection_id,
            connection_ordinal,
        );
        assert!(
            actor
                .reply_route_tenures
                .insert(connection_id, Arc::clone(&tenure))
                .is_none()
        );
        let route = NetworkReplyRoute::new(semantic_target, tenure, connection_ordinal);
        let authority = ProgressDeliveryAuthority::Reply(route.clone());
        let source = ActorProgressSource {
            target: Some(delivery_peer),
            class: ActorProgressClass::Lane,
        };
        let retained_shape = ProgressTicketShape {
            topic: message::Topic::Consensus,
            stream_wire_bytes: 1,
            broadcast: false,
            reply_writer_timeout_attempt: Some(0),
            request_digest: Hash::new_from_chunks(&[label, b"retained"]),
            authority: Some(authority.identity()),
        };
        let ProgressLeaseAttempt::Ready {
            lease,
            ticket: mut retained_ticket,
        } = actor.network_actor_progress_budget.try_reserve_for_source(
            1,
            retained_shape,
            source.clone(),
            Some(&authority),
            None,
        )
        else {
            panic!("reply teardown fixture must retain its source lane");
        };
        retained_ticket.commit();
        let waiting_shape = ProgressTicketShape {
            request_digest: Hash::new_from_chunks(&[label, b"waiting"]),
            ..retained_shape
        };
        let ProgressLeaseAttempt::Waiting {
            ticket: Some(waiter),
            rank: 1,
        } = actor.network_actor_progress_budget.try_reserve_for_source(
            1,
            waiting_shape,
            source,
            Some(&authority),
            None,
        )
        else {
            panic!("reply teardown fixture must retain one exact waiter");
        };
        (route, lease, waiter)
    };
    let (first_route, _first_lease, first_waiter) =
        prepare_waiter(&mut first_actor, 901, 41, b"first actor");
    let (independent_route, _independent_lease, independent_waiter) =
        prepare_waiter(&mut independent_actor, 901, 41, b"independent actor");
    assert!(first_route.is_active());
    assert!(independent_route.is_active());
    assert_eq!(first_waiter.rank(), Some(1));
    assert_eq!(independent_waiter.rank(), Some(1));
    drop(first_actor);
    assert!(
        !first_route.is_active(),
        "actor drop must revoke every externally retained route tenure"
    );
    assert_eq!(
        first_waiter.rank(),
        None,
        "actor drop must remove every waiter authorized by its retired tenures"
    );
    assert!(
        independent_route.is_active(),
        "another actor's source tenure must not inherit teardown"
    );
    assert_eq!(
        independent_waiter.rank(),
        Some(1),
        "another actor's source waiter must keep its independent rank"
    );
    drop(independent_actor);
    assert!(!independent_route.is_active());
    assert_eq!(independent_waiter.rank(), None);
}
#[tokio::test(flavor = "current_thread")]
async fn reconnecting_peer_cannot_multiply_retained_source_credits() {
    let_test_network!(network);
    network.authenticated_source_credit_capacity = 1;
    let peer = test_peer(socket_addr!(127.0.0.1:12077));
    replace_test_authenticated_source_geometry(
        &mut network,
        2,
        Some(HashSet::from([peer.id().clone()])),
    );
    network.current_topology.insert(peer.id().clone());
    let old_conn_id = 177;
    reserve_test_incoming(&mut network, old_conn_id);
    let (old_handle, old_receivers) = test_wire_peer_handle::<DummyMsg>(1);
    let (old_sender_tx, mut old_sender_rx) = tokio::sync::oneshot::channel();
    let old_delivery_drain = Arc::new(InboundDeliveryDrain::new());
    connect_authenticated_fixture(
        &mut network,
        Connected {
            peer: peer.clone(),
            connection_id: old_conn_id,
            ready_peer_handle: old_handle,
            peer_message_sender: old_sender_tx,
            delivery_drain: Arc::clone(&old_delivery_drain),
            disambiguator: 0,
            relay_role: RelayRole::Disabled,
            scion_supported: false,
            trust_gossip: true,
        },
    );
    let old_senders = old_sender_rx
        .try_recv()
        .expect("first authenticated connection receives its dispatch owners");
    let mut retained_old_message = PeerMessage::new(
        peer.clone(),
        dummy_relay_frame(network.self_id.clone(), peer.id()),
        1,
    );
    assert!(
        old_senders
            .transfer_before_send_for_test(
                &mut retained_old_message,
                message::Topic::Other,
                Priority::High,
            )
            .await
    );
    let (_peer, _authenticated_via, _payload, _bytes, retained_old_guard) =
        retained_old_message.into_parts();
    // Model transport teardown after the admitted message has already
    // crossed into an application backlog. The terminal retention guard is
    // now the only strong reference which can preserve the PeerId owner.
    drop(old_senders);
    old_delivery_drain.close_producer();
    let new_conn_id = 178;
    reserve_test_incoming(&mut network, new_conn_id);
    let (new_handle, _new_receivers) = test_wire_peer_handle::<DummyMsg>(1);
    let (new_sender_tx, mut new_sender_rx) = tokio::sync::oneshot::channel();
    let new_delivery_drain = Arc::new(InboundDeliveryDrain::new());
    connect_authenticated_fixture(
        &mut network,
        Connected {
            peer: peer.clone(),
            connection_id: new_conn_id,
            ready_peer_handle: new_handle,
            peer_message_sender: new_sender_tx,
            delivery_drain: new_delivery_drain,
            disambiguator: 1,
            relay_role: RelayRole::Disabled,
            scion_supported: false,
            trust_gossip: true,
        },
    );
    assert!(
        old_receivers.termination_requested(),
        "replacement must tear down the predecessor connection"
    );
    let new_senders = new_sender_rx
        .try_recv()
        .expect("replacement receives the PeerId-keyed dispatch owner");
    let mut replacement_message = PeerMessage::new(
        peer.clone(),
        dummy_relay_frame(network.self_id.clone(), peer.id()),
        1,
    );
    assert!(
        !new_senders
            .transfer_before_send_for_test(
                &mut replacement_message,
                message::Topic::Other,
                Priority::High,
            )
            .await,
        "a reconnect must not mint another high-lane count share while old work remains"
    );
    drop(retained_old_guard);
    assert!(
        new_senders
            .transfer_before_send_for_test(
                &mut replacement_message,
                message::Topic::Other,
                Priority::High,
            )
            .await,
        "the replacement advances as soon as the prior connection's terminal guard drops"
    );
}
#[test]
fn rejected_authenticated_connection_is_cancelled_and_remains_cap_accounted() {
    let_test_network!(network);
    let conn_id = 78;
    let peer_key_pair = random_node_key_pair();
    let peer = Peer::new(
        socket_addr!(127.0.0.1:12078),
        peer_key_pair.public_key().clone(),
    );
    network.max_total_connections = Some(1);
    reserve_test_incoming(&mut network, conn_id);
    // An empty permissioned topology rejects an untrusted authenticated observer.
    connect_test_peer!(
        network,
        peer,
        conn_id,
        0,
        Disabled => receivers,
        mut peer_message_receiver
    );
    assert!(network.peers.is_empty());
    assert!(!network.incoming_pending.contains(&conn_id));
    assert!(!network.incoming_active.contains(&conn_id));
    assert!(network.terminating_connections.contains(&conn_id));
    assert!(network.exceeds_caps());
    assert!(receivers.termination_requested());
    assert_eq!(network.peer_reputations.score(peer.id()), 0);
    assert!(matches!(
        peer_message_receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    network.peer_terminated(Terminated {
        peer: Some(peer.clone()),
        conn_id,
    });
    assert!(network.terminating_connections.is_empty());
    assert!(!network.exceeds_caps());
    assert!(
        network.retry_backoff.is_empty(),
        "rejected inbound identity churn must not accumulate redial state"
    );
    assert_eq!(network.peer_reputations.score(peer.id()), 0);
}
#[test]
fn public_observer_is_rejected_before_source_authority_and_admitted_after_explicit_empty() {
    let_test_network!(network);
    replace_test_authenticated_source_geometry(&mut network, 1, None);
    network.consensus_caps = Some(crate::ConsensusHandshakeCaps {
        mode: crate::ConsensusMode::Npos,
        proto_version: 1,
        consensus_fingerprint: [0; 32],
        config: crate::ConsensusConfigCaps {
            execution_policy_hash: [0; 32],
            nexus_policy_digest: [0; 32],
            native_config_fingerprint: [0; 32],
            ivm_gas_schedule_hash: [0; 32],
        },
    });
    let peer = test_peer(socket_addr!(127.0.0.1:12081));
    let first_conn_id = 81;
    reserve_test_incoming(&mut network, first_conn_id);
    connect_test_peer!(network, peer, first_conn_id, 0, Disabled => first_receivers, mut first_receiver);
    assert!(first_receivers.termination_requested());
    assert!(matches!(
        first_receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    assert!(!network.peers.contains_key(peer.id()));
    network.peer_terminated(Terminated {
        peer: Some(peer.clone()),
        conn_id: first_conn_id,
    });
    assert!(
        network
            .inbound_frame_byte_budgets
            .install_protected_sources(HashSet::new())
    );
    let second_conn_id = 82;
    reserve_test_incoming(&mut network, second_conn_id);
    connect_test_peer!(network, peer, second_conn_id, 1, Disabled => second_receivers, mut second_receiver);
    assert!(second_receiver.try_recv().is_ok());
    assert!(!second_receivers.termination_requested());
    assert_eq!(network.peers[peer.id()].conn_id, second_conn_id);
}
#[test]
fn failed_authenticated_handoff_never_installs_a_zombie_peer() {
    let_test_network!(network);
    let conn_id = 79;
    let peer = test_peer(socket_addr!(127.0.0.1:12079));
    replace_test_authenticated_source_geometry(
        &mut network,
        2,
        Some(HashSet::from([peer.id().clone()])),
    );
    network.current_topology.insert(peer.id().clone());
    reserve_test_incoming(&mut network, conn_id);
    let (handle, receivers) = test_wire_peer_handle::<DummyMsg>(1);
    let (peer_message_sender, peer_message_receiver) = tokio::sync::oneshot::channel();
    drop(peer_message_receiver);
    connect_authenticated_fixture(
        &mut network,
        Connected {
            peer: peer.clone(),
            connection_id: conn_id,
            ready_peer_handle: handle,
            peer_message_sender,
            delivery_drain: InboundDeliveryDrain::completed_for_test(),
            disambiguator: 0,
            relay_role: RelayRole::Disabled,
            scion_supported: false,
            trust_gossip: true,
        },
    );
    assert!(!network.peers.contains_key(peer.id()));
    assert!(!network.incoming_pending.contains(&conn_id));
    assert!(!network.incoming_active.contains(&conn_id));
    assert!(network.terminating_connections.contains(&conn_id));
    assert!(receivers.termination_requested());
    assert_eq!(network.peer_reputations.score(peer.id()), 0);
    assert!(!network.last_active.contains_key(peer.id()));
    assert!(!network.address_book.contains_key(peer.id()));
    assert!(!network.peer_capabilities.contains_key(peer.id()));
}
#[test]
fn configured_assist_hub_connection_cannot_overflow_reliable_geometry() {
    let_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Assist;
    let validator = random_peer_id();
    replace_test_authenticated_source_geometry(
        &mut network,
        1,
        Some(HashSet::from([validator.clone()])),
    );
    network.requested_topology.insert(validator.clone());
    network.current_topology.insert(validator.clone());
    let hub = test_peer(socket_addr!(127.0.0.1:12093));
    network.relay_hub_addresses.push(hub.address().clone());
    network.relay_trusted_peers.insert(hub.id().clone());
    network
        .peer_reputations
        .set_trusted(&HashSet::from([hub.id().clone()]));
    let conn_id = 2_093;
    reserve_test_incoming(&mut network, conn_id);
    connect_test_peer!(network, hub, conn_id, 0, Hub => receivers, mut peer_message_receiver);
    assert!(matches!(
        peer_message_receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    assert!(receivers.termination_requested());
    assert!(network.terminating_connections.contains(&conn_id));
    assert!(!network.peers.contains_key(hub.id()));
    assert_eq!(network.current_topology, HashSet::from([validator]));
    assert!(
        network.relay_hub_peer.is_none(),
        "over-capacity hub admission must leave the prior assist selection unchanged"
    );
}
#[test]
fn rejected_inbound_identity_churn_leaves_no_retry_or_session_state() {
    let_test_network!(network);
    replace_test_authenticated_source_geometry(&mut network, 1, Some(HashSet::new()));
    for offset in 0_u16..128 {
        let conn_id = 1_000 + u64::from(offset);
        let peer = Peer::new(
            format!("127.0.0.1:{}", 20_000 + offset)
                .parse()
                .expect("churn address"),
            random_node_key_pair().public_key().clone(),
        );
        reserve_test_incoming(&mut network, conn_id);
        connect_test_peer!(network, peer, conn_id, 0, Disabled => receivers, _peer_message_receiver);
        assert!(receivers.termination_requested());
        network.peer_terminated(Terminated {
            peer: Some(peer),
            conn_id,
        });
    }
    assert!(network.peers.is_empty());
    assert!(network.connecting_peers.is_empty());
    assert!(network.outbound_connections.is_empty());
    assert!(network.incoming_pending.is_empty());
    assert!(network.incoming_active.is_empty());
    assert!(network.terminating_connections.is_empty());
    assert!(network.retry_backoff.is_empty());
    assert!(network.peer_reputations.inner.is_empty());
    assert!(network.last_active.is_empty());
    assert!(network.address_book.is_empty());
    assert!(network.peer_capabilities.is_empty());
    assert!(network.current_topology.is_empty());
}
#[test]
fn accepted_public_observer_churn_does_not_expand_consensus_or_metadata_state() {
    let_test_network!(network);
    replace_test_authenticated_source_geometry(&mut network, 1, Some(HashSet::new()));
    network.consensus_caps = Some(crate::ConsensusHandshakeCaps {
        mode: crate::ConsensusMode::Npos,
        proto_version: 1,
        consensus_fingerprint: [0; 32],
        config: crate::ConsensusConfigCaps {
            execution_policy_hash: [0; 32],
            nexus_policy_digest: [0; 32],
            native_config_fingerprint: [0; 32],
            ivm_gas_schedule_hash: [0; 32],
        },
    });
    for offset in 0_u16..128 {
        let conn_id = 2_000 + u64::from(offset);
        let peer = Peer::new(
            format!("127.0.0.1:{}", 22_000 + offset)
                .parse()
                .expect("churn address"),
            random_node_key_pair().public_key().clone(),
        );
        reserve_test_incoming(&mut network, conn_id);
        connect_test_peer!(network, peer, conn_id, 0, Disabled => receivers, peer_message_receiver);
        assert!(network.peers.contains_key(peer.id()));
        assert!(!receivers.termination_requested());
        assert!(network.current_topology.is_empty());
        assert!(network.address_book.is_empty());
        assert!(network.peer_capabilities.is_empty());
        network.peer_terminated(Terminated {
            peer: Some(peer),
            conn_id,
        });
        drop(peer_message_receiver);
        assert!(network.peers.is_empty());
        assert!(network.incoming_pending.is_empty());
        assert!(network.incoming_active.is_empty());
        assert!(network.retry_backoff.is_empty());
        assert!(network.peer_reputations.inner.is_empty());
    }
    assert!(network.current_topology.is_empty());
    assert!(network.address_book.is_empty());
    assert!(network.peer_capabilities.is_empty());
}
#[tokio::test(flavor = "current_thread")]
async fn superseded_connection_cannot_deliver_an_already_queued_message() {
    let_test_network!(network);
    let peer_key_pair = random_node_key_pair();
    let peer = Peer::new(
        socket_addr!(127.0.0.1:12078),
        peer_key_pair.public_key().clone(),
    );
    let current_conn_id = 78;
    let stale_conn_id = 77;
    let (handle, _receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(
        &mut network,
        peer.id().clone(),
        peer.address().clone(),
        current_conn_id,
        handle,
    );
    let relay = || {
        RelayMessage::new_signed(
            &peer_key_pair,
            RelayTarget::Broadcast,
            DEFAULT_RELAY_TTL,
            DummyMsg,
        )
    };
    network
        .peer_message(PeerMessage::new_for_connection(
            peer.clone(),
            relay(),
            1,
            stale_conn_id,
        ))
        .await;
    assert!(
        !network.last_active.contains_key(peer.id()),
        "a queued predecessor message must be dropped before it mutates peer state"
    );
    network
        .peer_message(PeerMessage::new_for_connection(
            peer.clone(),
            relay(),
            1,
            current_conn_id,
        ))
        .await;
    assert!(
        network.last_active.contains_key(peer.id()),
        "the exact current authenticated tenure must remain serviceable"
    );
}
#[tokio::test(flavor = "current_thread")]
async fn accepted_draining_connection_delivers_reliable_progress_after_replacement() {
    let_test_network!(network, DeferredProgressMsg);
    let peer_key_pair = random_node_key_pair();
    let peer = Peer::new(
        socket_addr!(127.0.0.1:12079),
        peer_key_pair.public_key().clone(),
    );
    let current_conn_id = 80;
    let draining_conn_id = 79;
    let_deferred_peer!(_receivers = &mut network; peer.id().clone(), peer.address().clone(), current_conn_id);
    let relay = RelayMessage::new_signed(
        &peer_key_pair,
        RelayTarget::Broadcast,
        DEFAULT_RELAY_TTL,
        DeferredProgressMsg::Lane(9),
    );
    network
        .peer_message(PeerMessage::new_for_connection(
            peer.clone(),
            relay,
            1,
            draining_conn_id,
        ))
        .await;
    assert!(
        network.last_active.contains_key(peer.id()),
        "authenticated progress queued before replacement must survive the connection change"
    );
}
fn trust_skip_count(_: &str, _: &str) -> u64 {
    trust_gossip_skipped_capability_off_count()
}
#[test]
fn ip_bucket_v4_groups_by_24() {
    let k1 = ip_bucket_key(IpAddr::from([192, 168, 1, 10]), 24, 64);
    let k2 = ip_bucket_key(IpAddr::from([192, 168, 1, 200]), 24, 64);
    let k3 = ip_bucket_key(IpAddr::from([192, 168, 2, 1]), 24, 64);
    assert_eq!(k1, k2);
    assert_ne!(k1, k3);
}
#[test]
fn token_bucket_allows_burst_then_throttles() {
    let mut tb = TokenBucket::new(10.0, 3.0);
    // Allow immediately up to burst
    assert!(tb.allow());
    assert!(tb.allow());
    assert!(tb.allow());
    // Next one should be throttled without time passing
    assert!(!tb.allow());
}

#[test]
fn low_byte_burst_covers_each_plaintext_topic_and_preserves_explicit_choices() {
    use core::num::NonZeroU32;
    let rate = NonZeroU32::new(17);
    for index in 0..6 {
        let mut caps = TopicFrameCaps::uniform(32);
        let topics = [
            &mut caps.block_sync,
            &mut caps.tx_gossip,
            &mut caps.peer_gossip,
            &mut caps.health,
            &mut caps.connect,
            &mut caps.other,
        ];
        *topics.into_iter().nth(index).unwrap() = 4096;
        // High-only caps do not inflate low shaping; stream overhead is not charged here.
        caps.control = 8192;
        caps.consensus = 16384;
        assert_eq!(resolve_low_byte_burst(rate, None, caps).unwrap(), 4096);
        assert_eq!(resolve_low_byte_burst(None, None, caps).unwrap(), 4096);
        assert_eq!(
            resolve_low_byte_burst(NonZeroU32::new(8192), None, caps).unwrap(),
            8192
        );
        for exact_or_larger in [4096, 4097] {
            assert_eq!(
                resolve_low_byte_burst(rate, NonZeroU32::new(exact_or_larger), caps).unwrap(),
                exact_or_larger
            );
        }
        for configured_rate in [None, rate] {
            assert!(matches!(
                resolve_low_byte_burst(configured_rate, NonZeroU32::new(4095), caps),
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput
                    && error.to_string().contains("4095")
                    && error.to_string().contains("4096 canonical plaintext bytes")
            ));
        }
    }
    if let Some(above_u32) = (u32::MAX as usize).checked_add(1) {
        assert!(matches!(
            resolve_low_byte_burst(rate, None, TopicFrameCaps::uniform(above_u32)),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput
        ));
    }
}

#[tokio::test(start_paused = true)]
async fn low_byte_home_rate_admits_maximum_frame_then_refills_at_original_rate() {
    use iroha_config::parameters::{actual::LaneProfile, defaults::network as defaults};
    let rate = LaneProfile::Home
        .derived_limits()
        .low_priority_bytes_per_sec
        .unwrap();
    let maximum = defaults::MAX_FRAME_BYTES_TX_GOSSIP.get();
    let caps = TopicFrameCaps::uniform(maximum);
    let burst = resolve_low_byte_burst(Some(rate), None, caps).unwrap();
    assert_eq!(burst as usize, maximum);
    assert!(
        rate.get() < burst,
        "home profile recreates the former starvation geometry"
    );
    let mut network = bare_network().expect("local network fixture");
    network.low_bytes_per_sec = Some(f64::from(rate.get()));
    network.low_bytes_burst = f64::from(burst);
    let peer = random_peer_id();
    assert!(network.low_allow_bytes(&peer, maximum));
    assert!(!network.low_allow_bytes(&peer, 1));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(network.low_allow_bytes(&peer, rate.get() as usize));
    assert!(!network.low_allow_bytes(&peer, 1));
    tokio::time::advance(Duration::from_secs(100)).await;
    assert!(!network.low_allow_bytes(&peer, maximum + 1));
    assert!(network.low_allow_bytes(&peer, maximum));
    assert!(
        !network.low_allow_bytes(&peer, 1),
        "idle refill remains bounded by the finite burst"
    );
}

#[tokio::test(start_paused = true)]
async fn low_byte_posts_and_broadcasts_charge_materialized_data_framing() {
    for broadcast in [false, true] {
        let mut network = bare_network().expect("local network fixture");
        let peer = test_peer(socket_addr!(127.0.0.1:12055));
        let (handle, _receivers) = test_wire_peer_handle::<DummyMsg>(4);
        insert_dummy_ref_peer(
            &mut network,
            peer.id().clone(),
            peer.address().clone(),
            155,
            handle,
        );
        network.current_topology.insert(peer.id().clone());
        let target = if broadcast {
            RelayTarget::Broadcast
        } else {
            RelayTarget::Direct(peer.id().clone())
        };
        // A non-hub peer consumes the frame itself, so it stays link-local.
        let relay =
            RelayMessage::new_link(network.self_id.clone(), target, network.relay_ttl, DummyMsg);
        let plaintext = crate::peer::materialized_data_message_wire_len(relay).unwrap();
        network.low_bytes_per_sec = Some(1.0);
        network.low_bytes_burst = f64::from(u32::try_from(plaintext).unwrap());
        if broadcast {
            network.broadcast_low(Broadcast {
                data: DummyMsg,
                priority: Priority::Low,
            });
        } else {
            network.post_low(Post {
                data: DummyMsg,
                peer_id: peer.id().clone(),
                priority: Priority::Low,
            });
        }
        assert!(network.low_bytes_buckets.contains_key(peer.id()));
        assert!(
            !network.low_allow_bytes(peer.id(), 1),
            "the Data wrapper/header must also be charged"
        );
    }
}
#[test]
fn topology_update_interval_uses_configured_period() {
    let Some(network) = bare_network() else {
        return;
    };
    assert_eq!(
        network.topology_update_interval,
        iroha_config::parameters::defaults::network::PEER_GOSSIP_PERIOD
    );
}
#[test]
fn topology_tick_interval_ignores_env_override() {
    let configured = Duration::from_millis(500);
    assert_eq!(topology_tick_interval(configured), configured);
}
#[test]
fn connect_startup_delay_clamps_when_before_deadline() {
    let now = tokio::time::Instant::now();
    let delay_until = now + Duration::from_secs(5);
    let when = now + Duration::from_secs(1);
    assert_eq!(apply_connect_startup_delay(when, delay_until), delay_until);
}
#[test]
fn update_topology_respects_startup_delay() {
    let_test_network!(network);
    let peer_id = random_peer_id();
    let addr = socket_addr!(127.0.0.1:34567);
    let delay_until = tokio::time::Instant::now() + Duration::from_secs(5);
    network.connect_startup_delay_until = delay_until;
    network.current_topology.insert(peer_id.clone());
    network.current_peers_addresses.push((peer_id, addr));
    network.update_topology();
    assert!(
        !network.pending_connects.is_empty(),
        "pending connects should be scheduled for new topology peers"
    );
    assert!(
        network
            .pending_connects
            .iter()
            .all(|(when, _)| *when >= delay_until),
        "scheduled connect attempts must honor startup delay"
    );
}
#[test]
fn trusted_observers_survive_topology_updates() {
    let_test_network!(network);
    let peer_id = random_peer_id();
    let trusted_id = random_peer_id();
    let mut trusted = HashSet::new();
    trusted.insert(trusted_id.clone());
    network.peer_reputations.set_trusted(&trusted);
    network.set_current_topology(UpdateTopology([peer_id.clone()].into_iter().collect()));
    assert!(
        network.current_topology.contains(&peer_id),
        "topology should retain peers from update"
    );
    assert!(
        network.current_topology.contains(&trusted_id),
        "trusted observers should remain connected across topology updates"
    );
}
#[test]
fn topology_larger_than_reliable_target_geometry_is_rejected_atomically() {
    let_test_network!(network);
    network.max_total_connections = Some(2);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Assist;
    let retained = random_peer_id();
    let retained_hub = random_peer_id();
    network.current_topology.insert(retained.clone());
    network.relay_hub_peer = Some(retained_hub.clone());
    let oversized: HashSet<_> = (0..3).map(|_| random_peer_id()).collect();
    network.set_current_topology(UpdateTopology(oversized));
    assert_eq!(network.current_topology, HashSet::from([retained]));
    assert_eq!(
        network.relay_hub_peer,
        Some(retained_hub),
        "a rejected topology snapshot must not partially clear assist state"
    );
    assert_eq!(network.reliable_actor_target_capacity(), 2);
}
#[test]
fn rejected_validator_topology_cannot_partially_promote_dial_ownership() {
    let_test_network!(network);
    network.max_total_connections = Some(2);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Assist;
    let self_id = network.self_id.clone();
    let candidate = random_peer_id();
    let configured = HashSet::from([self_id.clone(), candidate.clone()]);
    network.validator_dial_scheduler =
        ValidatorDialScheduler::new(configured, Duration::from_secs(7));
    network
        .validator_dial_scheduler
        .replace_roster(HashSet::from([self_id.clone()]), &self_id);
    let oversized = HashSet::from([candidate.clone(), random_peer_id(), random_peer_id()]);
    network.set_validator_topology(message::UpdateValidatorTopology {
        topology: oversized,
        validator_dial_roster: HashSet::from([self_id.clone(), candidate.clone()]),
    });
    assert_eq!(
        network.validator_dial_scheduler.role(&self_id, &candidate),
        ValidatorDialRole::Unmanaged,
        "a rejected membership snapshot must roll back its ownership roster"
    );
    assert!(network.pending_reply_source_authority.is_empty());
}
#[test]
fn blocked_a_to_b_drains_old_route_and_suppresses_obsolete_reconnect() {
    let_test_network!(network);
    let old_source = test_peer(socket_addr!(127.0.0.1:12101));
    let desired_source = random_peer_id();
    replace_test_authenticated_source_geometry(
        &mut network,
        1,
        Some(HashSet::from([old_source.id().clone()])),
    );
    network.requested_topology = HashSet::from([old_source.id().clone()]);
    network.current_topology = network.requested_topology.clone();
    network
        .current_peers_addresses
        .push((old_source.id().clone(), old_source.address().clone()));
    network
        .pending_connects
        .push((tokio::time::Instant::now(), old_source.clone()));
    network.retry_backoff.insert(
        old_source.id().clone(),
        HashMap::from([(
            old_source.address().to_string(),
            (tokio::time::Instant::now(), Duration::from_secs(1)),
        )]),
    );
    let old_conn_id = 3_101;
    let (old_handle, old_receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(
        &mut network,
        old_source.id().clone(),
        old_source.address().clone(),
        old_conn_id,
        old_handle,
    );
    network.outbound_connections.insert(old_conn_id);
    let old_credits = network
        .inbound_frame_byte_budgets
        .source_credits(old_source.id(), 1)
        .expect("old source count owner");
    let old_tenure = Arc::new(ReliableReplyRouteTenure {
        owner: Arc::clone(&network.reply_route_owner),
        _source_credits: old_credits,
        delivery_peer: old_source.id().clone(),
        connection_id: old_conn_id,
        connection_ordinal: 0,
        source_capacity: 1,
        delivery_active: AtomicBool::new(true),
        reply_writable: AtomicBool::new(true),
        delivery_drain: InboundDeliveryDrain::completed_for_test(),
        termination_seen: AtomicBool::new(false),
    });
    network
        .reply_route_tenures
        .insert(old_conn_id, Arc::clone(&old_tenure));
    let retained_route = NetworkReplyRoute::new(random_peer_id(), old_tenure, 0);
    network.set_current_topology(UpdateTopology(HashSet::from([desired_source.clone()])));
    assert!(!network.pending_reply_source_authority.is_empty());
    assert_eq!(
        network.requested_topology,
        HashSet::from([old_source.id().clone()])
    );
    assert_eq!(
        network.inbound_frame_byte_budgets.protected_sources(),
        Some(HashSet::from([desired_source.clone()]))
    );
    assert!(
        !network
            .inbound_frame_byte_budgets
            .protected_source_geometry_fits()
    );
    assert!(old_receivers.termination_requested());
    assert!(!network.peers.contains_key(old_source.id()));
    assert!(network.pending_connects.is_empty());
    assert!(!network.retry_backoff.contains_key(old_source.id()));
    assert!(
        network
            .inbound_frame_byte_budgets
            .source_credits(&desired_source, 1)
            .is_none(),
        "B cannot publish while A's retained route still owns the only source slot"
    );
    // `request_termination` is only the writer-side signal. Model the
    // peer task's exact terminal notice as well so the actor can retire
    // its tenure while the independently retained route keeps A's source
    // owner charged until the final local capability is dropped.
    network.peer_terminated(Terminated {
        peer: Some(old_source.clone()),
        conn_id: old_conn_id,
    });
    assert!(!retained_route.is_active());
    assert!(!network.reply_route_tenures.contains_key(&old_conn_id));
    let reconnect_conn_id = 3_102;
    network.outbound_connections.insert(reconnect_conn_id);
    connect_test_peer!(network, old_source, reconnect_conn_id, 1, Disabled => reconnect_receivers, mut reconnect_receiver);
    assert!(reconnect_receivers.termination_requested());
    assert!(matches!(
        reconnect_receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    network.peer_terminated(Terminated {
        peer: Some(old_source.clone()),
        conn_id: reconnect_conn_id,
    });
    assert!(
        !network.retry_backoff.contains_key(old_source.id()),
        "the obsolete outbound attempt cannot recreate A's redial state"
    );
    drop(retained_route);
    assert!(network.retry_pending_reply_source_authority());
    assert!(network.pending_reply_source_authority.is_empty());
    assert_eq!(
        network.requested_topology,
        HashSet::from([desired_source.clone()])
    );
    assert!(network.current_topology.contains(&desired_source));
    assert!(
        network
            .inbound_frame_byte_budgets
            .protected_source_geometry_fits()
    );
}
#[test]
fn a_to_b_to_a_source_authority_commits_only_newest_snapshot() {
    let_test_network!(network);
    let source_a = random_peer_id();
    let source_b = random_peer_id();
    replace_test_authenticated_source_geometry(
        &mut network,
        1,
        Some(HashSet::from([source_a.clone()])),
    );
    network.requested_topology = HashSet::from([source_a.clone()]);
    network.current_topology = network.requested_topology.clone();
    let retained_a = network
        .inbound_frame_byte_budgets
        .source_credits(&source_a, 1)
        .expect("A owns the sole source slot");
    network.set_current_topology(UpdateTopology(HashSet::from([source_b.clone()])));
    assert!(!network.pending_reply_source_authority.is_empty());
    assert_eq!(
        network.inbound_frame_byte_budgets.protected_sources(),
        Some(HashSet::from([source_b.clone()]))
    );
    network.set_current_topology(UpdateTopology(HashSet::from([source_a.clone()])));
    assert!(network.pending_reply_source_authority.is_empty());
    assert_eq!(
        network.requested_topology,
        HashSet::from([source_a.clone()])
    );
    assert_eq!(network.current_topology, HashSet::from([source_a.clone()]));
    assert_eq!(
        network.inbound_frame_byte_budgets.protected_sources(),
        Some(HashSet::from([source_a]))
    );
    assert!(
        network
            .inbound_frame_byte_budgets
            .protected_source_geometry_fits()
    );
    drop(retained_a);
}
#[test]
fn impossible_source_authority_snapshot_preserves_last_valid_projection() {
    let_test_network!(network);
    let retained = random_peer_id();
    let overflow_a = random_peer_id();
    let overflow_b = random_peer_id();
    replace_test_authenticated_source_geometry(
        &mut network,
        1,
        Some(HashSet::from([retained.clone()])),
    );
    network.requested_topology = HashSet::from([retained.clone()]);
    network.current_topology = network.requested_topology.clone();
    network.set_current_topology(UpdateTopology(HashSet::from([overflow_a, overflow_b])));
    assert!(network.pending_reply_source_authority.is_empty());
    assert_eq!(
        network.requested_topology,
        HashSet::from([retained.clone()])
    );
    assert_eq!(network.current_topology, HashSet::from([retained.clone()]));
    assert_eq!(
        network.inbound_frame_byte_budgets.protected_sources(),
        Some(HashSet::from([retained]))
    );
}
#[test]
fn assist_hub_refresh_above_reliable_geometry_is_rejected_atomically() {
    let_test_network!(network);
    network.max_total_connections = Some(1);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Assist;
    let validator = random_peer_id();
    let hub = random_peer_id();
    let hub_addr = socket_addr!(127.0.0.1:12092);
    network.current_topology.insert(validator.clone());
    network.relay_hub_addresses.push(hub_addr.clone());
    network
        .current_peers_addresses
        .push((hub.clone(), hub_addr));
    network.relay_trusted_peers.insert(hub);
    network.update_topology();
    assert_eq!(network.current_topology, HashSet::from([validator]));
    assert!(
        network.relay_hub_peer.is_none(),
        "a rejected assist refresh must not install only the hub half of the transition"
    );
}
#[test]
fn configured_hub_handoff_waits_for_retained_old_source_and_commits_on_reconnect() {
    let_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
    let hub_a = test_peer(socket_addr!(127.0.0.1:12111));
    let hub_b = test_peer(socket_addr!(127.0.0.1:12112));
    replace_test_authenticated_source_geometry(
        &mut network,
        1,
        Some(HashSet::from([hub_a.id().clone()])),
    );
    network.relay_trusted_peers = HashSet::from([hub_a.id().clone(), hub_b.id().clone()]);
    network.relay_hub_peer = Some(hub_a.id().clone());
    network.current_topology = HashSet::from([hub_a.id().clone()]);
    network.current_peers_addresses.extend([
        (hub_a.id().clone(), hub_a.address().clone()),
        (hub_b.id().clone(), hub_b.address().clone()),
    ]);
    let hub_a_conn_id = 3_111;
    let (hub_a_handle, _hub_a_receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(
        &mut network,
        hub_a.id().clone(),
        hub_a.address().clone(),
        hub_a_conn_id,
        hub_a_handle,
    );
    network
        .peers
        .get_mut(hub_a.id())
        .expect("hub A peer")
        .relay_role = RelayRole::Hub;
    network.outbound_connections.insert(hub_a_conn_id);
    let hub_a_credits = network
        .inbound_frame_byte_budgets
        .source_credits(hub_a.id(), 1)
        .expect("hub A source owner");
    let hub_a_tenure = Arc::new(ReliableReplyRouteTenure {
        owner: Arc::clone(&network.reply_route_owner),
        _source_credits: hub_a_credits,
        delivery_peer: hub_a.id().clone(),
        connection_id: hub_a_conn_id,
        connection_ordinal: 0,
        source_capacity: 1,
        delivery_active: AtomicBool::new(true),
        reply_writable: AtomicBool::new(true),
        delivery_drain: InboundDeliveryDrain::completed_for_test(),
        termination_seen: AtomicBool::new(false),
    });
    network
        .reply_route_tenures
        .insert(hub_a_conn_id, Arc::clone(&hub_a_tenure));
    let retained_hub_a_route = NetworkReplyRoute::new(random_peer_id(), hub_a_tenure, 0);
    network.peer_terminated(Terminated {
        peer: Some(hub_a.clone()),
        conn_id: hub_a_conn_id,
    });
    assert!(network.retry_backoff.contains_key(hub_a.id()));
    assert!(!network.peers.contains_key(hub_a.id()));
    assert!(network.is_configured_hub_peer(&hub_b, RelayRole::Hub));
    let first_b_conn_id = 3_112;
    reserve_test_incoming(&mut network, first_b_conn_id);
    connect_test_peer!(network, hub_b, first_b_conn_id, 0, Hub => first_b_receivers, mut first_b_receiver);
    assert!(first_b_receivers.termination_requested());
    assert!(matches!(
        first_b_receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    assert_eq!(
        network.pending_configured_hub_source,
        Some(hub_b.id().clone())
    );
    assert_eq!(
        network.inbound_frame_byte_budgets.protected_sources(),
        Some(HashSet::from([hub_b.id().clone()]))
    );
    assert!(
        !network
            .inbound_frame_byte_budgets
            .protected_source_geometry_fits()
    );
    assert!(
        !network.retry_backoff.contains_key(hub_a.id()),
        "staging B retires the stale A redial state"
    );
    network.peer_terminated(Terminated {
        peer: Some(hub_b.clone()),
        conn_id: first_b_conn_id,
    });
    assert!(network.retry_backoff.contains_key(hub_b.id()));
    let replayed_a_conn_id = 3_114;
    reserve_test_incoming(&mut network, replayed_a_conn_id);
    connect_test_peer!(network, hub_a, replayed_a_conn_id, 1, Hub => replayed_a_receivers, mut replayed_a_receiver);
    assert!(replayed_a_receivers.termination_requested());
    assert!(matches!(
        replayed_a_receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    assert_eq!(
        network.pending_configured_hub_source,
        Some(hub_b.id().clone())
    );
    assert_eq!(
        network.inbound_frame_byte_budgets.protected_sources(),
        Some(HashSet::from([hub_b.id().clone()]))
    );
    assert!(!network.peers.contains_key(hub_a.id()));
    network.peer_terminated(Terminated {
        peer: Some(hub_a.clone()),
        conn_id: replayed_a_conn_id,
    });
    assert!(
        !network.retry_backoff.contains_key(hub_a.id()),
        "an obsolete authenticated A replay cannot recreate A's redial state"
    );
    drop(retained_hub_a_route);
    assert!(
        network
            .inbound_frame_byte_budgets
            .protected_source_geometry_fits()
    );
    let second_b_conn_id = 3_113;
    reserve_test_incoming(&mut network, second_b_conn_id);
    connect_test_peer!(network, hub_b, second_b_conn_id, 1, Hub => second_b_receivers, mut second_b_receiver);
    assert!(second_b_receiver.try_recv().is_ok());
    assert!(!second_b_receivers.termination_requested());
    assert_eq!(network.pending_configured_hub_source, None);
    assert_eq!(network.relay_hub_peer, Some(hub_b.id().clone()));
    assert_eq!(
        network.current_topology,
        HashSet::from([hub_b.id().clone()])
    );
    assert_eq!(network.peers[hub_b.id()].conn_id, second_b_conn_id);
    assert!(
        network
            .inbound_frame_byte_budgets
            .protected_source_geometry_fits()
    );
}
#[test]
fn peer_capability_snapshot_replaces_prior_state() {
    let_test_network!(network);
    let omitted_peer = random_peer_id();
    let retained_peer = random_peer_id();
    let outside_topology = random_peer_id();
    let self_id = network.self_id.clone();
    network.current_topology = HashSet::from([omitted_peer.clone(), retained_peer.clone()]);
    network.peer_capabilities.insert(
        omitted_peer.clone(),
        message::PeerTransportCapabilities {
            scion_supported: true,
        },
    );
    network.peer_capabilities.insert(
        retained_peer.clone(),
        message::PeerTransportCapabilities {
            scion_supported: false,
        },
    );
    network.set_peer_capabilities(message::UpdatePeerCapabilities(vec![
        (
            retained_peer.clone(),
            message::PeerTransportCapabilities {
                scion_supported: true,
            },
        ),
        (
            outside_topology.clone(),
            message::PeerTransportCapabilities {
                scion_supported: true,
            },
        ),
        (
            self_id,
            message::PeerTransportCapabilities {
                scion_supported: true,
            },
        ),
    ]));
    assert_eq!(
        network.peer_capabilities,
        HashMap::from([
            (
                retained_peer,
                message::PeerTransportCapabilities {
                    scion_supported: true,
                },
            ),
            (
                outside_topology.clone(),
                message::PeerTransportCapabilities {
                    scion_supported: true,
                },
            ),
        ])
    );
    assert!(!network.peer_capabilities.contains_key(&omitted_peer));
    assert!(network.peer_capabilities.contains_key(&outside_topology));
    network.set_peer_capabilities(message::UpdatePeerCapabilities(Vec::new()));
    assert!(network.peer_capabilities.is_empty());
}
#[test]
fn peer_capability_snapshot_is_independent_of_topology_order() {
    let Some(mut caps_first) = bare_network() else {
        return;
    };
    let Some(mut topology_first) = bare_network() else {
        return;
    };
    let peer_id = random_peer_id();
    let capabilities = message::PeerTransportCapabilities {
        scion_supported: true,
    };
    let caps_update = || message::UpdatePeerCapabilities(vec![(peer_id.clone(), capabilities)]);
    let topology_update = || message::UpdateTopology(HashSet::from([peer_id.clone()]));
    caps_first.set_peer_capabilities(caps_update());
    caps_first.set_current_topology(topology_update());
    topology_first.set_current_topology(topology_update());
    topology_first.set_peer_capabilities(caps_update());
    let expected = HashMap::from([(peer_id.clone(), capabilities)]);
    assert_eq!(caps_first.peer_capabilities, expected);
    assert_eq!(topology_first.peer_capabilities, expected);
    caps_first.set_current_topology(message::UpdateTopology(HashSet::new()));
    assert_eq!(
        caps_first.peer_capabilities, expected,
        "an independently ordered topology snapshot must not erase the latest capability snapshot"
    );
}
#[test]
fn empty_topology_does_not_add_trusted_observers() {
    let_test_network!(network);
    let trusted_id = random_peer_id();
    let mut trusted = HashSet::new();
    trusted.insert(trusted_id);
    network.peer_reputations.set_trusted(&trusted);
    network.set_current_topology(UpdateTopology(HashSet::new()));
    assert!(
        network.current_topology.is_empty(),
        "empty topology updates should remain empty even with trusted observers"
    );
}
#[test]
fn process_pending_connects_respects_startup_delay() {
    let_test_network!(network);
    let peer_id = random_peer_id();
    let addr = socket_addr!(127.0.0.1:45678);
    let delay_until = tokio::time::Instant::now() + Duration::from_secs(5);
    network.connect_startup_delay_until = delay_until;
    network.current_topology.insert(peer_id.clone());
    network
        .pending_connects
        .push((tokio::time::Instant::now(), Peer::new(addr, peer_id)));
    network.process_pending_connects();
    assert!(
        network.connecting_peers.is_empty(),
        "startup delay should prevent immediate dial attempts"
    );
    assert_eq!(
        network.pending_connects.len(),
        1,
        "connect attempt should be rescheduled"
    );
    assert!(
        network.pending_connects[0].0 >= delay_until,
        "rescheduled connect should honor startup delay"
    );
}
#[test]
fn authenticated_session_cancels_obsolete_standby_attempt_without_reschedule_loop() {
    let_test_network!(network);
    let peer_id = random_peer_id();
    let addr = socket_addr!(127.0.0.1:45683);
    network.current_topology.insert(peer_id.clone());
    network
        .current_peers_addresses
        .push((peer_id.clone(), addr.clone()));
    let (handle, _receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(&mut network, peer_id.clone(), addr.clone(), 93, handle);
    network
        .pending_connects
        .push((tokio::time::Instant::now(), Peer::new(addr, peer_id)));
    network.process_pending_connects();
    assert!(network.pending_connects.is_empty());
    assert!(network.connecting_peers.is_empty());
}
#[tokio::test]
async fn reserved_hub_slot_allows_proof_beside_untrusted_inbound_incumbent() {
    let_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Assist;
    network.max_total_connections = Some(2);
    let hub = test_peer(socket_addr!(127.0.0.1:45686));
    network.relay_hub_addresses.push(hub.address().clone());
    network
        .current_peers_addresses
        .push((hub.id().clone(), hub.address().clone()));
    network.relay_hub_candidates.insert(hub.id().clone());
    let (handle, _receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(
        &mut network,
        hub.id().clone(),
        hub.address().clone(),
        94,
        handle,
    );
    network
        .pending_connects
        .push((tokio::time::Instant::now(), hub.clone()));
    assert!(network.reserves_relay_hub_slot());

    network.process_pending_connects();

    assert!(network.pending_connects.is_empty());
    assert!(network.exceeds_caps());
    assert!(
        network.connecting_peers.values().any(|candidate| {
            candidate.id() == hub.id() && candidate.address() == hub.address()
        })
    );
    assert!(network.outbound_connections.iter().any(|connection_id| {
        network
            .connecting_peers
            .get(connection_id)
            .is_some_and(|candidate| candidate == &hub)
    }));
}
#[test]
fn physically_saturated_cap_retains_unproven_hub_proof_for_retry() {
    let_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Assist;
    network.max_total_connections = Some(1);
    let hub = test_peer(socket_addr!(127.0.0.1:45687));
    network.relay_hub_addresses.push(hub.address().clone());
    network
        .current_peers_addresses
        .push((hub.id().clone(), hub.address().clone()));
    network.relay_hub_candidates.insert(hub.id().clone());
    let (handle, _receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(
        &mut network,
        hub.id().clone(),
        hub.address().clone(),
        95,
        handle,
    );
    network
        .pending_connects
        .push((tokio::time::Instant::now(), hub.clone()));

    network.process_pending_connects();

    assert!(network.connecting_peers.is_empty());
    assert!(network.pending_connects.iter().any(|(_, candidate)| {
        candidate.id() == hub.id() && candidate.address() == hub.address()
    }));
}
#[test]
fn configured_hub_reserves_single_slot_before_candidate_discovery() {
    let_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Assist;
    network.max_total_connections = Some(1);
    network
        .relay_hub_addresses
        .push(socket_addr!(127.0.0.1:45688));
    assert!(network.reserves_relay_hub_slot());
    assert!(network.exceeds_ordinary_connection_cap());

    let conn_id = 96;
    let (reply, mut response) = tokio::sync::oneshot::channel();
    network.handle_service_message(ServiceMessage::InboundAsk {
        conn_id,
        remote_addr: "127.0.0.1:45689".parse().expect("remote address"),
        reply,
    });
    assert!(!response.try_recv().expect("admission response"));
    assert!(!network.incoming_pending.contains(&conn_id));

    let ordinary = test_peer(socket_addr!(127.0.0.1:45690));
    network.current_topology.insert(ordinary.id().clone());
    network
        .current_peers_addresses
        .push((ordinary.id().clone(), ordinary.address().clone()));
    network
        .pending_connects
        .push((tokio::time::Instant::now(), ordinary.clone()));
    network.process_pending_connects();
    assert!(network.connecting_peers.is_empty());
    assert!(network.pending_connects.iter().any(|(_, candidate)| {
        candidate.id() == ordinary.id() && candidate.address() == ordinary.address()
    }));
}
#[tokio::test]
async fn exact_hub_dial_spends_reserved_single_slot() {
    let_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
    network.max_total_connections = Some(1);
    let hub = test_peer(socket_addr!(127.0.0.1:45691));
    network.relay_hub_addresses.push(hub.address().clone());
    network
        .current_peers_addresses
        .push((hub.id().clone(), hub.address().clone()));
    network.relay_hub_candidates.insert(hub.id().clone());
    let wrong_address = Peer::new(socket_addr!(127.0.0.1:45692), hub.id().clone());
    assert!(network.is_exact_relay_hub_dial_target(&hub));
    assert!(!network.is_exact_relay_hub_dial_target(&wrong_address));
    network
        .pending_connects
        .push((tokio::time::Instant::now(), hub.clone()));

    network.process_pending_connects();

    assert!(network.exceeds_caps());
    assert!(!network.reserves_relay_hub_slot());
    assert!(
        network
            .connecting_peers
            .values()
            .any(|candidate| candidate == &hub)
    );
    assert!(network.outbound_connections.iter().any(|connection_id| {
        network
            .connecting_peers
            .get(connection_id)
            .is_some_and(|candidate| candidate == &hub)
    }));
}
#[test]
fn only_authenticated_or_exact_outbound_hub_occupies_reservation() {
    let_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Assist;
    let hub = test_peer(socket_addr!(127.0.0.1:45693));
    network.relay_hub_addresses.push(hub.address().clone());
    network
        .current_peers_addresses
        .push((hub.id().clone(), hub.address().clone()));
    network.relay_hub_candidates.insert(hub.id().clone());
    let (handle, _receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(
        &mut network,
        hub.id().clone(),
        hub.address().clone(),
        97,
        handle,
    );
    network
        .peers
        .get_mut(hub.id())
        .expect("inserted peer")
        .relay_role = RelayRole::Hub;
    assert!(network.reserves_relay_hub_slot());

    network.relay_trusted_peers.insert(hub.id().clone());
    assert!(!network.reserves_relay_hub_slot());
    network.relay_trusted_peers.clear();
    network.peers.clear();
    network.connecting_peers.insert(98, hub.clone());
    assert!(network.reserves_relay_hub_slot());
    network.outbound_connections.insert(98);
    assert!(!network.reserves_relay_hub_slot());
}
#[test]
fn process_pending_connects_never_exceeds_the_total_inflight_cap() {
    let_test_network!(network);
    network.max_total_connections = Some(1);
    let occupied = Peer::new(socket_addr!(127.0.0.1:45679), random_peer_id());
    network.connecting_peers.insert(91, occupied);
    let due = Peer::new(socket_addr!(127.0.0.1:45680), random_peer_id());
    network.current_topology.insert(due.id().clone());
    network
        .current_peers_addresses
        .push((due.id().clone(), due.address().clone()));
    network
        .pending_connects
        .push((tokio::time::Instant::now(), due.clone()));
    network.process_pending_connects();
    assert_eq!(
        network.connecting_peers.len(),
        1,
        "a due outbound dial must not create a second in-flight connection"
    );
    assert!(
        network
            .pending_connects
            .iter()
            .any(|(_, pending)| { pending.id() == due.id() && pending.address() == due.address() }),
        "the capped dial must remain fairly scheduled for a later free slot"
    );
}
#[test]
fn process_pending_connects_rejects_a_revoked_exact_address() {
    let_test_network!(network);
    let peer_id = random_peer_id();
    let old_addr = socket_addr!(127.0.0.1:45684);
    let replacement_addr = socket_addr!(127.0.0.1:45685);
    network.current_topology.insert(peer_id.clone());
    network
        .current_peers_addresses
        .push((peer_id.clone(), replacement_addr));
    network.pending_connects.push((
        tokio::time::Instant::now(),
        Peer::new(old_addr.clone(), peer_id),
    ));
    network.retry_backoff.insert(
        network.pending_connects[0].1.id().clone(),
        HashMap::from([(
            old_addr.to_string(),
            (tokio::time::Instant::now(), Duration::from_millis(250)),
        )]),
    );

    network.process_pending_connects();

    assert!(network.pending_connects.is_empty());
    assert!(
        network.connecting_peers.is_empty(),
        "a due retry cannot dial an address absent from the current authority snapshot"
    );
    assert!(network.outbound_connections.is_empty());
    assert!(
        network.retry_backoff.is_empty(),
        "execution-time revocation must also clear stale per-address backoff"
    );
}
#[test]
fn immediate_reconnect_respects_the_total_inflight_cap_and_stays_scheduled() {
    let_test_network!(network);
    network.max_total_connections = Some(1);
    let occupied = Peer::new(socket_addr!(127.0.0.1:45681), random_peer_id());
    network.connecting_peers.insert(92, occupied);
    let target_id = random_peer_id();
    let target_addr = socket_addr!(127.0.0.1:45682);
    network.current_topology.insert(target_id.clone());
    network
        .current_peers_addresses
        .push((target_id.clone(), target_addr.clone()));
    assert!(network.trigger_reconnect_for_peer(&target_id));
    assert_eq!(
        network.connecting_peers.len(),
        1,
        "a missing-session reconnect must not bypass the total cap"
    );
    assert!(network.is_scheduled(&target_id, &target_addr));
}
#[test]
fn deferred_queue_preserves_order_and_connection_bindings() {
    let_deferred_queue_clock!(peer_id, now);
    let mut queue = DeferredPeerFrameQueue::<DummyMsg>::new(8, usize::MAX, Duration::from_secs(1));
    let frame_one = direct_frame!(peer_id.clone(), peer_id, DummyMsg,);
    let frame_two = direct_frame!(peer_id.clone(), peer_id, DummyMsg,);
    let frame_three = direct_frame!(peer_id.clone(), peer_id, DummyMsg,);
    let outcome_one = defer_frame!(queue, peer_id, frame_one, Other, Some(11), now);
    let outcome_two = defer_frame!(queue, peer_id, frame_two, Other, Some(12), now, 1);
    let outcome_three = defer_frame!(queue, peer_id, frame_three, Other, None, now, 2);
    let accepted = DeferredEnqueueOutcome {
        expired: 0,
        overflow: 0,
        enqueued: true,
    };
    assert_eq!(outcome_one, accepted);
    assert_eq!(outcome_two, accepted);
    assert_eq!(outcome_three, accepted);
    let (queued, expired) = queue.take_peer(&peer_id, now + Duration::from_millis(3));
    assert_eq!(expired, 0);
    let observed_connection_bindings: Vec<Option<ConnectionId>> = queued
        .iter()
        .map(|entry| entry.bound_connection_id)
        .collect();
    assert_eq!(observed_connection_bindings, vec![Some(11), Some(12), None]);
}
#[test]
fn deferred_wire_counting_distinguishes_exact_maximum_from_failure() {
    assert_eq!(
        admitted_deferred_wire_bytes(Ok(usize::MAX), usize::MAX),
        Some(usize::MAX),
        "an exact representable maximum is not an error sentinel"
    );
    assert_eq!(
        admitted_deferred_wire_bytes(Err(ncore::Error::LengthMismatch), usize::MAX),
        None,
        "counting failure must be rejected even at maximum configuration"
    );
    assert_eq!(
        admitted_deferred_wire_bytes(Ok(usize::MAX), usize::MAX - 1),
        None,
        "a successfully counted oversized frame is rejected"
    );
}
#[test]
fn deferred_progress_never_displaces_safety_and_still_preserves_fifo_rank() {
    let_deferred_queue_clock!(peer_id, now);
    let mut queue = DeferredPeerFrameQueue::<RouteMsg>::new(1, usize::MAX, Duration::from_secs(1));
    let frame = || direct_frame!(peer_id.clone(), peer_id, RouteMsg::Lane,);
    let _ = defer_frame!(queue, peer_id, frame(), ConsensusSafety, Some(100), now);
    for connection_id in 1..=8 {
        let outcome = defer_frame!(
            queue,
            peer_id,
            frame(),
            Consensus,
            Some(connection_id),
            now,
            connection_id
        );
        assert!(
            !outcome.enqueued,
            "ordinary progress must never discard an already admitted safety witness"
        );
    }
    let (queued, expired) = queue.take_peer(&peer_id, now + Duration::from_millis(20));
    assert_eq!(expired, 0);
    let observed: Vec<_> = queued
        .iter()
        .map(|entry| entry.bound_connection_id)
        .collect();
    assert_eq!(observed, vec![Some(100)]);
    for connection_id in 1..=8 {
        let outcome = defer_frame!(
            queue,
            peer_id,
            frame(),
            Consensus,
            Some(connection_id),
            now,
            20 + connection_id
        );
        assert_eq!(
            outcome.enqueued,
            connection_id == 1,
            "later progress cannot evict its admitted FIFO predecessor"
        );
    }
    assert_eq!(queue.by_peer[&peer_id].len(), 1);
    assert_eq!(
        queue.by_peer[&peer_id]
            .front()
            .map(|entry| entry.bound_connection_id),
        Some(Some(1))
    );
}
#[test]
fn deferred_bulk_flood_reserves_lane_and_safety_count_slots() {
    let_deferred_queue_clock!(peer_id, now);
    let mut queue = DeferredPeerFrameQueue::<RouteMsg>::new(6, usize::MAX, Duration::from_secs(1));
    let frame = || direct_frame!(peer_id.clone(), peer_id, RouteMsg::Lane,);
    let admitted_bulk = (0..64)
        .filter(|connection_id| {
            defer_frame!(
                queue,
                peer_id,
                frame(),
                ConsensusChunk,
                Some(*connection_id),
                now,
                *connection_id
            )
            .enqueued
        })
        .count();
    assert_eq!(admitted_bulk, 4);
    assert!(
        defer_frame!(queue, peer_id, frame(), Consensus, Some(100), now, 100).enqueued,
        "bulk progress must leave an isolated lane slot"
    );
    assert!(
        defer_frame!(
            queue,
            peer_id,
            frame(),
            ConsensusSafety,
            Some(101),
            now,
            101
        )
        .enqueued,
        "bulk progress must leave an isolated safety slot"
    );
}
#[test]
fn deferred_safety_cannot_borrow_the_ordinary_progress_reserve() {
    let_deferred_queue_clock!(peer_id, now);
    let frame = || direct_frame!(peer_id.clone(), peer_id, DummyMsg,);
    let wire_bytes = crate::peer::checked_data_message_wire_len(&frame())
        .expect("test frame wire length must be representable");
    let total_bytes = wire_bytes
        .checked_mul(2)
        .expect("two test frames must fit in usize");
    let mut queue = DeferredPeerFrameQueue::<DummyMsg>::new_with_total(
        4,
        usize::MAX,
        total_bytes,
        wire_bytes,
        0,
        Duration::from_secs(1),
    )
    .expect("test deferred geometry must be valid");
    assert!(defer_frame!(queue, peer_id, frame(), ConsensusSafety, Some(1), now, 1).enqueued);
    assert!(
        !defer_frame!(queue, peer_id, frame(), ConsensusSafety, Some(2), now, 2).enqueued,
        "safety must not borrow the disjoint ordinary progress reserve"
    );
    let progress = defer_frame!(queue, peer_id, frame(), BlockSync, Some(3), now, 3);
    assert!(progress.enqueued);
    assert_eq!(progress.overflow, 0);
    assert_eq!(queue.safety_by_peer[&peer_id].len(), 1);
    assert_eq!(queue.by_peer[&peer_id].len(), 1);
    assert_eq!(
        queue.safety_by_peer[&peer_id]
            .front()
            .map(|entry| entry.bound_connection_id),
        Some(Some(1)),
        "the admitted safety witness must coexist with ordinary progress"
    );
    assert_eq!(
        queue.by_peer[&peer_id]
            .front()
            .map(|entry| entry.bound_connection_id),
        Some(Some(3))
    );
}
#[test]
fn deferred_consensus_safety_displaces_only_non_progress_ordinary_work() {
    let_deferred_queue_clock!(peer_id, now);
    let mut queue = DeferredPeerFrameQueue::<DummyMsg>::new(1, usize::MAX, Duration::from_secs(1));
    let frame = || direct_frame!(peer_id.clone(), peer_id, DummyMsg,);
    assert!(defer_frame!(queue, peer_id, frame(), Other, Some(1), now).enqueued);
    let safety = defer_frame!(queue, peer_id, frame(), ConsensusSafety, Some(2), now, 1);
    assert!(safety.enqueued);
    assert_eq!(safety.overflow, 1);
    assert!(!queue.by_peer.contains_key(&peer_id));
    assert_eq!(queue.safety_by_peer[&peer_id].len(), 1);
    let (queued, expired) = queue.take_peer(&peer_id, now + Duration::from_millis(2));
    assert_eq!(expired, 0);
    assert_eq!(
        queued
            .iter()
            .map(|entry| entry.bound_connection_id)
            .collect::<Vec<_>>(),
        vec![Some(2)]
    );
}
#[test]
fn deferred_high_gossip_cannot_evict_a_safety_witness() {
    let_deferred_queue_clock!(peer_id, now);
    let mut queue = DeferredPeerFrameQueue::<DummyMsg>::new(1, usize::MAX, Duration::from_secs(1));
    let frame = || direct_frame!(peer_id.clone(), peer_id, DummyMsg,);
    assert!(defer_frame!(queue, peer_id, frame(), ConsensusSafety, Some(1), now).enqueued);
    assert!(
        !defer_frame!(queue, peer_id, frame(), TxGossip, Some(2), now, 1).enqueued,
        "caller-selected priority must not turn gossip into protected progress"
    );
    assert_eq!(
        queue.safety_by_peer[&peer_id]
            .front()
            .map(|entry| entry.bound_connection_id),
        Some(Some(1))
    );
}
#[test]
fn deferred_safety_service_rank_is_bounded_before_ordinary_progress() {
    let_deferred_queue_clock!(peer_id, now);
    let mut queue = DeferredPeerFrameQueue::<DummyMsg>::new(16, usize::MAX, Duration::from_secs(1));
    let frame = || direct_frame!(peer_id.clone(), peer_id, DummyMsg,);
    for generation in 1..=8 {
        assert!(
            defer_frame!(
                queue,
                peer_id,
                frame(),
                ConsensusSafety,
                Some(generation),
                now,
                generation
            )
            .enqueued
        );
    }
    assert!(defer_frame!(queue, peer_id, frame(), BlockSync, Some(99), now, 9).enqueued);
    let (mut ordered, expired) = queue.take_peer(&peer_id, now + Duration::from_millis(10));
    assert_eq!(expired, 0);
    assert_eq!(
        ordered[DEFERRED_SAFETY_BURST_MAX as usize].bound_connection_id,
        Some(99)
    );
    // Persisting the exact debt across a backpressured flush makes the
    // ordinary witness first on the next attempt; a new safety arrival
    // cannot reset its rank.
    for _ in 0..DEFERRED_SAFETY_BURST_MAX {
        let served = ordered.pop_front().expect("bounded safety predecessor");
        assert!(matches!(served.topic, message::Topic::ConsensusSafety));
        queue.note_served(&peer_id, message::Topic::ConsensusSafety);
    }
    queue.restore_peer(peer_id.clone(), ordered);
    let (ordered_again, _) = queue.take_peer(&peer_id, now + Duration::from_millis(11));
    assert_eq!(
        ordered_again
            .front()
            .and_then(|entry| entry.bound_connection_id),
        Some(99)
    );
}
#[test]
fn topology_removal_cancels_every_deferred_owner_for_removed_peer() {
    let_deferred_test_network!(network);
    let retained_peer = random_peer_id();
    let removed_peer = random_peer_id();
    let origin = network.self_id.clone();
    let frame_for = |peer_id: &PeerId| direct_frame!(origin.clone(), peer_id, DummyMsg,);
    let now = tokio::time::Instant::now();
    let _ = defer_frame!(
        network.deferred_send_queue,
        retained_peer,
        frame_for(&retained_peer),
        Other,
        None,
        now
    );
    let _ = defer_frame!(
        network.deferred_send_queue,
        removed_peer,
        frame_for(&removed_peer),
        Other,
        None,
        now
    );
    let _ = defer_frame!(
        network.deferred_send_queue,
        removed_peer,
        frame_for(&removed_peer),
        ConsensusSafety,
        None,
        now
    );
    network.set_current_topology(UpdateTopology(HashSet::from([retained_peer.clone()])));
    assert!(
        network
            .deferred_send_queue
            .by_peer
            .contains_key(&retained_peer)
    );
    assert!(
        !network
            .deferred_send_queue
            .by_peer
            .contains_key(&removed_peer)
    );
    assert!(
        !network
            .deferred_send_queue
            .safety_by_peer
            .contains_key(&removed_peer),
        "explicit topology removal is the cancellation witness for progress owned by that target"
    );
    let retained_bytes = DeferredPeerFrameQueue::retained_wire_bytes(
        &network.deferred_send_queue.by_peer[&retained_peer],
    )
    .expect("retained topology queue bytes");
    let aggregate = &network.deferred_send_queue.aggregate_budget;
    assert_eq!(aggregate.retained_total(), retained_bytes);
    assert_eq!(aggregate.retained_ordinary(), retained_bytes);
}
#[test]
fn deferred_queue_ttl_and_cap_drop_oldest_deterministically() {
    let_deferred_queue_clock!(peer_id, now);
    let mut queue =
        DeferredPeerFrameQueue::<DummyMsg>::new(2, usize::MAX, Duration::from_millis(5));
    let mk_frame = || direct_frame!(peer_id.clone(), peer_id, DummyMsg,);
    let outcome_one = defer_frame!(queue, peer_id, mk_frame(), Other, Some(1), now);
    let outcome_two = defer_frame!(queue, peer_id, mk_frame(), Other, Some(2), now, 1);
    let outcome_three = defer_frame!(queue, peer_id, mk_frame(), Other, Some(3), now, 2);
    assert_eq!(outcome_one.overflow, 0);
    assert_eq!(outcome_two.overflow, 0);
    assert_eq!(
        outcome_three.overflow, 1,
        "queue cap should evict oldest entry"
    );
    let (queued_before_ttl, expired_before_ttl) =
        queue.take_peer(&peer_id, now + Duration::from_millis(3));
    assert_eq!(expired_before_ttl, 0);
    let kept_connection_bindings: Vec<Option<ConnectionId>> = queued_before_ttl
        .iter()
        .map(|entry| entry.bound_connection_id)
        .collect();
    assert_eq!(kept_connection_bindings, vec![Some(2), Some(3)]);
    let mut ttl_queue =
        DeferredPeerFrameQueue::<DummyMsg>::new(2, usize::MAX, Duration::from_millis(5));
    let _ = defer_frame!(ttl_queue, peer_id, mk_frame(), Other, Some(9), now);
    let (queued_after_ttl, expired_after_ttl) =
        ttl_queue.take_peer(&peer_id, now + Duration::from_millis(20));
    assert_eq!(queued_after_ttl.len(), 0);
    assert_eq!(
        expired_after_ttl, 1,
        "expired entries should be dropped on flush"
    );
}
#[test]
fn deferred_progress_survives_ttl_but_explicit_peer_removal_cancels_it() {
    let_deferred_queue_clock!(peer_id, now);
    let mut queue =
        DeferredPeerFrameQueue::<RouteMsg>::new(3, usize::MAX, Duration::from_millis(5));
    let frame = direct_frame!(peer_id.clone(), peer_id, RouteMsg::Lane,);
    assert!(defer_frame!(queue, peer_id, frame, Consensus, Some(7), now).enqueued);
    let (retained, expired) = queue.take_peer(&peer_id, now + Duration::from_secs(60));
    assert_eq!(expired, 0);
    assert_eq!(retained.len(), 1);
    assert_eq!(
        retained.front().and_then(|entry| entry.bound_connection_id),
        Some(7)
    );
    queue.restore_peer(peer_id.clone(), retained);
    assert_eq!(queue.remove_peer(&peer_id), 1);
    let (cancelled, expired) = queue.take_peer(&peer_id, now + Duration::from_secs(61));
    assert_eq!(expired, 0);
    assert!(cancelled.is_empty());
}
#[test]
fn deferred_queue_byte_cap_drops_oldest_and_rejects_oversized_newest() {
    let_deferred_queue_clock!(peer_id, now);
    let mk_frame = |body_len: usize| direct_frame!(peer_id.clone(), peer_id, vec![7; body_len],);
    let sample_frame = mk_frame(32);
    let sample_bytes = crate::frame_queue_charge(crate::peer::data_message_wire_len(&sample_frame))
        .expect("deferred fixture stream charge");
    let mut queue = DeferredPeerFrameQueue::<Vec<u8>>::new(
        8,
        sample_bytes.saturating_mul(2),
        Duration::from_secs(1),
    );
    let outcome_one = defer_frame!(queue, peer_id, sample_frame, Other, Some(1), now);
    let outcome_two = defer_frame!(queue, peer_id, mk_frame(32), Other, Some(2), now, 1);
    let outcome_three = defer_frame!(queue, peer_id, mk_frame(32), Other, Some(3), now, 2);
    assert_eq!(outcome_one.overflow, 0);
    assert_eq!(outcome_two.overflow, 0);
    assert_eq!(
        outcome_three.overflow, 1,
        "byte cap should evict the oldest queued frame"
    );
    let (queued, expired) = queue.take_peer(&peer_id, now + Duration::from_millis(3));
    assert_eq!(expired, 0);
    let kept_connection_bindings: Vec<Option<ConnectionId>> = queued
        .iter()
        .map(|entry| entry.bound_connection_id)
        .collect();
    assert_eq!(kept_connection_bindings, vec![Some(2), Some(3)]);
    assert!(
        DeferredPeerFrameQueue::retained_wire_bytes(&queued)
            .is_some_and(|retained| retained <= sample_bytes.saturating_mul(2)),
        "retained bytes should stay within the configured cap"
    );
    let mut oversized_queue =
        DeferredPeerFrameQueue::<Vec<u8>>::new(8, sample_bytes, Duration::from_secs(1));
    let _ = defer_frame!(oversized_queue, peer_id, mk_frame(32), Other, Some(7), now);
    let large_frame = mk_frame(1024);
    let large_bytes = crate::frame_queue_charge(crate::peer::data_message_wire_len(&large_frame))
        .expect("large deferred fixture stream charge");
    assert!(
        large_bytes > sample_bytes,
        "test must exercise a single frame larger than the byte cap"
    );
    let oversized_outcome = defer_frame!(
        oversized_queue,
        peer_id,
        large_frame,
        Other,
        Some(8),
        now,
        1
    );
    assert_eq!(
        oversized_outcome,
        DeferredEnqueueOutcome {
            expired: 0,
            overflow: 1,
            enqueued: false,
        },
        "a frame larger than the byte cap must be rejected"
    );
    let (oversized_queued, oversized_expired) =
        oversized_queue.take_peer(&peer_id, now + Duration::from_millis(2));
    assert_eq!(oversized_expired, 0);
    assert_eq!(oversized_queued.len(), 1);
    assert_eq!(oversized_queued[0].bound_connection_id, Some(7));
    assert!(oversized_queued[0].wire_bytes <= sample_bytes);
    let fresh_peer = random_peer_id();
    let fresh_outcome = defer_frame!(
        oversized_queue,
        fresh_peer,
        mk_frame(1024),
        ConsensusSafety,
        None,
        now,
        3
    );
    assert!(!fresh_outcome.enqueued);
    assert!(
        !oversized_queue.safety_by_peer.contains_key(&fresh_peer),
        "rejecting an oversized safety frame must not allocate peer queue state"
    );
}
#[test]
fn deferred_safety_and_progress_share_one_exact_peer_cap_without_eviction() {
    let_deferred_queue_clock!(peer_id, now);
    let frame = || direct_frame!(peer_id.clone(), peer_id, DummyMsg,);
    let frame_bytes = crate::frame_queue_charge(
        crate::peer::checked_data_message_wire_len(&frame()).expect("count deferred-frame fixture"),
    )
    .expect("deferred fixture stream charge");
    let byte_cap = frame_bytes.checked_mul(2).expect("small fixture cap");
    let mut queue = DeferredPeerFrameQueue::<DummyMsg>::new(8, byte_cap, Duration::from_secs(1));
    assert!(defer_frame!(queue, peer_id, frame(), ConsensusSafety, Some(1), now).enqueued);
    assert!(defer_frame!(queue, peer_id, frame(), BlockSync, Some(2), now, 1).enqueued);
    let replacement = defer_frame!(queue, peer_id, frame(), BlockSync, Some(3), now, 2);
    assert!(!replacement.enqueued);
    assert_eq!(replacement.overflow, 1);
    assert_eq!(queue.safety_by_peer[&peer_id].len(), 1);
    assert_eq!(queue.by_peer[&peer_id].len(), 1);
    let safety_replacement =
        defer_frame!(queue, peer_id, frame(), ConsensusSafety, Some(4), now, 3);
    assert!(!safety_replacement.enqueued);
    assert_eq!(safety_replacement.overflow, 1);
    assert_eq!(queue.by_peer[&peer_id].len(), 1);
    assert_eq!(queue.safety_by_peer[&peer_id].len(), 1);
    let (queued, expired) = queue.take_peer(&peer_id, now + Duration::from_millis(4));
    assert_eq!(expired, 0);
    assert_eq!(
        DeferredPeerFrameQueue::retained_wire_bytes(&queued),
        Some(byte_cap)
    );
    assert_eq!(
        queued
            .iter()
            .map(|entry| entry.bound_connection_id)
            .collect::<Vec<_>>(),
        vec![Some(1), Some(2)]
    );
}
#[test]
fn deferred_total_cap_rejects_cross_peer_ordinary_overflow_without_eviction() {
    let _guard = deferred_send_test_guard();
    let peers: Vec<_> = (0..3).map(|_| random_peer_id()).collect();
    let origin = random_peer_id();
    let target = peers[0].clone();
    let frame = || direct_frame!(origin.clone(), target, DummyMsg,);
    let frame_bytes = crate::frame_queue_charge(
        crate::peer::checked_data_message_wire_len(&frame()).expect("count deferred fixture"),
    )
    .expect("deferred stream charge");
    let total = frame_bytes.checked_mul(2).expect("small fixture total");
    let mut queue = DeferredPeerFrameQueue::<DummyMsg>::new_with_total(
        8,
        usize::MAX,
        total,
        0,
        crate::frame_queue_charge(0).expect("default frame overhead"),
        Duration::from_secs(1),
    )
    .expect("valid aggregate deferred geometry");
    let now = tokio::time::Instant::now();
    for (index, peer) in peers[..2].iter().enumerate() {
        let outcome = defer_frame!(
            queue,
            peer,
            frame(),
            Other,
            Some(u64::try_from(index).expect("small index")),
            now,
            u64::try_from(index).expect("small index")
        );
        assert!(outcome.enqueued);
        assert_eq!(outcome.overflow, 0);
    }
    let overflow = defer_frame!(queue, peers[2], frame(), Other, Some(2), now, 2);
    assert_eq!(
        overflow,
        DeferredEnqueueOutcome {
            expired: 0,
            overflow: 1,
            enqueued: false,
        }
    );
    assert!(queue.by_peer.contains_key(&peers[0]));
    assert!(queue.by_peer.contains_key(&peers[1]));
    assert!(!queue.by_peer.contains_key(&peers[2]));
    assert_eq!(queue.aggregate_budget.retained_total(), total);
    assert_eq!(queue.aggregate_budget.retained_ordinary(), total);
}
#[test]
fn deferred_total_safety_reserve_is_additive_and_disjoint_from_progress() {
    let _guard = deferred_send_test_guard();
    let peers: Vec<_> = (0..7).map(|_| random_peer_id()).collect();
    let origin = random_peer_id();
    let target = peers[0].clone();
    let frame = || direct_frame!(origin.clone(), target, DummyMsg,);
    let frame_bytes = crate::frame_queue_charge(
        crate::peer::checked_data_message_wire_len(&frame()).expect("count deferred fixture"),
    )
    .expect("deferred stream charge");
    let total = frame_bytes.checked_mul(3).expect("small fixture total");
    let mut queue = DeferredPeerFrameQueue::<DummyMsg>::new_with_total(
        8,
        usize::MAX,
        total,
        frame_bytes,
        crate::frame_queue_charge(0).expect("default frame overhead"),
        Duration::from_secs(1),
    )
    .expect("valid aggregate deferred geometry");
    let now = tokio::time::Instant::now();
    let enqueue =
        |queue: &mut DeferredPeerFrameQueue<DummyMsg>, peer_index: usize, topic: message::Topic| {
            queue.enqueue(
                peers[peer_index].clone(),
                frame(),
                topic,
                Some(u64::try_from(peer_index).expect("small peer index")),
                now + Duration::from_millis(u64::try_from(peer_index).expect("small peer index")),
            )
        };
    assert!(enqueue(&mut queue, 0, message::Topic::BlockSync).enqueued);
    assert!(enqueue(&mut queue, 1, message::Topic::BlockSync).enqueued);
    let third_ordinary = enqueue(&mut queue, 2, message::Topic::BlockSync);
    assert!(!third_ordinary.enqueued);
    assert_eq!(third_ordinary.overflow, 1);
    assert!(queue.by_peer.contains_key(&peers[0]));
    assert!(queue.by_peer.contains_key(&peers[1]));
    assert!(!queue.by_peer.contains_key(&peers[2]));
    assert!(
        enqueue(&mut queue, 3, message::Topic::ConsensusSafety).enqueued,
        "safety must use the additive reserve without evicting ordinary ownership"
    );
    let second_safety = enqueue(&mut queue, 4, message::Topic::ConsensusSafety);
    assert!(!second_safety.enqueued);
    assert_eq!(second_safety.overflow, 1);
    assert!(queue.by_peer.contains_key(&peers[0]));
    assert!(queue.by_peer.contains_key(&peers[1]));
    assert!(
        queue.safety_by_peer.contains_key(&peers[3]),
        "new safety work must not discard an already admitted safety witness"
    );
    for peer in &peers[4..=6] {
        assert!(!queue.safety_by_peer.contains_key(peer));
    }
    assert_eq!(queue.aggregate_budget.retained_total(), total);
    assert_eq!(queue.aggregate_budget.retained_ordinary(), frame_bytes * 2);
}
#[test]
fn deferred_aggregate_lease_survives_take_restore_and_releases_on_ttl() {
    let _guard = deferred_send_test_guard();
    let peer = random_peer_id();
    let frame = direct_frame!(peer.clone(), peer, DummyMsg,);
    let frame_bytes = crate::frame_queue_charge(
        crate::peer::checked_data_message_wire_len(&frame).expect("count deferred fixture"),
    )
    .expect("deferred stream charge");
    let mut queue = DeferredPeerFrameQueue::<DummyMsg>::new_with_total(
        8,
        usize::MAX,
        frame_bytes,
        0,
        crate::frame_queue_charge(0).expect("default frame overhead"),
        Duration::from_millis(5),
    )
    .expect("valid aggregate deferred geometry");
    let now = tokio::time::Instant::now();
    assert!(defer_frame!(queue, peer, frame, Other, Some(7), now).enqueued);
    assert_eq!(queue.aggregate_budget.retained_total(), frame_bytes);
    let (taken, expired) = queue.take_peer(&peer, now + Duration::from_millis(1));
    assert_eq!(expired, 0);
    assert_eq!(queue.aggregate_budget.retained_total(), frame_bytes);
    queue.restore_peer(peer.clone(), taken);
    assert_eq!(queue.aggregate_budget.retained_total(), frame_bytes);
    let (expired_entries, expired) = queue.take_peer(&peer, now + Duration::from_millis(20));
    assert!(expired_entries.is_empty());
    assert_eq!(expired, 1);
    assert_eq!(queue.aggregate_budget.retained_total(), 0);
}
#[test]
fn missing_session_defers_frame_and_schedules_reconnect() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45679);
    network.current_topology.insert(peer_id.clone());
    network
        .current_peers_addresses
        .push((peer_id.clone(), peer_addr.clone()));
    let now = tokio::time::Instant::now();
    network.retry_backoff.insert(
        peer_id.clone(),
        HashMap::from([(
            peer_addr.to_string(),
            (now + Duration::from_secs(1), Duration::from_millis(25)),
        )]),
    );
    let deferred_before = deferred_send_enqueued_count();
    let reconnect_before = session_reconnect_total();
    let frame = direct_frame!(network.self_id.clone(), peer_id, DummyMsg,);
    assert!(
        network.send_frame_to_peer(&peer_id, frame, message::Topic::Other),
        "frame should be deferred when peer session is missing"
    );
    assert_eq!(
        network
            .deferred_send_queue
            .by_peer
            .get(&peer_id)
            .map(VecDeque::len),
        Some(1),
        "missing-session send should enqueue exactly one deferred frame"
    );
    assert!(
        !network.pending_connects.is_empty() || !network.connecting_peers.is_empty(),
        "missing-session defer should schedule reconnect work"
    );
    assert!(
        deferred_send_enqueued_count() >= deferred_before.saturating_add(1),
        "deferred send counter should increment"
    );
    assert!(
        session_reconnect_total() >= reconnect_before.saturating_add(1),
        "reconnect counter should increment"
    );
}
#[test]
fn unknown_peer_cannot_allocate_deferred_queue_state() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let frame = direct_frame!(network.self_id.clone(), peer_id, DummyMsg,);
    assert!(
        !network.send_frame_to_peer(&peer_id, frame, message::Topic::Other),
        "a target outside the admitted topology must be rejected"
    );
    assert!(!network.deferred_send_queue.by_peer.contains_key(&peer_id));
    assert!(
        !network
            .deferred_send_queue
            .safety_by_peer
            .contains_key(&peer_id)
    );
}
#[test]
fn outside_topology_retransmit_is_not_misreported_as_delivered() {
    let_test_network!(network, DeferredProgressMsg);
    let peer_id = random_peer_id();
    let frame = direct_frame!(
        network.self_id.clone(),
        peer_id,
        DeferredProgressMsg::Lane(1),
    );
    assert!(!network.send_frame_to_peer(&peer_id, frame, message::Topic::Consensus));
    assert!(!network.deferred_send_queue.by_peer.contains_key(&peer_id));
}
#[test]
fn missing_session_retains_unbound_consensus_frame_and_schedules_reconnect() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45681);
    network.current_topology.insert(peer_id.clone());
    network
        .current_peers_addresses
        .push((peer_id.clone(), peer_addr.clone()));
    let now = tokio::time::Instant::now();
    network.retry_backoff.insert(
        peer_id.clone(),
        HashMap::from([(
            peer_addr.to_string(),
            (now + Duration::from_secs(1), Duration::from_millis(25)),
        )]),
    );
    let deferred_before = deferred_send_enqueued_count();
    let reconnect_before = session_reconnect_total();
    let frame = direct_frame!(network.self_id.clone(), peer_id, DummyMsg,);
    assert!(
        network.send_frame_to_peer(&peer_id, frame, message::Topic::Consensus),
        "bounded admission should retain missing-session consensus progress"
    );
    let entries = network
        .deferred_send_queue
        .by_peer
        .get(&peer_id)
        .expect("missing-session consensus progress should be retained");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries.front().and_then(|entry| entry.bound_connection_id),
        None
    );
    assert_eq!(
        deferred_send_enqueued_count(),
        deferred_before.saturating_add(1),
        "retaining consensus progress should increment the deferred-send counter"
    );
    assert!(
        session_reconnect_total() >= reconnect_before.saturating_add(1),
        "missing-session consensus sends should schedule reconnect work"
    );
}
#[test]
fn missing_session_defers_consensus_but_not_control() {
    let_deferred_test_network!(network, RouteMsg);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45697);
    network.current_topology.insert(peer_id.clone());
    network
        .current_peers_addresses
        .push((peer_id.clone(), peer_addr.clone()));
    let now = tokio::time::Instant::now();
    network.retry_backoff.insert(
        peer_id.clone(),
        HashMap::from([(
            peer_addr.to_string(),
            (now + Duration::from_secs(1), Duration::from_millis(25)),
        )]),
    );
    let lane = direct_frame!(network.self_id.clone(), peer_id, RouteMsg::Lane,);
    assert!(
        network.send_frame_to_peer(&peer_id, lane, message::Topic::Consensus),
        "consensus traffic is reliable progress"
    );
    let control = direct_frame!(network.self_id.clone(), peer_id, RouteMsg::Control,);
    assert!(
        !network.send_frame_to_peer(&peer_id, control, message::Topic::Control),
        "general control must stay lossy when no authenticated session exists"
    );
    let entries = network
        .deferred_send_queue
        .by_peer
        .get(&peer_id)
        .expect("consensus frame should remain retained");
    assert_eq!(entries.len(), 1);
    assert!(matches!(
        entries.front().map(|entry| entry.frame.payload),
        Some(RouteMsg::Lane)
    ));
}
#[test]
fn actor_progress_bypasses_full_deferred_owner_and_waits_for_writer_flush() {
    let_deferred_test_network!(network, DeferredProgressMsg);
    network.deferred_send_queue =
        DeferredPeerFrameQueue::new(1, usize::MAX, Duration::from_secs(60));
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45698);
    network.current_topology.insert(peer_id.clone());
    network
        .current_peers_addresses
        .push((peer_id.clone(), peer_addr.clone()));
    let_deferred_peer!(mut receivers = &mut network; peer_id.clone(), peer_addr.clone(), 106);
    let now = tokio::time::Instant::now();
    network.retry_backoff.insert(
        peer_id.clone(),
        HashMap::from([(
            peer_addr.to_string(),
            (now + Duration::from_secs(1), Duration::from_millis(25)),
        )]),
    );
    let occupied = direct_frame!(
        network.self_id.clone(),
        peer_id,
        DeferredProgressMsg::Chunk(1),
    );
    assert!(
        defer_frame!(
            network.deferred_send_queue,
            peer_id,
            occupied,
            ConsensusChunk,
            None,
            now
        )
        .enqueued
    );
    let actor_budget = NetworkActorByteBudget::new(1, 0).expect("test actor owner");
    let actor_lease = actor_budget
        .try_reserve(1, false)
        .expect("reserve exact actor owner");
    let admitted = AdmittedNetworkMessage::new(
        NetworkMessage::Post(Post {
            data: DeferredProgressMsg::Lane(99),
            peer_id: peer_id.clone(),
            priority: Priority::High,
        }),
        actor_lease,
    );
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("peer mailbox admission must not retire actor ownership");
    assert_eq!(actor_budget.retained().total, 1);
    assert_eq!(
        network
            .deferred_send_queue
            .by_peer
            .get(&peer_id)
            .map_or(0, VecDeque::len),
        1,
        "actor-owned progress must not duplicate itself into deferred ownership"
    );
    assert_lane_flushed!(
        receivers,
        99,
        "synthetic writer must receive actor-owned progress"
    );
    assert!(
        network.dispatch_reliable_actor_message(retained).is_ok(),
        "only a successful writer flush may retire actor ownership"
    );
    assert_eq!(actor_budget.retained().total, 0);
}
#[tokio::test(start_paused = true)]
async fn reply_flush_ack_completes_only_after_peer_writer_flush() {
    let_test_network!(network, DeferredProgressMsg);
    network.reply_writer_flush_timeout = Duration::from_millis(10);
    let_reply_handle!(network, handle, progress_rx);
    let connection_id = 138;
    let (_delivery_peer, semantic_target, mut peer_receivers, tenure, route) =
        install_test_reply_route(
            &mut network,
            socket_addr!(127.0.0.1:45718),
            connection_id,
            32,
            47,
            true,
        );
    drop(tenure);
    admit_lane_reply!(handle, progress_rx => completion, admitted; 77, semantic_target, route);
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Pending);
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("peer-writer admission alone cannot complete the reply");
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Pending);
    tokio::time::advance(network.reply_writer_flush_timeout).await;
    assert_lane_flushed!(
        peer_receivers,
        77,
        "peer writer receives and flushes the exact reply"
    );
    assert_eq!(
        completion.poll(),
        NetworkReplyFlushAckStatus::Pending,
        "only the network actor may publish its observed writer flush"
    );
    assert!(
        network.dispatch_reliable_actor_message(retained).is_ok(),
        "a ready flush acknowledgement must win at the exact deadline"
    );
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Flushed);
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Flushed);
    assert!(route.is_reply_writable());
    assert!(!peer_receivers.termination_requested());
}
#[tokio::test(start_paused = true)]
async fn ready_exact_reply_flush_wins_route_retirement() {
    let_test_network!(network, DeferredProgressMsg);
    let_reply_handle!(network, handle, progress_rx);
    let connection_id = 145;
    let (_delivery_peer, semantic_target, mut peer_receivers, tenure, route) =
        install_test_reply_route(
            &mut network,
            socket_addr!(127.0.0.1:45725),
            connection_id,
            37,
            52,
            true,
        );
    admit_lane_reply!(handle, progress_rx => completion, admitted; 82, semantic_target, route);
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("peer-writer admission awaits completion");
    assert_lane_flushed!(
        peer_receivers,
        82,
        "old writer publishes the exact full-flush witness"
    );
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Pending);
    tenure.cancel();
    assert!(!route.is_active());
    assert!(
        network.dispatch_reliable_actor_message(retained).is_ok(),
        "an already-published exact flush must win route retirement"
    );
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Flushed);
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[tokio::test(start_paused = true)]
async fn ready_exact_reply_flush_wins_connection_replacement() {
    let_test_network!(network, DeferredProgressMsg);
    network.reply_writer_flush_timeout = Duration::from_millis(10);
    let_reply_handle!(network, handle, progress_rx);
    let old_connection_id = 146;
    let replacement_connection_id = 147;
    let (delivery_peer, semantic_target, mut old_receivers, tenure, route) =
        install_test_reply_route(
            &mut network,
            socket_addr!(127.0.0.1:45726),
            old_connection_id,
            38,
            53,
            true,
        );
    drop(tenure);
    admit_lane_reply!(handle, progress_rx => completion, admitted; 83, semantic_target, route);
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("old peer writer owns the exact occurrence");
    assert_lane_flushed!(
        old_receivers,
        83,
        "old writer publishes the exact full-flush witness"
    );
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Pending);
    let_deferred_peer!(replacement_receivers = &mut network; delivery_peer.clone(), socket_addr!(127.0.0.1:45727), replacement_connection_id);
    tokio::time::advance(network.reply_writer_flush_timeout).await;
    assert!(
        network.dispatch_reliable_actor_message(retained).is_ok(),
        "an already-published exact flush must win replacement and deadline observation"
    );
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Flushed);
    assert_eq!(
        network
            .peers
            .get(&delivery_peer)
            .expect("replacement remains current")
            .conn_id,
        replacement_connection_id
    );
    assert!(
        !network.expire_reply_writer_occurrence(&route, old_connection_id),
        "an obsolete timeout cannot terminate the replacement after flush"
    );
    assert!(!replacement_receivers.termination_requested());
    assert!(
        !network
            .terminating_connections
            .contains(&replacement_connection_id)
    );
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[tokio::test(start_paused = true)]
async fn terminal_fence_observes_deadline_flush_published_after_initial_poll() {
    let_test_network!(network, DeferredProgressMsg);
    network.reply_writer_flush_timeout = Duration::from_millis(10);
    let_reply_handle!(network, handle, progress_rx);
    let connection_id = 152;
    let (_delivery_peer, semantic_target, mut peer_receivers, tenure, route) =
        install_test_reply_route(
            &mut network,
            socket_addr!(127.0.0.1:45730),
            connection_id,
            40,
            55,
            true,
        );
    drop(tenure);
    admit_lane_reply!(handle, progress_rx => completion, admitted; 85, semantic_target, route);
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("peer-writer admission awaits completion");
    tokio::time::advance(network.reply_writer_flush_timeout).await;
    assert!(
        network
            .dispatch_reliable_actor_message_inner(retained, || {
                assert_lane_flushed!(
                    peer_receivers,
                    85,
                    "writer publishes after the optimistic poll"
                );
            })
            .is_ok(),
        "the terminal fence must observe a deadline-gap flush"
    );
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Flushed);
    assert!(route.is_reply_writable());
    assert!(!peer_receivers.termination_requested());
    assert!(!network.terminating_connections.contains(&connection_id));
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[tokio::test(start_paused = true)]
async fn terminal_fence_observes_replacement_flush_published_after_initial_poll() {
    let_test_network!(network, DeferredProgressMsg);
    let_reply_handle!(network, handle, progress_rx);
    let old_connection_id = 153;
    let replacement_connection_id = 154;
    let (delivery_peer, semantic_target, mut old_receivers, tenure, route) =
        install_test_reply_route(
            &mut network,
            socket_addr!(127.0.0.1:45731),
            old_connection_id,
            41,
            56,
            true,
        );
    drop(tenure);
    admit_lane_reply!(handle, progress_rx => completion, admitted; 86, semantic_target, route);
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("old peer writer owns the exact occurrence");
    let_deferred_peer!(replacement_receivers = &mut network; delivery_peer.clone(), socket_addr!(127.0.0.1:45732), replacement_connection_id);
    assert!(
        network
            .dispatch_reliable_actor_message_inner(retained, || {
                assert_lane_flushed!(consensus old_receivers, 86, "old writer publishes after the optimistic poll");
            })
            .is_ok(),
        "the terminal fence must observe a replacement-gap flush"
    );
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Flushed);
    assert!(route.is_reply_writable());
    assert_eq!(
        network
            .peers
            .get(&delivery_peer)
            .expect("replacement remains current")
            .conn_id,
        replacement_connection_id
    );
    assert!(!old_receivers.termination_requested());
    assert!(!replacement_receivers.termination_requested());
    assert!(
        !network
            .terminating_connections
            .contains(&replacement_connection_id)
    );
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[tokio::test(start_paused = true)]
async fn terminal_fence_observes_inactive_route_flush_published_after_initial_poll() {
    let_test_network!(network, DeferredProgressMsg);
    let_reply_handle!(network, handle, progress_rx);
    let connection_id = 155;
    let (_delivery_peer, semantic_target, mut peer_receivers, tenure, route) =
        install_test_reply_route(
            &mut network,
            socket_addr!(127.0.0.1:45733),
            connection_id,
            42,
            57,
            true,
        );
    admit_lane_reply!(handle, progress_rx => completion, admitted; 87, semantic_target, route);
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("peer-writer admission awaits completion");
    tenure.cancel();
    assert!(!route.is_active());
    assert!(
        network
            .dispatch_reliable_actor_message_inner(retained, || {
                assert_lane_flushed!(
                    peer_receivers,
                    87,
                    "writer publishes after the optimistic poll"
                );
            })
            .is_ok(),
        "the terminal fence must observe an inactive-route-gap flush"
    );
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Flushed);
    assert!(!peer_receivers.termination_requested());
    assert!(!network.terminating_connections.contains(&connection_id));
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[test]
fn terminal_fence_observes_send_before_close_and_rejects_send_after_close() {
    let exact_target = random_peer_id();
    let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
    let mut ready = HashMap::from([(
        exact_target.clone(),
        PendingWriterFlush {
            receiver: ready_receiver,
        },
    )]);
    assert!(ready_sender.send(()).is_ok());
    assert!(exact_reply_flush_wins_terminal_fence(
        &mut ready,
        Some(&exact_target)
    ));
    assert!(ready.is_empty());
    let (late_sender, late_receiver) = tokio::sync::oneshot::channel();
    let mut late = HashMap::from([(
        exact_target.clone(),
        PendingWriterFlush {
            receiver: late_receiver,
        },
    )]);
    assert!(!exact_reply_flush_wins_terminal_fence(
        &mut late,
        Some(&exact_target)
    ));
    assert!(late.is_empty());
    assert!(
        late_sender.send(()).is_err(),
        "a writer which loses the terminal close cannot publish success"
    );
    let (topology_sender, topology_receiver) = tokio::sync::oneshot::channel();
    let mut topology = HashMap::from([(
        exact_target.clone(),
        PendingWriterFlush {
            receiver: topology_receiver,
        },
    )]);
    assert!(!exact_reply_flush_wins_terminal_fence(&mut topology, None));
    assert_eq!(topology.len(), 1);
    assert!(
        topology_sender.send(()).is_ok(),
        "topology traffic must not enter the exact-reply terminal fence"
    );
    assert!(matches!(
        topology
            .get_mut(&exact_target)
            .expect("topology receiver remains owned")
            .receiver
            .try_recv(),
        Ok(())
    ));
}
#[tokio::test(start_paused = true)]
async fn cancelled_pending_exact_reply_observes_ready_flush_before_release() {
    let_test_network!(network, DeferredProgressMsg);
    let_reply_handle!(network, handle, progress_rx);
    let connection_id = 156;
    let (_delivery_peer, semantic_target, mut peer_receivers, tenure, route) =
        install_test_reply_route(
            &mut network,
            socket_addr!(127.0.0.1:45734),
            connection_id,
            43,
            58,
            true,
        );
    admit_lane_reply!(handle, progress_rx => completion, admitted; 88, semantic_target, route);
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("peer-writer admission awaits completion");
    let mut pending = ReliableActorPending::new(4);
    pending.push_back(retained);
    tenure.cancel();
    assert!(!route.is_active());
    assert_lane_flushed!(
        peer_receivers,
        88,
        "writer publishes while the cancelled item is queued"
    );
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Pending);
    assert_eq!(pending.release_cancelled_targets(), 1);
    assert_eq!(pending.len(), 0);
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Flushed);
    assert!(!peer_receivers.termination_requested());
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[tokio::test(start_paused = true)]
async fn pending_queue_drop_observes_ready_exact_flush_before_shutdown_close() {
    let_test_network!(network, DeferredProgressMsg);
    let_reply_handle!(network, handle, progress_rx);
    let connection_id = 157;
    let (_delivery_peer, semantic_target, mut peer_receivers, tenure, route) =
        install_test_reply_route(
            &mut network,
            socket_addr!(127.0.0.1:45735),
            connection_id,
            44,
            59,
            true,
        );
    drop(tenure);
    admit_lane_reply!(handle, progress_rx => completion, admitted; 89, semantic_target, route);
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("peer-writer admission awaits completion");
    let mut pending = ReliableActorPending::new(4);
    pending.push_back(retained);
    assert_lane_flushed!(
        peer_receivers,
        89,
        "writer publishes while the shutdown-owned item is queued"
    );
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Pending);
    drop(pending);
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Flushed);
    assert!(route.is_reply_writable());
    assert!(!peer_receivers.termination_requested());
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[tokio::test(start_paused = true)]
async fn nonready_exact_reply_ack_cannot_keep_stale_route_alive() {
    for close_old_writer in [false, true] {
        let_test_network!(network, DeferredProgressMsg);
        let (mut handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
            handle_with_network_receivers::<DeferredProgressMsg>();
        handle.reply_route_owner = Arc::clone(&network.reply_route_owner);
        let old_connection_id = if close_old_writer { 149 } else { 148 };
        let replacement_connection_id = if close_old_writer { 151 } else { 150 };
        let (delivery_peer, semantic_target, old_receivers, tenure, route) =
            install_test_reply_route(
                &mut network,
                socket_addr!(127.0.0.1:45728),
                old_connection_id,
                39,
                54,
                true,
            );
        drop(tenure);
        admit_lane_reply!(handle, progress_rx => completion, admitted; 84, semantic_target, route);
        let retained = network
            .dispatch_reliable_actor_message(admitted)
            .expect_err("old peer writer owns the unflushed occurrence");
        assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Pending);
        let old_receivers = if close_old_writer {
            drop(old_receivers);
            None
        } else {
            Some(old_receivers)
        };
        let_deferred_peer!(replacement_receivers = &mut network; delivery_peer.clone(), socket_addr!(127.0.0.1:45729), replacement_connection_id);
        assert!(
            network.dispatch_reliable_actor_message(retained).is_ok(),
            "an empty or closed acknowledgement cannot retain a stale exact route"
        );
        assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Closed);
        assert!(!route.is_reply_writable());
        assert_eq!(
            network
                .peers
                .get(&delivery_peer)
                .expect("replacement remains current")
                .conn_id,
            replacement_connection_id
        );
        assert!(!replacement_receivers.termination_requested());
        assert!(
            !network
                .terminating_connections
                .contains(&replacement_connection_id)
        );
        assert_eq!(handle.network_actor_progress_budget.retained(), 0);
        drop(old_receivers);
    }
}
#[tokio::test(start_paused = true)]
async fn expired_exact_deadline_beats_closed_peer_writer_receiver() {
    let_test_network!(network, DeferredProgressMsg);
    network.reply_writer_flush_timeout = Duration::from_millis(10);
    let_reply_handle!(network, handle, progress_rx);
    let connection_id = 143;
    let (_delivery_peer, semantic_target, peer_receivers, tenure, route) = install_test_reply_route(
        &mut network,
        socket_addr!(127.0.0.1:45723),
        connection_id,
        35,
        50,
        false,
    );
    drop(tenure);
    admit_lane_reply!(handle, progress_rx => completion, admitted; 80, semantic_target, route);
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("peer-writer admission awaits completion");
    tokio::time::advance(network.reply_writer_flush_timeout).await;
    drop(peer_receivers);
    assert!(
        network.dispatch_reliable_actor_message(retained).is_ok(),
        "an expired occurrence must not evade timeout via a closed writer receiver"
    );
    assert_eq!(
        completion.poll(),
        NetworkReplyFlushAckStatus::TimedOut,
        "only a published successful flush may win at the deadline"
    );
    assert!(!route.is_reply_writable());
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[tokio::test(start_paused = true)]
async fn adaptive_reply_attempt_flushes_between_base_and_doubled_deadline() {
    let_test_network!(network, DeferredProgressMsg);
    let base = Duration::from_millis(10);
    network.reply_writer_flush_timeout = base;
    let_reply_handle!(network, handle, progress_rx);
    let connection_id = 144;
    let (_delivery_peer, semantic_target, mut peer_receivers, tenure, route) =
        install_test_reply_route(
            &mut network,
            socket_addr!(127.0.0.1:45724),
            connection_id,
            36,
            51,
            true,
        );
    drop(tenure);
    let mut completion = handle
        .post_reply_recoverable_with_flush_ack_at_attempt(
            Post {
                data: DeferredProgressMsg::Lane(81),
                peer_id: semantic_target,
                priority: Priority::High,
            },
            &route,
            None,
            1,
        )
        .expect("adaptive retry enters actor ownership")
        .expect("adaptive retry returns one completion");
    let admitted = progress_rx
        .try_recv()
        .expect("admitted adaptive reply actor item");
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("writer admission awaits its flush");
    tokio::time::advance(Duration::from_millis(15)).await;
    let retained = network
        .dispatch_reliable_actor_message(retained)
        .expect_err("attempt one owns twice the base timeout");
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Pending);
    assert!(route.is_reply_writable());
    assert_lane_flushed!(
        peer_receivers,
        81,
        "writer flushes between base and doubled deadline"
    );
    assert!(network.dispatch_reliable_actor_message(retained).is_ok());
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Flushed);
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[test]
fn adaptive_reply_timeout_scaling_handles_extreme_duration_without_panicking() {
    assert_eq!(
        scaled_reply_writer_flush_timeout(Duration::from_millis(1), 32),
        Duration::from_millis(1_u64 << 32),
        "u8 attempts must not saturate merely because a u32 multiplier cannot encode them"
    );
    assert_eq!(
        scaled_reply_writer_flush_timeout(Duration::MAX, 1),
        Duration::MAX
    );
    assert_eq!(
        scaled_reply_writer_flush_timeout(Duration::from_millis(u64::MAX), u8::MAX),
        Duration::MAX
    );
    let now = tokio::time::Instant::now();
    let deadline = ExactReplyWriterDeadline {
        admitted_at: now,
        timeout: scaled_reply_writer_flush_timeout(Duration::MAX, u8::MAX),
    };
    assert!(!deadline.expired_at(now));
}
// TODO: Add a four-peer authenticated socket test whose Byzantine peer
// keeps the inbound idle timer alive with valid frames while never reading
// its outbound stream; assert this actor deadline still drains only that
// connection and preserves sibling progress.
#[tokio::test(start_paused = true)]
async fn full_exact_writer_queue_times_out_closes_route_and_releases_actor_budget() {
    let_test_network!(network, DeferredProgressMsg);
    network.reply_writer_flush_timeout = Duration::from_millis(10);
    network.disconnect_on_post_overflow = false;
    let_reply_handle!(network, handle, progress_rx);
    let delivery_peer = random_peer_id();
    let semantic_target = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45719);
    let connection_id = 139;
    let (peer_handle, peer_receivers) = test_wire_peer_handle::<DeferredProgressMsg>(1);
    peer_handle
        .post(direct_frame!(
            network.self_id.clone(),
            semantic_target,
            DeferredProgressMsg::Lane(1),
        ))
        .expect("prefill the cap-one peer-writer queue");
    insert_ref_peer(
        &mut network,
        delivery_peer.clone(),
        peer_addr,
        connection_id,
        peer_handle,
        true,
    );
    let tenure = test_reply_tenure(&network.reply_route_owner, delivery_peer, connection_id, 33);
    assert!(
        network
            .reply_route_tenures
            .insert(connection_id, Arc::clone(&tenure))
            .is_none()
    );
    let route = NetworkReplyRoute::new(semantic_target.clone(), tenure, 48);
    let mut completion = handle
        .post_reply_recoverable_with_flush_ack(
            Post {
                data: DeferredProgressMsg::Lane(78),
                peer_id: semantic_target,
                priority: Priority::High,
            },
            &route,
            None,
        )
        .expect("reply enters actor ownership")
        .expect("new reply admission returns one completion");
    assert!(
        handle.network_actor_progress_budget.retained() > 0,
        "actor admission must retain the exact reply bytes"
    );
    let admitted = progress_rx.try_recv().expect("admitted reply actor item");
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("a full peer-writer queue retains actor ownership");
    tokio::time::advance(Duration::from_millis(9)).await;
    let retained = network
        .dispatch_reliable_actor_message(retained)
        .expect_err("retry polling must not reset or prematurely expire the deadline");
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::Pending);
    assert!(route.is_reply_writable());
    assert!(!peer_receivers.termination_requested());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(
        network.dispatch_reliable_actor_message(retained).is_ok(),
        "expired occurrence must release the actor owner"
    );
    assert_eq!(completion.poll(), NetworkReplyFlushAckStatus::TimedOut);
    assert_eq!(
        completion.poll(),
        NetworkReplyFlushAckStatus::TimedOut,
        "timeout completion must remain terminal and never become flushed"
    );
    assert!(
        route.is_active(),
        "delivery authority drains separately from writer authority"
    );
    assert!(!route.is_reply_writable());
    assert!(peer_receivers.termination_requested());
    assert!(network.terminating_connections.contains(&connection_id));
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[tokio::test(start_paused = true)]
async fn topology_writer_full_retry_does_not_acquire_exact_reply_deadline() {
    let_test_network!(network, DeferredProgressMsg);
    network.reply_writer_flush_timeout = Duration::from_millis(10);
    network.disconnect_on_post_overflow = false;
    let (handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let peer_id = random_peer_id();
    reconcile_test_topology!(
        handle.reliable_direct_topology,
        &HashSet::from([peer_id.clone()])
    );
    let peer_addr = socket_addr!(127.0.0.1:45722);
    let connection_id = 142;
    let (peer_handle, mut peer_receivers) = test_wire_peer_handle::<DeferredProgressMsg>(1);
    peer_handle
        .post(direct_frame!(
            network.self_id.clone(),
            peer_id,
            DeferredProgressMsg::Lane(1),
        ))
        .expect("prefill the topology peer-writer queue");
    insert_ref_peer(
        &mut network,
        peer_id.clone(),
        peer_addr,
        connection_id,
        peer_handle,
        true,
    );
    handle
        .post_recoverable(
            Post {
                data: DeferredProgressMsg::Lane(79),
                peer_id,
                priority: Priority::High,
            },
            None,
        )
        .expect("topology-authorized progress enters actor ownership");
    let admitted = progress_rx
        .try_recv()
        .expect("topology-authorized actor item");
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("full topology writer retains actor ownership");
    tokio::time::advance(Duration::from_secs(1)).await;
    let retained = network
        .dispatch_reliable_actor_message(retained)
        .expect_err("topology retry remains independent of reply timeout");
    assert!(!peer_receivers.termination_requested());
    assert!(handle.network_actor_progress_budget.retained() > 0);
    assert_lane_flushed!(
        peer_receivers,
        1,
        "drain the prefilled topology writer slot"
    );
    let retained = network
        .dispatch_reliable_actor_message(retained)
        .expect_err("writer admission still awaits its flush");
    assert_lane_flushed!(peer_receivers, 79, "flush the topology actor occurrence");
    assert!(network.dispatch_reliable_actor_message(retained).is_ok());
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[tokio::test(start_paused = true)]
async fn stale_reply_writer_deadline_does_not_terminate_replacement() {
    let_test_network!(network, DeferredProgressMsg);
    let delivery_peer = random_peer_id();
    let semantic_target = random_peer_id();
    let old_connection_id = 140;
    let replacement_connection_id = 141;
    let tenure = test_reply_tenure(
        &network.reply_route_owner,
        delivery_peer.clone(),
        old_connection_id,
        34,
    );
    assert!(
        network
            .reply_route_tenures
            .insert(old_connection_id, Arc::clone(&tenure))
            .is_none()
    );
    let route = NetworkReplyRoute::new(semantic_target, tenure, 49);
    let_deferred_peer!(replacement_receivers = &mut network; delivery_peer.clone(), socket_addr!(127.0.0.1:45720), replacement_connection_id);
    assert!(
        !network.expire_reply_writer_occurrence(&route, old_connection_id),
        "a stale timeout must not remove a replacement connection"
    );
    assert!(!route.is_reply_writable());
    assert_eq!(
        network
            .peers
            .get(&delivery_peer)
            .expect("replacement remains current")
            .conn_id,
        replacement_connection_id
    );
    assert!(!replacement_receivers.termination_requested());
    assert!(
        !network
            .terminating_connections
            .contains(&replacement_connection_id)
    );
}
#[tokio::test(start_paused = true)]
async fn reply_writer_deadline_retirement_is_idempotent() {
    let_test_network!(network, DeferredProgressMsg);
    let delivery_peer = random_peer_id();
    let semantic_target = random_peer_id();
    let connection_id = 142;
    let tenure = test_reply_tenure(
        &network.reply_route_owner,
        delivery_peer.clone(),
        connection_id,
        35,
    );
    assert!(
        network
            .reply_route_tenures
            .insert(connection_id, Arc::clone(&tenure))
            .is_none()
    );
    let route = NetworkReplyRoute::new(semantic_target, tenure, 50);
    let_deferred_peer!(peer_receivers = &mut network; delivery_peer.clone(), socket_addr!(127.0.0.1:45721), connection_id);
    assert!(network.expire_reply_writer_occurrence(&route, connection_id));
    let terminating_after_first = network.terminating_connections.len();
    let pending_connects_after_first = network.pending_connects.len();
    assert!(
        !network.expire_reply_writer_occurrence(&route, connection_id),
        "the same timeout cannot cancel its connection twice"
    );
    assert_eq!(
        network.terminating_connections.len(),
        terminating_after_first
    );
    assert_eq!(network.pending_connects.len(), pending_connects_after_first);
    assert!(peer_receivers.termination_requested());
    assert!(!route.is_reply_writable());
    assert!(!network.peers.contains_key(&delivery_peer));
}
#[test]
fn actor_progress_lease_survives_topology_transition() {
    let_deferred_test_network!(network, DeferredProgressMsg);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45699);
    let actor_budget = NetworkActorByteBudget::new(1, 0).expect("test actor owner");
    let actor_lease = actor_budget
        .try_reserve(1, false)
        .expect("reserve exact actor owner");
    let admitted = AdmittedNetworkMessage::new(
        NetworkMessage::Post(Post {
            data: DeferredProgressMsg::Lane(7),
            peer_id: peer_id.clone(),
            priority: Priority::High,
        }),
        actor_lease,
    );
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("a target outside topology has no downstream owner");
    assert_eq!(actor_budget.retained().total, 1);
    assert!(!network.deferred_send_queue.by_peer.contains_key(&peer_id));
    network.current_topology.insert(peer_id.clone());
    network
        .current_peers_addresses
        .push((peer_id.clone(), peer_addr.clone()));
    let now = tokio::time::Instant::now();
    network.retry_backoff.insert(
        peer_id.clone(),
        HashMap::from([(
            peer_addr.to_string(),
            (now + Duration::from_secs(1), Duration::from_millis(25)),
        )]),
    );
    let retained = network
        .dispatch_reliable_actor_message(retained)
        .expect_err("topology alone is not a peer-writer flush");
    assert_eq!(actor_budget.retained().total, 1);
    assert!(!network.deferred_send_queue.by_peer.contains_key(&peer_id));
    let_deferred_peer!(mut receivers = &mut network; peer_id.clone(), peer_addr, 107);
    let retained = network
        .dispatch_reliable_actor_message(retained)
        .expect_err("writer admission must retain the actor lease until flush");
    assert_lane_flushed!(
        receivers,
        7,
        "replacement writer connection receives the retained intent"
    );
    assert!(network.dispatch_reliable_actor_message(retained).is_ok());
    assert_eq!(actor_budget.retained().total, 0);
}
#[test]
fn actor_progress_retries_exactly_once_on_peer_writer_replacement() {
    let_test_network!(network, DeferredProgressMsg);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45706);
    network.current_topology.insert(peer_id.clone());
    network
        .current_peers_addresses
        .push((peer_id.clone(), peer_addr.clone()));
    let_deferred_peer!(old_receivers = &mut network; peer_id.clone(), peer_addr.clone(), 109);
    let actor_budget = NetworkActorByteBudget::new(1, 0).expect("test actor owner");
    let admitted = AdmittedNetworkMessage::new(
        NetworkMessage::Post(Post {
            data: DeferredProgressMsg::Lane(17),
            peer_id: peer_id.clone(),
            priority: Priority::High,
        }),
        actor_budget
            .try_reserve(1, false)
            .expect("reserve exact actor owner"),
    );
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("old writer has not flushed");
    let old = network
        .peers
        .remove(&peer_id)
        .expect("old generation must be present");
    old.handle.request_termination();
    drop(old_receivers);
    let_deferred_peer!(mut new_receivers = &mut network; peer_id, peer_addr, 110);
    let retained = network
        .dispatch_reliable_actor_message(retained)
        .expect_err("closed old acknowledgement must retry on the replacement writer");
    assert_lane_flushed!(
        new_receivers,
        17,
        "replacement writer receives exactly one retry"
    );
    assert!(matches!(
        new_receivers.try_recv_any(),
        Err(TryRecvError::Empty)
    ));
    assert!(network.dispatch_reliable_actor_message(retained).is_ok());
    assert_eq!(actor_budget.retained().total, 0);
}
#[test]
fn actor_progress_retry_round_robin_bypasses_partitioned_target() {
    let_test_network!(network, DeferredProgressMsg);
    let blocked_peer = random_peer_id();
    let live_peer = random_peer_id();
    let live_addr = socket_addr!(127.0.0.1:45700);
    let_deferred_peer!(mut receivers = &mut network; live_peer.clone(), live_addr, 101; capacity 2);
    let actor_budget = NetworkActorByteBudget::new(2, 0).expect("test actor owner");
    let mut pending = ReliableActorPending::new(2);
    for (peer_id, tag) in [(blocked_peer, 1), (live_peer, 2)] {
        let actor_lease = actor_budget
            .try_reserve(1, false)
            .expect("reserve exact actor owner");
        pending.push_back(AdmittedNetworkMessage::new(
            NetworkMessage::Post(Post {
                data: DeferredProgressMsg::Lane(tag),
                peer_id,
                priority: Priority::High,
            }),
            actor_lease,
        ));
    }
    assert_eq!(
        network.retry_reliable_actor_messages(&mut pending, 2),
        0,
        "mailbox admission is not yet a writer flush"
    );
    assert_eq!(pending.len(), 2);
    assert_eq!(actor_budget.retained().total, 2);
    let delivered = receivers
        .try_recv_any_and_acknowledge_flush()
        .expect("responsive peer writer receives the retained progress frame");
    assert_eq!(delivered.payload, DeferredProgressMsg::Lane(2));
    assert_eq!(
        network.retry_reliable_actor_messages(&mut pending, 2),
        1,
        "the responsive writer flush must complete behind a partitioned source"
    );
    assert_eq!(pending.len(), 1);
    assert_eq!(actor_budget.retained().total, 1);
}
#[test]
fn cap_one_blocked_source_cannot_prevent_live_source_service() {
    let_test_network!(network, DeferredProgressMsg);
    let blocked_peer = random_peer_id();
    let live_peer = random_peer_id();
    let_deferred_peer!(mut receivers = &mut network; live_peer.clone(), socket_addr!(127.0.0.1:45704), 105);
    let budget =
        NetworkActorProgressBudget::new(1, 2, 2).expect("two one-item source lanes must fit");
    let shape = ProgressTicketShape {
        topic: message::Topic::Consensus,
        stream_wire_bytes: 1,
        broadcast: false,
        reply_writer_timeout_attempt: None,
        request_digest: Hash::new(b"blocked-live-source"),
        authority: None,
    };
    let blocked_source = ActorProgressSource {
        target: Some(blocked_peer.clone()),
        class: ActorProgressClass::Lane,
    };
    let live_source = ActorProgressSource {
        target: Some(live_peer.clone()),
        class: ActorProgressClass::Lane,
    };
    let ProgressLeaseAttempt::Ready {
        lease: blocked_lease,
        ticket: mut blocked_admission,
    } = budget.try_reserve_for_source(1, shape, blocked_source.clone(), None, None)
    else {
        panic!("first blocked-source item must own its single slot");
    };
    blocked_admission.commit();
    let ProgressLeaseAttempt::Waiting {
        ticket: Some(_blocked_retry_ticket),
        rank: 1,
    } = budget.try_reserve_for_source(1, shape, blocked_source, None, None)
    else {
        panic!("second blocked-source item must stay recoverably with its caller");
    };
    let ProgressLeaseAttempt::Ready {
        lease: live_lease,
        ticket: mut live_admission,
    } = budget.try_reserve_for_source(1, shape, live_source, None, None)
    else {
        panic!("a distinct responsive source must retain independent admission");
    };
    live_admission.commit();
    let mut pending = ReliableActorPending::new(2);
    pending.push_back(AdmittedNetworkMessage::new(
        NetworkMessage::Post(Post {
            data: DeferredProgressMsg::Lane(1),
            peer_id: blocked_peer,
            priority: Priority::High,
        }),
        blocked_lease,
    ));
    assert_eq!(network.retry_reliable_actor_messages(&mut pending, 1), 0);
    pending.push_back(AdmittedNetworkMessage::new(
        NetworkMessage::Post(Post {
            data: DeferredProgressMsg::Lane(2),
            peer_id: live_peer,
            priority: Priority::High,
        }),
        live_lease,
    ));
    assert_eq!(
        network.retry_reliable_actor_messages(&mut pending, 2),
        0,
        "one retained retry is serviced before the live source receives the next RR rank, but writer admission is not completion"
    );
    assert_eq!(pending.len(), 2);
    assert_lane_flushed!(receivers, 2, "responsive source must reach the peer queue");
    assert_eq!(network.retry_reliable_actor_messages(&mut pending, 2), 1);
    assert_eq!(pending.len(), 1);
}
#[test]
fn admitted_reliable_payload_materializes_once_and_reuses_its_allocation() {
    let origin = random_peer_id();
    let pending = AdmittedNetworkPayload::from_network(NetworkMessage::Broadcast(Broadcast {
        data: DeferredProgressMsg::Lane(40),
        priority: Priority::High,
    }));

    let first_state = pending.materialize(&origin, 8);
    let first = Arc::clone(first_state.frame());
    let second_state = first_state.materialize(&origin, 8);
    let second = second_state.frame();

    // A repeated materialization would necessarily create a distinct live
    // relay allocation while `first` is held. These pointer checks therefore
    // pin the retry materialization count to one without adding
    // production-only instrumentation.
    assert!(Arc::ptr_eq(&first, second));
    assert_eq!(Arc::strong_count(&first), 2);
    assert!(matches!(&second.target, RelayTarget::Broadcast));
    assert_eq!(second.origin, origin);
    assert!(
        !second.is_relay_signed(),
        "materialization creates a link-local frame; only a forwarding hop signs it"
    );
}
#[test]
fn reliable_direct_retry_reuses_the_link_envelope_without_signing() {
    let_deferred_test_network!(network, DeferredProgressMsg);
    let target = random_peer_id();
    let (admitted, actor_budget, retained_bytes) = admitted_with_exact_actor_bytes(
        &network,
        NetworkMessage::Post(Post {
            data: DeferredProgressMsg::Lane(41),
            peer_id: target.clone(),
            priority: Priority::High,
        }),
    );

    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("an unavailable direct target must retain actor ownership");
    let first = Arc::clone(
        retained
            .message
            .as_ref()
            .expect("first dispatch retains one payload")
            .frame(),
    );
    let retained = network
        .dispatch_reliable_actor_message(retained)
        .expect_err("the unavailable direct target must remain retryable");
    let second = retained
        .message
        .as_ref()
        .expect("retry retains the payload")
        .frame();

    assert!(Arc::ptr_eq(&first, second));
    assert!(matches!(&second.target, RelayTarget::Direct(peer) if peer == &target));
    assert!(
        !second.is_relay_signed(),
        "a direct frame for its own target never needs an origin signature"
    );
    assert_eq!(
        actor_budget.retained(),
        NetworkActorRetainedBytes {
            total: retained_bytes,
            ordinary: retained_bytes,
        }
    );
}
#[test]
fn reliable_broadcast_retry_reuses_the_link_envelope_allocation() {
    let_deferred_test_network!(network, DeferredProgressMsg);
    let blocked_peer = random_peer_id();
    network.current_topology = HashSet::from([blocked_peer]);
    let (admitted, actor_budget, retained_bytes) = admitted_with_exact_actor_bytes(
        &network,
        NetworkMessage::Broadcast(Broadcast {
            data: DeferredProgressMsg::Lane(42),
            priority: Priority::High,
        }),
    );

    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("an unavailable target must retain the reliable broadcast");
    let first = Arc::clone(
        retained
            .message
            .as_ref()
            .expect("first dispatch retains one payload")
            .frame(),
    );
    assert!(
        !first.is_relay_signed(),
        "no hop received the broadcast, so nothing required an origin signature"
    );

    let retained = network
        .dispatch_reliable_actor_message(retained)
        .expect_err("the same unavailable target must remain retryable");
    let second = retained
        .message
        .as_ref()
        .expect("retry retains the payload")
        .frame();

    assert!(Arc::ptr_eq(&first, second));
    assert!(matches!(&second.target, RelayTarget::Broadcast));
    assert_eq!(
        actor_budget.retained(),
        NetworkActorRetainedBytes {
            total: retained_bytes,
            ordinary: retained_bytes,
        }
    );
}
#[test]
fn reliable_hub_routed_retry_reuses_the_signed_envelope_allocation() {
    let_deferred_test_network!(network, DeferredProgressMsg);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
    let hub = random_peer_id();
    let hub_addr = socket_addr!(127.0.0.1:45712);
    let target = random_peer_id();
    let_deferred_peer!(mut hub_receivers = &mut network; hub.clone(), hub_addr.clone(), 112; capacity 2);
    network.relay_hub_addresses.push(hub_addr.clone());
    network
        .current_peers_addresses
        .push((hub.clone(), hub_addr));
    network.relay_trusted_peers.insert(hub.clone());
    network.current_topology.insert(hub.clone());
    network
        .peers
        .get_mut(&hub)
        .expect("connected relay hub")
        .relay_role = RelayRole::Hub;
    network.relay_hub_peer = Some(hub.clone());
    let (admitted, actor_budget, retained_bytes) = admitted_with_exact_actor_bytes(
        &network,
        NetworkMessage::Post(Post {
            data: DeferredProgressMsg::Lane(43),
            peer_id: target.clone(),
            priority: Priority::High,
        }),
    );

    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("hub writer admission still awaits its flush");
    let first = Arc::clone(
        retained
            .message
            .as_ref()
            .expect("hub-routed dispatch retains one payload")
            .frame(),
    );
    first
        .verify_origin_signature()
        .expect("the hub relays this frame, so its hand-off adds a valid origin signature");
    let signature_allocation = first.origin_signature.as_ptr();
    let first_delivery = hub_receivers
        .try_recv_any()
        .expect("the unconnected target must route through the live hub");
    assert!(matches!(
        &first_delivery.target,
        RelayTarget::Direct(peer) if peer == &target
    ));
    assert_eq!(first_delivery.origin_signature, first.origin_signature);

    let retained = network
        .dispatch_reliable_actor_message(retained)
        .expect_err("a closed first writer completion must retry through the hub");
    let second = retained
        .message
        .as_ref()
        .expect("hub retry retains the payload")
        .frame();
    assert!(Arc::ptr_eq(&first, second));
    assert_eq!(second.origin_signature.as_ptr(), signature_allocation);
    assert_eq!(
        actor_budget.retained(),
        NetworkActorRetainedBytes {
            total: retained_bytes,
            ordinary: retained_bytes,
        }
    );

    let retry_delivery = hub_receivers
        .try_recv_any_and_acknowledge_flush()
        .expect("the retry must keep the same semantic target through the hub");
    assert!(matches!(
        &retry_delivery.target,
        RelayTarget::Direct(peer) if peer == &target
    ));
    assert_eq!(retry_delivery.origin_signature, first.origin_signature);
    assert!(network.dispatch_reliable_actor_message(retained).is_ok());
    assert_eq!(
        actor_budget.retained(),
        NetworkActorRetainedBytes::default()
    );
}
#[test]
fn actor_broadcast_retry_targets_only_failed_peers() {
    let_deferred_test_network!(network, DeferredProgressMsg);
    let blocked_peer = random_peer_id();
    let live_peer = random_peer_id();
    let live_addr = socket_addr!(127.0.0.1:45702);
    let_deferred_peer!(mut receivers = &mut network; live_peer.clone(), live_addr, 103; capacity 4);
    network.current_topology = HashSet::from([blocked_peer.clone(), live_peer]);
    network.deferred_send_queue =
        DeferredPeerFrameQueue::new(1, usize::MAX, Duration::from_secs(60));
    assert!(
        defer_frame!(
            network.deferred_send_queue,
            blocked_peer,
            direct_frame!(
                network.self_id.clone(),
                blocked_peer,
                DeferredProgressMsg::Lane(1),
            ),
            Consensus,
            None,
            tokio::time::Instant::now()
        )
        .enqueued
    );
    let actor_budget = NetworkActorByteBudget::new(1, 0).expect("test actor owner");
    let admitted = AdmittedNetworkMessage::new(
        NetworkMessage::Broadcast(Broadcast {
            data: DeferredProgressMsg::Lane(2),
            priority: Priority::High,
        }),
        actor_budget
            .try_reserve(1, false)
            .expect("reserve exact actor owner"),
    );
    let retained = network
        .dispatch_reliable_actor_message(admitted)
        .expect_err("the saturated target must remain in the broadcast cursor");
    assert_lane_flushed!(
        receivers,
        2,
        "the live peer writer receives the first fanout attempt"
    );
    let (prefilled, _) = network
        .deferred_send_queue
        .take_peer(&blocked_peer, tokio::time::Instant::now());
    drop(prefilled);
    let_deferred_peer!(mut blocked_receivers = &mut network; blocked_peer.clone(), socket_addr!(127.0.0.1:45705), 108);
    let retained = network
        .dispatch_reliable_actor_message(retained)
        .expect_err("new target writer admission still awaits its flush");
    assert!(matches!(receivers.try_recv_any(), Err(TryRecvError::Empty)));
    assert_lane_flushed!(
        blocked_receivers,
        2,
        "only the previously unavailable target receives the retry"
    );
    assert!(network.dispatch_reliable_actor_message(retained).is_ok());
    assert_eq!(actor_budget.retained().total, 0);
    assert_eq!(
        network
            .deferred_send_queue
            .by_peer
            .get(&blocked_peer)
            .map_or(0, VecDeque::len),
        0,
        "actor-owned retry must never duplicate into the deferred queue"
    );
}
#[test]
fn distinct_broadcast_residual_is_target_isolated_and_its_rank_decreases() {
    let (handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let blocked_peer = random_peer_id();
    let live_peer = random_peer_id();
    reconcile_test_topology!(
        handle.reliable_broadcast_topology,
        &HashSet::from([blocked_peer.clone(), live_peer.clone()])
    );
    reserve_direct_lane_lease!(handle, blocked_peer.clone(), 99 => direct_lease; "direct fixture must occupy only the blocked target lane");
    let broadcast = |tag| Broadcast {
        data: DeferredProgressMsg::Lane(tag),
        priority: Priority::High,
    };
    let (first_ticket, first_rank) = match handle.broadcast_recoverable(broadcast(1), None) {
        Err(NetworkBroadcastAdmissionError::Backpressured {
            message,
            ticket,
            rank,
        }) => {
            assert_eq!(message.data, DeferredProgressMsg::Lane(1));
            (ticket, rank)
        }
        _ => panic!("only the blocked target copy must remain with the caller"),
    };
    assert_eq!(first_rank, 1);
    assert_eq!(first_ticket.pending_targets(), 1);
    let first_live = progress_rx
        .try_recv()
        .expect("responsive target receives the first broadcast");
    assert_eq!(
        first_live
            .progress_source()
            .and_then(|source| source.target.as_ref()),
        Some(&live_peer)
    );
    drop(first_live);
    let (second_ticket, second_rank) = match handle.broadcast_recoverable(broadcast(2), None) {
        Err(NetworkBroadcastAdmissionError::Backpressured {
            message,
            ticket,
            rank,
        }) => {
            assert_eq!(message.data, DeferredProgressMsg::Lane(2));
            (ticket, rank)
        }
        _ => panic!("later blocked copy must remain independently exact"),
    };
    assert_eq!(second_rank, 2);
    let second_live = progress_rx
        .try_recv()
        .expect("blocked target must not prevent later responsive fanout");
    assert_eq!(
        second_live
            .progress_source()
            .and_then(|source| source.target.as_ref()),
        Some(&live_peer)
    );
    drop(second_live);
    drop(direct_lease);
    handle
        .broadcast_recoverable(broadcast(1), Some(first_ticket))
        .expect("first target ticket acquires the released lane");
    let first_blocked = progress_rx
        .try_recv()
        .expect("first blocked target copy reaches actor ownership");
    let second_ticket = match handle.broadcast_recoverable(broadcast(2), Some(second_ticket)) {
        Err(NetworkBroadcastAdmissionError::Backpressured {
            ticket, rank: 1, ..
        }) => ticket,
        _ => panic!("committing the predecessor must decrease the next rank"),
    };
    drop(first_blocked);
    handle
        .broadcast_recoverable(broadcast(2), Some(second_ticket))
        .expect("second exact target copy eventually acquires the lane");
    assert!(progress_rx.try_recv().is_ok());
}
#[test]
fn configured_peer_snapshot_keeps_spoke_targets_and_excludes_observers() {
    let_test_network!(network);
    let mut expected = (0..4).map(|_| random_peer_id()).collect::<Vec<_>>();
    network.requested_topology = expected.iter().cloned().collect();
    network.current_topology = HashSet::from([expected[0].clone()]);
    let observer = random_peer_id();
    let (observer_handle, _observer_receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(
        &mut network,
        observer.clone(),
        socket_addr!(127.0.0.1:12888),
        8_888,
        observer_handle,
    );

    let _ = network.reconcile_reliable_progress_topologies();
    expected.sort();
    let published = network
        .configured_peer_ids
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .peer_ids
        .clone();
    assert_eq!(published, expected);
    assert!(!published.contains(&observer));
}
#[test]
fn configured_peer_snapshot_applies_pending_revocations_fail_closed() {
    let_test_network!(network);
    let retained = random_peer_id();
    let topology_revoked = random_peer_id();
    let acl_revoked = random_peer_id();
    network.requested_topology = HashSet::from([
        retained.clone(),
        topology_revoked.clone(),
        acl_revoked.clone(),
    ]);
    network.pending_reply_source_authority.topology = Some(UpdateTopology(HashSet::from([
        retained.clone(),
        acl_revoked.clone(),
        random_peer_id(),
    ])));
    network.pending_reply_source_authority.acl = Some(
        ValidatedAclUpdate::parse(message::UpdateAcl {
            deny_keys: vec![acl_revoked.public_key().clone()],
            ..message::UpdateAcl::default()
        })
        .expect("test ACL is valid"),
    );

    let _ = network.reconcile_reliable_progress_topologies();
    let state = network
        .configured_peer_ids
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(state.peer_ids.as_slice(), [retained]);
    assert_eq!(state.generation, 1);
}
#[test]
fn configured_peer_ids_are_bounded_and_round_robin() {
    let (handle, _safety_rx, _progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let mut expected = (0..4).map(|_| random_peer_id()).collect::<Vec<_>>();
    expected.sort();
    let mut state = handle
        .configured_peer_ids
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.generation = 7;
    state.peer_ids = expected.clone();
    drop(state);

    let first = handle.configured_peer_ids_bounded(0, 2);
    assert_eq!(first.generation, 7);
    assert_eq!(first.peer_ids, expected[..2]);
    let second = handle.configured_peer_ids_bounded(first.next_start_index, 2);
    assert_eq!(second.peer_ids, expected[2..]);
    let wrapped = handle.configured_peer_ids_bounded(second.next_start_index, 2);
    assert_eq!(wrapped.peer_ids, expected[..2]);

    let full = handle.configured_peer_ids_bounded(0, expected.len());
    assert_eq!(full.peer_ids, expected);
    assert_eq!(full.next_start_index, 1);
    let rotated = handle.configured_peer_ids_bounded(full.next_start_index, usize::MAX);
    assert_eq!(rotated.peer_ids[0], expected[1]);
    assert_eq!(rotated.peer_ids.last(), Some(&expected[0]));
}
#[test]
fn configured_peer_generation_callback_holds_membership_stable() {
    let (handle, _safety_rx, _progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let peer = random_peer_id();
    {
        let mut state = handle
            .configured_peer_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.generation = 3;
        state.peer_ids = vec![peer];
    }
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let reader = {
        let handle = handle.clone();
        std::thread::spawn(move || {
            handle.with_configured_peer_generation_and_count(|generation, count| {
                assert_eq!((generation, count), (3, 1));
                entered_tx.send(()).expect("publish callback entry");
                release_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("release generation reader");
            });
        })
    };
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("generation reader enters callback");
    assert!(
        handle.configured_peer_ids.try_lock().is_err(),
        "membership publication must wait for a generation-bound operation"
    );
    release_tx.send(()).expect("release generation callback");
    reader.join().expect("generation reader thread");
}
#[test]
fn exact_broadcast_retry_coalesces_but_distinct_and_direct_requests_do_not() {
    let (handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let target = random_peer_id();
    reconcile_test_topology!(
        handle.reliable_broadcast_topology,
        &HashSet::from([target.clone()])
    );
    let broadcast = |tag| Broadcast {
        data: DeferredProgressMsg::Lane(tag),
        priority: Priority::High,
    };
    handle
        .broadcast_recoverable(broadcast(1), None)
        .expect("first targetized broadcast owns the lane");
    let first = progress_rx.try_recv().expect("first exact actor child");
    handle
        .broadcast_recoverable(broadcast(1), None)
        .expect("identical canonical retry shares the existing owner");
    assert!(matches!(
        progress_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    let distinct_ticket = match handle.broadcast_recoverable(broadcast(2), None) {
        Err(NetworkBroadcastAdmissionError::Backpressured {
            ticket, rank: 1, ..
        }) => ticket,
        _ => panic!("distinct digest must retain independent target ownership"),
    };
    assert!(matches!(
        handle.post_recoverable(
            Post {
                data: DeferredProgressMsg::Lane(1),
                peer_id: target,
                priority: Priority::High,
            },
            None,
        ),
        Err(NetworkActorAdmissionError::Backpressured { .. })
    ));
    drop(first);
    handle
        .broadcast_recoverable(broadcast(2), Some(distinct_ticket))
        .expect("distinct copy crosses only after the exact owner retires");
    assert!(progress_rx.try_recv().is_ok());
}
#[test]
fn removed_membership_cancels_only_old_broadcast_debt_across_readd() {
    let (handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let target = random_peer_id();
    let topology = HashSet::from([target.clone()]);
    reconcile_test_topology!(handle.reliable_broadcast_topology, &topology);
    reconcile_test_topology!(handle.reliable_direct_topology, &topology);
    reserve_direct_lane_lease!(handle, target.clone(), 7 => direct_lease; "direct post must own the target lane across topology changes");
    let message = Broadcast {
        data: DeferredProgressMsg::Lane(8),
        priority: Priority::High,
    };
    let old_ticket = match handle.broadcast_recoverable(message.clone(), None) {
        Err(NetworkBroadcastAdmissionError::Backpressured { ticket, .. }) => ticket,
        _ => panic!("old membership copy must remain with its caller"),
    };
    let old_generation = old_ticket
        .targets
        .front()
        .expect("old target debt")
        .membership
        .generation;
    let added = random_peer_id();
    let expanded = HashSet::from([target.clone(), added.clone()]);
    reconcile_test_topology!(handle.reliable_broadcast_topology, &expanded);
    let old_ticket = match handle.broadcast_recoverable(message.clone(), Some(old_ticket)) {
        Err(NetworkBroadcastAdmissionError::Backpressured { ticket, .. }) => ticket,
        _ => panic!("an old target snapshot must not acquire an added membership"),
    };
    assert!(matches!(
        progress_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    let added_residual = match handle.broadcast_recoverable(
        Broadcast {
            data: DeferredProgressMsg::Lane(9),
            priority: Priority::High,
        },
        None,
    ) {
        Err(NetworkBroadcastAdmissionError::Backpressured { ticket, .. }) => ticket,
        _ => panic!("fresh fanout must retain only the still-blocked original target"),
    };
    let added_child = progress_rx
        .try_recv()
        .expect("fresh fanout includes the newly accepted membership");
    assert_eq!(
        added_child
            .progress_source()
            .and_then(|source| source.target.as_ref()),
        Some(&added)
    );
    drop((added_child, added_residual));
    let removed = {
        let mut shared = handle
            .reliable_broadcast_topology
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let removed = shared.reconcile(&HashSet::new(), &handle.self_id);
        assert_eq!(removed.len(), 2);
        assert!(shared.reconcile(&topology, &handle.self_id).is_empty());
        removed
    };
    for membership in &removed {
        handle
            .network_actor_progress_budget
            .cancel_membership(membership, true);
    }
    // Do not retry or drop `old_ticket`: topology reconciliation itself
    // must remove its old-generation rank. Once the unrelated direct
    // owner retires, a new direct request must not wait behind the
    // abandoned producer.
    drop(direct_lease);
    handle
        .post_recoverable(
            Post {
                data: DeferredProgressMsg::Lane(10),
                peer_id: target.clone(),
                priority: Priority::High,
            },
            None,
        )
        .expect("removed broadcast tenure cannot block a fresh direct owner");
    let fresh_direct = progress_rx
        .try_recv()
        .expect("fresh direct owner crosses after the old tenure is cancelled");
    let new_ticket = match handle.broadcast_recoverable(message.clone(), None) {
        Err(NetworkBroadcastAdmissionError::Backpressured { ticket, .. }) => ticket,
        _ => panic!("re-addition creates a new tenure behind the direct post"),
    };
    let new_generation = new_ticket
        .targets
        .front()
        .expect("new target debt")
        .membership
        .generation;
    assert_ne!(old_generation, new_generation);
    drop(fresh_direct);
    handle
        .broadcast_recoverable(message.clone(), Some(new_ticket))
        .expect("new membership copy crosses after the shared lane releases");
    let new_child = progress_rx
        .try_recv()
        .expect("new membership child enters actor ownership");
    // Ticket ids may reset when the removed waiter was the last one. A
    // delayed old retry/drop must match its complete old shape and cannot
    // cancel the newly admitted generation, even if the numeric id was
    // reused.
    handle
        .broadcast_recoverable(message, Some(old_ticket))
        .expect("delayed removed-tenure retry is an exact cancellation no-op");
    assert!(matches!(
        progress_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    drop(new_child);
}
#[test]
fn cancelled_target_child_with_pending_flush_ack_releases_exactly_once() {
    let (handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let target = random_peer_id();
    reconcile_test_topology!(
        handle.reliable_broadcast_topology,
        &HashSet::from([target.clone()])
    );
    handle
        .broadcast_recoverable(
            Broadcast {
                data: DeferredProgressMsg::Lane(3),
                priority: Priority::High,
            },
            None,
        )
        .expect("target child enters actor ownership");
    let mut child = progress_rx.try_recv().expect("targetized actor child");
    let Some(ProgressDeliveryAuthority::Topology(membership)) = child.progress_authority.as_ref()
    else {
        panic!("broadcast child carries exact topology authority");
    };
    let membership = Arc::clone(membership);
    let (ack_sender, ack_receiver) = tokio::sync::oneshot::channel();
    child.pending_flush_acks.insert(
        target.clone(),
        PendingWriterFlush {
            receiver: ack_receiver,
        },
    );
    let ordinary_budget = NetworkActorByteBudget::new(1, 0).expect("direct fixture owner");
    let direct = AdmittedNetworkMessage::new(
        NetworkMessage::Post(Post {
            data: DeferredProgressMsg::Lane(4),
            peer_id: target,
            priority: Priority::High,
        }),
        ordinary_budget
            .try_reserve(1, false)
            .expect("direct fixture byte owner"),
    );
    let mut pending = ReliableActorPending::new(2);
    pending.push_back(child);
    pending.push_back(direct);
    membership.cancel();
    assert_eq!(pending.release_cancelled_targets(), 1);
    assert_eq!(pending.len(), 1, "direct post remains exact");
    assert!(ack_sender.send(()).is_err());
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
}
#[test]
fn requested_topology_is_not_authority_and_closed_fanout_returns_all_targets() {
    let (handle, _safety_rx, _progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let requested = random_peer_id();
    handle.update_topology(UpdateTopology(HashSet::from([requested])));
    let empty_ticket = match handle.broadcast_recoverable(
        Broadcast {
            data: DeferredProgressMsg::Lane(1),
            priority: Priority::High,
        },
        None,
    ) {
        Err(NetworkBroadcastAdmissionError::Backpressured {
            ticket:
                NetworkBroadcastAdmissionTicket {
                    needs_topology_snapshot: true,
                    ..
                },
            ..
        }) => match handle.broadcast_recoverable(
            Broadcast {
                data: DeferredProgressMsg::Lane(1),
                priority: Priority::High,
            },
            None,
        ) {
            Err(NetworkBroadcastAdmissionError::Backpressured { ticket, .. }) => ticket,
            _ => panic!("empty accepted topology must stay caller-owned"),
        },
        _ => panic!("a requested topology is not actor-accepted authority"),
    };
    assert!(empty_ticket.awaiting_topology_snapshot());
    assert_eq!(
        empty_ticket.pending_targets(),
        0,
        "no target count is invented before actor topology acceptance"
    );
    let (other_handle, _safety_rx, _progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    assert!(matches!(
        other_handle.broadcast_recoverable(
            Broadcast {
                data: DeferredProgressMsg::Lane(1),
                priority: Priority::High,
            },
            Some(empty_ticket),
        ),
        Err(NetworkBroadcastAdmissionError::Rejected {
            reason: NetworkActorAdmissionRejection::InvalidTicket,
            ..
        })
    ));
    let original_state = handle
        .network_actor_progress_budget
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(original_state.waiter_count, 0);
    assert_eq!(original_state.retained_items, 0);
    drop(original_state);
    let (closed_empty_handle, _safety_rx, closed_empty_progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let closed_empty_message = Broadcast {
        data: DeferredProgressMsg::Lane(2),
        priority: Priority::High,
    };
    let closed_empty_ticket =
        match closed_empty_handle.broadcast_recoverable(closed_empty_message.clone(), None) {
            Err(NetworkBroadcastAdmissionError::Backpressured { ticket, .. }) => ticket,
            _ => panic!("empty accepted topology must retain one unsnapshotted fanout"),
        };
    drop(closed_empty_progress_rx);
    match closed_empty_handle.broadcast_recoverable(closed_empty_message, Some(closed_empty_ticket))
    {
        Err(NetworkBroadcastAdmissionError::Closed { ticket, .. }) => {
            assert!(ticket.awaiting_topology_snapshot());
            assert_eq!(ticket.pending_targets(), 0);
        }
        _ => panic!("closed empty-topology actor must not report perpetual pressure"),
    }
    let (closed_owned_handle, _safety_rx, mut closed_owned_progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let closed_owned_target = random_peer_id();
    reconcile_test_topology!(
        closed_owned_handle.reliable_broadcast_topology,
        &HashSet::from([closed_owned_target])
    );
    let closed_owned_message = Broadcast {
        data: DeferredProgressMsg::Lane(3),
        priority: Priority::High,
    };
    closed_owned_handle
        .broadcast_recoverable(closed_owned_message.clone(), None)
        .expect("first exact broadcast enters actor ownership");
    let closed_owned_child = closed_owned_progress_rx
        .try_recv()
        .expect("exact target child remains live for the close race");
    drop(closed_owned_progress_rx);
    assert!(matches!(
        closed_owned_handle.broadcast_recoverable(closed_owned_message, None),
        Err(NetworkBroadcastAdmissionError::Closed { .. })
    ));
    drop(closed_owned_child);
    let target = random_peer_id();
    reconcile_test_topology!(
        handle.reliable_broadcast_topology,
        &HashSet::from([target.clone()])
    );
    reserve_direct_lane_lease!(handle, target, 11 => direct_lease; "direct fixture must occupy the target lane");
    let nonempty_ticket = match handle.broadcast_recoverable(
        Broadcast {
            data: DeferredProgressMsg::Lane(12),
            priority: Priority::High,
        },
        None,
    ) {
        Err(NetworkBroadcastAdmissionError::Backpressured { ticket, .. }) => ticket,
        _ => panic!("blocked target must return an aggregate with one live waiter"),
    };
    assert_eq!(nonempty_ticket.pending_targets(), 1);
    assert!(matches!(
        other_handle.broadcast_recoverable(
            Broadcast {
                data: DeferredProgressMsg::Lane(12),
                priority: Priority::High,
            },
            Some(nonempty_ticket),
        ),
        Err(NetworkBroadcastAdmissionError::Rejected {
            reason: NetworkActorAdmissionRejection::InvalidTicket,
            ..
        })
    ));
    let original_state = handle
        .network_actor_progress_budget
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(original_state.waiter_count, 0);
    assert_eq!(
        original_state.retained_items, 1,
        "invalid aggregate cleanup must leave the direct owner intact"
    );
    drop(original_state);
    drop(direct_lease);
    assert_eq!(handle.network_actor_progress_budget.retained(), 0);
    let (handle, _safety_rx, progress_rx, _high_rx, _low_rx) =
        handle_with_network_receivers::<DeferredProgressMsg>();
    let peers: HashSet<_> = (0..3).map(|_| random_peer_id()).collect();
    reconcile_test_topology!(handle.reliable_broadcast_topology, &peers);
    drop(progress_rx);
    match handle.broadcast_recoverable(
        Broadcast {
            data: DeferredProgressMsg::Lane(5),
            priority: Priority::High,
        },
        None,
    ) {
        Err(NetworkBroadcastAdmissionError::Closed { ticket, .. }) => {
            assert_eq!(ticket.pending_targets(), 3);
        }
        _ => panic!("closed actor must return every exact target copy"),
    }
}
#[test]
fn reliable_broadcast_snapshot_excludes_connected_observers() {
    let_test_network!(network, DeferredProgressMsg);
    let validator = random_peer_id();
    let observer = random_peer_id();
    let_deferred_peer!(_observer_receivers = &mut network; observer.clone(), socket_addr!(127.0.0.1:45703), 104; capacity 2);
    network.current_topology.insert(validator.clone());
    assert_eq!(
        network.reliable_broadcast_targets(),
        Some(VecDeque::from([validator])),
        "an arbitrary authenticated observer is not part of the protocol fanout snapshot"
    );
    assert!(!network.current_topology.contains(&observer));
}
#[test]
fn flush_deferred_frames_sends_unbound_entries_to_current_session() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45682);
    let (handle, mut receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(&mut network, peer_id.clone(), peer_addr, 7, handle);
    let frame = dummy_relay_frame(network.self_id.clone(), &peer_id);
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        frame,
        Other,
        None,
        tokio::time::Instant::now()
    );
    assert_deferred_flushed!(network, peer_id);
    assert!(
        !network.deferred_send_queue.by_peer.contains_key(&peer_id),
        "successful flush should remove the peer queue"
    );
    let received = receivers
        .try_recv_other()
        .expect("unbound frame should be sent to the current peer session");
    assert_eq!(received.origin, network.self_id);
    match received.target {
        RelayTarget::Direct(target) => assert_eq!(target, peer_id),
        RelayTarget::Broadcast => panic!("expected direct relay target"),
    }
}
#[test]
fn flush_deferred_frames_drops_stale_connection_binding_without_posting() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45683);
    let (handle, mut receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(&mut network, peer_id.clone(), peer_addr, 8, handle);
    let frame = dummy_relay_frame(network.self_id.clone(), &peer_id);
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        frame,
        Other,
        Some(7),
        tokio::time::Instant::now()
    );
    assert_deferred_flushed!(network, peer_id);
    assert!(matches!(receivers.try_recv_any(), Err(TryRecvError::Empty)));
    assert!(
        !network.deferred_send_queue.by_peer.contains_key(&peer_id),
        "stale entries should be dropped instead of restored"
    );
}
#[test]
fn flush_deferred_frames_rebinds_reliable_stale_connection() {
    let_deferred_test_network!(network, DeferredProgressMsg);
    let peer_id = random_peer_id();
    let_deferred_peer!(mut receivers = &mut network; peer_id.clone(), socket_addr!(127.0.0.1:45685), 8; capacity 2);
    assert!(
        defer_frame!(
            network.deferred_send_queue,
            peer_id,
            direct_frame!(
                network.self_id.clone(),
                peer_id,
                DeferredProgressMsg::Lane(7),
            ),
            Consensus,
            Some(7),
            tokio::time::Instant::now()
        )
        .enqueued
    );
    assert_deferred_flushed!(network, peer_id);
    assert_eq!(
        receivers
            .try_recv_any()
            .expect("reliable frame bound to the old connection must reach the replacement")
            .payload,
        DeferredProgressMsg::Lane(7)
    );
}
#[test]
fn flush_deferred_frames_restores_remaining_entries_on_backpressure() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45684);
    let (handle, _receivers) = test_wire_peer_handle::<DummyMsg>(1);
    handle
        .post(dummy_relay_frame(network.self_id.clone(), &peer_id))
        .expect("test peer queue prefill should succeed");
    insert_dummy_ref_peer(&mut network, peer_id.clone(), peer_addr, 9, handle);
    let now = tokio::time::Instant::now();
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        dummy_relay_frame(network.self_id.clone(), &peer_id),
        Other,
        None,
        now
    );
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        dummy_relay_frame(network.self_id.clone(), &peer_id),
        Other,
        None,
        now,
        1
    );
    assert!(matches!(
        network.flush_deferred_frames_for_peer(&peer_id),
        DeferredFlushOutcome::Backpressured(9)
    ));
    let entries = network
        .deferred_send_queue
        .by_peer
        .get(&peer_id)
        .expect("backpressure should keep deferred entries for retry");
    let connection_bindings: Vec<Option<ConnectionId>> = entries
        .iter()
        .map(|entry| entry.bound_connection_id)
        .collect();
    assert_eq!(connection_bindings, vec![None, None]);
}
#[test]
fn full_safety_lane_cannot_block_deferred_block_sync_progress() {
    let_deferred_test_network!(network, DeferredProgressMsg);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45695);
    let (handle, mut receivers) = test_wire_peer_handle::<DeferredProgressMsg>(1);
    handle
        .post(relay_frame(
            network.self_id.clone(),
            &peer_id,
            DeferredProgressMsg::Safety(0),
        ))
        .expect("test safety lane prefill should succeed");
    insert_ref_peer(&mut network, peer_id.clone(), peer_addr, 10, handle, true);
    let now = tokio::time::Instant::now();
    assert!(
        defer_frame!(
            network.deferred_send_queue,
            peer_id,
            relay_frame(
                network.self_id.clone(),
                &peer_id,
                DeferredProgressMsg::Safety(1),
            ),
            ConsensusSafety,
            None,
            now
        )
        .enqueued
    );
    assert!(
        defer_frame!(
            network.deferred_send_queue,
            peer_id,
            relay_frame(
                network.self_id.clone(),
                &peer_id,
                DeferredProgressMsg::BlockSync(2),
            ),
            BlockSync,
            None,
            now,
            1
        )
        .enqueued
    );
    assert_eq!(
        network.flush_deferred_frames_for_peer(&peer_id),
        DeferredFlushOutcome::Backpressured(10)
    );
    assert!(matches!(
        receivers.try_recv_block_sync(),
        Ok(RelayMessage {
            payload: DeferredProgressMsg::BlockSync(2),
            ..
        })
    ));
    assert!(
        !network.deferred_send_queue.by_peer.contains_key(&peer_id),
        "the successfully posted progress witness must leave the deferred queue"
    );
    assert_eq!(
        network
            .deferred_send_queue
            .safety_by_peer
            .get(&peer_id)
            .map(VecDeque::len),
        Some(1),
        "the blocked safety frame must retain exact ownership"
    );
    assert!(matches!(
        receivers.try_recv_consensus_safety(),
        Ok(RelayMessage {
            payload: DeferredProgressMsg::Safety(0),
            ..
        })
    ));
    assert_eq!(
        network.flush_deferred_frames_for_peer(&peer_id),
        DeferredFlushOutcome::Flushed
    );
    assert!(matches!(
        receivers.try_recv_consensus_safety(),
        Ok(RelayMessage {
            payload: DeferredProgressMsg::Safety(1),
            ..
        })
    ));
}
#[test]
fn live_session_backpressure_defers_retry_with_current_connection() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45685);
    let (handle, _receivers) = test_wire_peer_handle::<DummyMsg>(1);
    handle
        .post(dummy_relay_frame(network.self_id.clone(), &peer_id))
        .expect("test peer queue prefill should succeed");
    insert_dummy_ref_peer(&mut network, peer_id.clone(), peer_addr, 55, handle);
    assert!(
        network.send_frame_to_peer(
            &peer_id,
            dummy_relay_frame(network.self_id.clone(), &peer_id),
            message::Topic::Other,
        ),
        "full live peer queue should defer the retry"
    );
    let connection_binding = network
        .deferred_send_queue
        .by_peer
        .get(&peer_id)
        .and_then(|entries| entries.back())
        .map(|entry| entry.bound_connection_id);
    assert_eq!(
        connection_binding,
        Some(Some(55)),
        "live-session retry must remain tied to the connection that backpressured"
    );
}
#[test]
fn deferred_retry_tick_resumes_after_capacity_opens_without_a_new_send() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45696);
    let (handle, mut receivers) = test_wire_peer_handle::<DummyMsg>(1);
    handle
        .post(dummy_relay_frame(network.self_id.clone(), &peer_id))
        .expect("test peer queue prefill should succeed");
    insert_dummy_ref_peer(&mut network, peer_id.clone(), peer_addr, 56, handle);
    assert!(network.send_frame_to_peer(
        &peer_id,
        dummy_relay_frame(network.self_id.clone(), &peer_id),
        message::Topic::Other,
    ));
    assert!(network.deferred_send_queue.retry_members.contains(&peer_id));
    let _prefill = receivers
        .try_recv_other()
        .expect("draining the peer lane should open capacity");
    network.retry_deferred_frames();
    assert!(
        receivers.try_recv_other().is_ok(),
        "the retry clock must deliver retained work without another outbound post"
    );
    assert!(!network.deferred_send_queue.by_peer.contains_key(&peer_id));
    assert!(!network.deferred_send_queue.retry_members.contains(&peer_id));
}
#[test]
fn flush_deferred_frames_expires_entries_before_posting() {
    let_deferred_test_network!(network);
    network.deferred_send_queue = DeferredPeerFrameQueue::new(4, usize::MAX, Duration::ZERO);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45689);
    let (handle, mut receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(&mut network, peer_id.clone(), peer_addr, 91, handle);
    let dropped_before = deferred_send_dropped_count();
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        dummy_relay_frame(network.self_id.clone(), &peer_id),
        Other,
        None,
        tokio::time::Instant::now()
    );
    assert_deferred_flushed!(network, peer_id);
    assert!(matches!(receivers.try_recv_any(), Err(TryRecvError::Empty)));
    assert!(
        !network.deferred_send_queue.by_peer.contains_key(&peer_id),
        "expired deferred entries should be removed during flush"
    );
    assert!(
        deferred_send_dropped_count() >= dropped_before.saturating_add(1),
        "expired flush should increment the deferred-drop counter"
    );
}
#[test]
fn send_frame_to_peer_flushes_queued_frame_and_sends_current_frame() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45690);
    let (handle, mut receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(&mut network, peer_id.clone(), peer_addr, 92, handle);
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        dummy_relay_frame(network.self_id.clone(), &peer_id),
        Other,
        None,
        tokio::time::Instant::now()
    );
    assert!(
        network.send_frame_to_peer(
            &peer_id,
            dummy_relay_frame(network.self_id.clone(), &peer_id),
            message::Topic::Other,
        ),
        "current frame should be posted after queued frames flush"
    );
    assert!(
        !network.deferred_send_queue.by_peer.contains_key(&peer_id),
        "successful send should leave no deferred queue"
    );
    receivers
        .try_recv_other()
        .expect("queued frame should be posted");
    receivers
        .try_recv_other()
        .expect("current frame should be posted");
    assert!(matches!(receivers.try_recv_any(), Err(TryRecvError::Empty)));
}
#[test]
fn send_frame_to_peer_defers_current_frame_when_deferred_flush_backpressures() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45691);
    let (handle, _receivers) = test_wire_peer_handle::<DummyMsg>(1);
    handle
        .post(dummy_relay_frame(network.self_id.clone(), &peer_id))
        .expect("test peer queue prefill should succeed");
    insert_dummy_ref_peer(&mut network, peer_id.clone(), peer_addr, 93, handle);
    let now = tokio::time::Instant::now();
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        dummy_relay_frame(network.self_id.clone(), &peer_id),
        Other,
        None,
        now
    );
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        dummy_relay_frame(network.self_id.clone(), &peer_id),
        Other,
        None,
        now,
        1
    );
    assert!(
        network.send_frame_to_peer(
            &peer_id,
            dummy_relay_frame(network.self_id.clone(), &peer_id),
            message::Topic::Other,
        ),
        "current frame should be deferred when deferred flush hits backpressure"
    );
    let entries = network
        .deferred_send_queue
        .by_peer
        .get(&peer_id)
        .expect("backpressure should keep deferred entries for retry");
    let connection_bindings: Vec<Option<ConnectionId>> = entries
        .iter()
        .map(|entry| entry.bound_connection_id)
        .collect();
    assert_eq!(connection_bindings, vec![None, None, Some(93)]);
}
#[test]
fn send_frame_to_peer_defers_current_frame_after_deferred_flush_closes_session() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45692);
    let (handle, receivers) = test_wire_peer_handle::<DummyMsg>(4);
    drop(receivers);
    insert_dummy_ref_peer(&mut network, peer_id.clone(), peer_addr.clone(), 94, handle);
    network.current_topology.insert(peer_id.clone());
    network
        .current_peers_addresses
        .push((peer_id.clone(), peer_addr.clone()));
    network.retry_backoff.insert(
        peer_id.clone(),
        HashMap::from([(
            peer_addr.to_string(),
            (
                tokio::time::Instant::now() + Duration::from_secs(1),
                Duration::from_millis(25),
            ),
        )]),
    );
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        dummy_relay_frame(network.self_id.clone(), &peer_id),
        Other,
        Some(94),
        tokio::time::Instant::now()
    );
    assert!(
        network.send_frame_to_peer(
            &peer_id,
            dummy_relay_frame(network.self_id.clone(), &peer_id),
            message::Topic::Other,
        ),
        "current frame should be deferred after flush removes a closed session"
    );
    assert!(
        !network.peers.contains_key(&peer_id),
        "closed deferred flush should remove the peer"
    );
    let entries = network
        .deferred_send_queue
        .by_peer
        .get(&peer_id)
        .expect("both unsent frames should be queued for the next session");
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .all(|entry| entry.bound_connection_id.is_none())
    );
    assert!(
        !network.pending_connects.is_empty(),
        "closed-session flush should schedule reconnect work"
    );
}
#[test]
fn flush_deferred_frames_restores_all_entries_when_peer_missing() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let now = tokio::time::Instant::now();
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        dummy_relay_frame(network.self_id.clone(), &peer_id),
        Other,
        None,
        now
    );
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        dummy_relay_frame(network.self_id.clone(), &peer_id),
        Other,
        Some(77),
        now,
        1
    );
    assert!(matches!(
        network.flush_deferred_frames_for_peer(&peer_id),
        DeferredFlushOutcome::PeerMissing
    ));
    let connection_bindings: Vec<Option<ConnectionId>> = network
        .deferred_send_queue
        .by_peer
        .get(&peer_id)
        .expect("peer-missing flush should restore queued frames")
        .iter()
        .map(|entry| entry.bound_connection_id)
        .collect();
    assert_eq!(
        connection_bindings,
        vec![None, Some(77)],
        "unposted frames should stay queued in their original order"
    );
}
#[test]
fn flush_deferred_frames_closed_session_restores_remaining_unbound() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45686);
    let (handle, receivers) = test_wire_peer_handle::<DummyMsg>(4);
    drop(receivers);
    insert_dummy_ref_peer(&mut network, peer_id.clone(), peer_addr, 88, handle);
    network.incoming_active.insert(88);
    network
        .last_active
        .insert(peer_id.clone(), tokio::time::Instant::now());
    let now = tokio::time::Instant::now();
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        dummy_relay_frame(network.self_id.clone(), &peer_id),
        Other,
        Some(88),
        now
    );
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        dummy_relay_frame(network.self_id.clone(), &peer_id),
        Other,
        Some(88),
        now,
        1
    );
    assert!(matches!(
        network.flush_deferred_frames_for_peer(&peer_id),
        DeferredFlushOutcome::PeerMissing
    ));
    assert!(
        !network.peers.contains_key(&peer_id),
        "closed peer handle should remove the peer"
    );
    assert!(
        !network.incoming_active.contains(&88),
        "closed peer handle should clear incoming activity"
    );
    assert!(
        !network.last_active.contains_key(&peer_id),
        "closed peer handle should clear last-active state"
    );
    let entries = network
        .deferred_send_queue
        .by_peer
        .get(&peer_id)
        .expect("all unsent deferred frames should be restored for a future session");
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .all(|entry| entry.bound_connection_id.is_none()),
        "all unsent entries must be unbound after the old session is removed"
    );
}
#[test]
fn live_session_closed_defers_retry_unbound_and_removes_peer() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45687);
    let (handle, receivers) = test_wire_peer_handle::<DummyMsg>(4);
    drop(receivers);
    insert_dummy_ref_peer(&mut network, peer_id.clone(), peer_addr.clone(), 89, handle);
    network.current_topology.insert(peer_id.clone());
    network
        .current_peers_addresses
        .push((peer_id.clone(), peer_addr.clone()));
    network.retry_backoff.insert(
        peer_id.clone(),
        HashMap::from([(
            peer_addr.to_string(),
            (
                tokio::time::Instant::now() + Duration::from_secs(1),
                Duration::from_millis(25),
            ),
        )]),
    );
    assert!(
        network.send_frame_to_peer(
            &peer_id,
            dummy_relay_frame(network.self_id.clone(), &peer_id),
            message::Topic::Other,
        ),
        "closed live peer should defer the retry for a future session"
    );
    assert!(
        !network.peers.contains_key(&peer_id),
        "closed peer handle should remove the live peer"
    );
    assert_eq!(
        network
            .deferred_send_queue
            .by_peer
            .get(&peer_id)
            .and_then(|entries| entries.front())
            .map(|entry| entry.bound_connection_id),
        Some(None),
        "retry should not be tied to the closed transport tenure"
    );
    assert!(
        !network.pending_connects.is_empty(),
        "closed live peer should schedule reconnect work when it remains in topology"
    );
}
#[test]
fn flush_deferred_frames_skips_trust_gossip_when_peer_capability_disabled() {
    let _guard = deferred_send_test_guard();
    let_test_network!(network, TopicMsg);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45688);
    let (handle, receivers) = test_wire_peer_handle::<TopicMsg>(4);
    drop(receivers);
    insert_ref_peer(&mut network, peer_id.clone(), peer_addr, 90, handle, false);
    let skipped_before = trust_gossip_skipped_capability_off_count();
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        relay_frame(network.self_id.clone(), &peer_id, TopicMsg::Trust,),
        TrustGossip,
        None,
        tokio::time::Instant::now()
    );
    assert_deferred_flushed!(network, peer_id);
    assert!(
        !network.deferred_send_queue.by_peer.contains_key(&peer_id),
        "capability-skipped frames should not be restored"
    );
    assert!(
        network.peers.contains_key(&peer_id),
        "capability skip should not drop an otherwise live peer"
    );
    assert!(
        trust_gossip_skipped_capability_off_count() >= skipped_before.saturating_add(1),
        "capability skip metric should increment"
    );
}
#[test]
fn flush_deferred_frames_skips_trust_gossip_when_local_capability_disabled() {
    let _guard = deferred_send_test_guard();
    let_test_network!(network, TopicMsg);
    network.trust_gossip = false;
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45693);
    let (handle, mut receivers) = test_wire_peer_handle::<TopicMsg>(4);
    insert_ref_peer(&mut network, peer_id.clone(), peer_addr, 95, handle, true);
    let skipped_before = trust_gossip_skipped_capability_off_count();
    let _ = defer_frame!(
        network.deferred_send_queue,
        peer_id,
        relay_frame(network.self_id.clone(), &peer_id, TopicMsg::Trust,),
        TrustGossip,
        None,
        tokio::time::Instant::now()
    );
    assert_deferred_flushed!(network, peer_id);
    assert!(
        !network.deferred_send_queue.by_peer.contains_key(&peer_id),
        "locally skipped trust-gossip frames should not be restored"
    );
    assert!(matches!(receivers.try_recv_any(), Err(TryRecvError::Empty)));
    assert!(
        trust_gossip_skipped_capability_off_count() >= skipped_before.saturating_add(1),
        "local capability skip metric should increment"
    );
}
#[test]
fn live_session_skips_trust_gossip_when_peer_capability_disabled() {
    let _guard = deferred_send_test_guard();
    let_test_network!(network, TopicMsg);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45694);
    let (handle, mut receivers) = test_wire_peer_handle::<TopicMsg>(4);
    insert_ref_peer(&mut network, peer_id.clone(), peer_addr, 96, handle, false);
    let skipped_before = trust_gossip_skipped_capability_off_count();
    assert!(
        !network.send_frame_to_peer(
            &peer_id,
            relay_frame(network.self_id.clone(), &peer_id, TopicMsg::Trust,),
            message::Topic::TrustGossip,
        ),
        "live trust-gossip send should be skipped when peer lacks capability"
    );
    assert!(
        !network.deferred_send_queue.by_peer.contains_key(&peer_id),
        "capability skip should not defer the live frame"
    );
    assert!(matches!(receivers.try_recv_any(), Err(TryRecvError::Empty)));
    assert!(
        network.peers.contains_key(&peer_id),
        "capability skip should keep the live peer"
    );
    assert!(
        trust_gossip_skipped_capability_off_count() >= skipped_before.saturating_add(1),
        "live capability skip metric should increment"
    );
}
#[test]
fn live_session_post_overflow_disconnect_policy_defers_unbound() {
    let_deferred_test_network!(network);
    network.disconnect_on_post_overflow = true;
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45695);
    let (handle, _receivers) = test_wire_peer_handle::<DummyMsg>(1);
    handle
        .post(dummy_relay_frame(network.self_id.clone(), &peer_id))
        .expect("test peer queue prefill should succeed");
    insert_dummy_ref_peer(&mut network, peer_id.clone(), peer_addr.clone(), 97, handle);
    network.current_topology.insert(peer_id.clone());
    network
        .current_peers_addresses
        .push((peer_id.clone(), peer_addr.clone()));
    network.retry_backoff.insert(
        peer_id.clone(),
        HashMap::from([(
            peer_addr.to_string(),
            (
                tokio::time::Instant::now() + Duration::from_secs(1),
                Duration::from_millis(25),
            ),
        )]),
    );
    let overflows_before = post_overflow_count();
    assert!(
        network.send_frame_to_peer(
            &peer_id,
            dummy_relay_frame(network.self_id.clone(), &peer_id),
            message::Topic::Other,
        ),
        "overflow disconnect policy should defer the retry for a future session"
    );
    assert!(
        !network.peers.contains_key(&peer_id),
        "overflow disconnect policy should remove the peer"
    );
    assert_eq!(
        network
            .deferred_send_queue
            .by_peer
            .get(&peer_id)
            .and_then(|entries| entries.front())
            .map(|entry| entry.bound_connection_id),
        Some(None),
        "retry after overflow disconnect should not keep the old connection binding"
    );
    assert!(
        !network.pending_connects.is_empty(),
        "overflow disconnect should schedule reconnect work"
    );
    assert!(
        post_overflow_count() >= overflows_before.saturating_add(1),
        "overflow counter should increment"
    );
}
#[test]
fn send_frame_to_self_is_not_deferred() {
    let_deferred_test_network!(network);
    let self_id = network.self_id.clone();
    assert!(
        !network.send_frame_to_peer(
            &self_id,
            dummy_relay_frame(network.self_id.clone(), &self_id),
            message::Topic::Other,
        ),
        "self-directed direct frames should not be sent"
    );
    assert!(
        !network.deferred_send_queue.by_peer.contains_key(&self_id),
        "self-directed direct frames should not be deferred"
    );
}
#[test]
fn post_routes_unconnected_target_through_live_hub() {
    let_deferred_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
    let hub_id = random_peer_id();
    let hub_addr = socket_addr!(127.0.0.1:45696);
    let target_id = random_peer_id();
    let (hub_handle, mut hub_receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(
        &mut network,
        hub_id.clone(),
        hub_addr.clone(),
        98,
        hub_handle,
    );
    network.relay_hub_addresses.push(hub_addr.clone());
    network
        .current_peers_addresses
        .push((hub_id.clone(), hub_addr));
    network.relay_trusted_peers.insert(hub_id.clone());
    network.current_topology.insert(hub_id.clone());
    network
        .peers
        .get_mut(&hub_id)
        .expect("connected relay hub")
        .relay_role = RelayRole::Hub;
    network.relay_hub_peer = Some(hub_id);
    network.post(Post {
        data: DummyMsg,
        peer_id: target_id.clone(),
        priority: Priority::High,
    });
    let received = hub_receivers
        .try_recv_other()
        .expect("unconnected target should be routed through the hub");
    assert_eq!(received.origin, network.self_id);
    match received.target {
        RelayTarget::Direct(target) => assert_eq!(target, target_id),
        RelayTarget::Broadcast => panic!("expected direct relay target"),
    }
    assert!(
        !network.deferred_send_queue.by_peer.contains_key(&target_id),
        "hub-routed post should not also defer against the unconnected target"
    );
}
#[test]
fn post_prefers_connected_target_over_hub_route() {
    let_deferred_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
    let hub_id = random_peer_id();
    let hub_addr = socket_addr!(127.0.0.1:45697);
    let target_id = random_peer_id();
    let target_addr = socket_addr!(127.0.0.1:45698);
    let (hub_handle, mut hub_receivers) = test_wire_peer_handle::<DummyMsg>(4);
    let (target_handle, mut target_receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(
        &mut network,
        hub_id.clone(),
        hub_addr.clone(),
        99,
        hub_handle,
    );
    insert_dummy_ref_peer(
        &mut network,
        target_id.clone(),
        target_addr,
        100,
        target_handle,
    );
    network.relay_hub_addresses.push(hub_addr.clone());
    network
        .current_peers_addresses
        .push((hub_id.clone(), hub_addr));
    network.current_topology.insert(hub_id);
    network.post(Post {
        data: DummyMsg,
        peer_id: target_id.clone(),
        priority: Priority::Low,
    });
    let received = target_receivers
        .try_recv_other()
        .expect("connected target should receive the direct post");
    match received.target {
        RelayTarget::Direct(target) => assert_eq!(target, target_id),
        RelayTarget::Broadcast => panic!("expected direct relay target"),
    }
    assert!(matches!(
        hub_receivers.try_recv_other(),
        Err(TryRecvError::Empty)
    ));
}
#[test]
fn broadcast_sends_broadcast_frame_to_all_connected_peers() {
    let_deferred_test_network!(network);
    let peer_one = random_peer_id();
    let peer_two = random_peer_id();
    let (handle_one, mut receivers_one) = test_wire_peer_handle::<DummyMsg>(4);
    let (handle_two, mut receivers_two) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(
        &mut network,
        peer_one,
        socket_addr!(127.0.0.1:45699),
        101,
        handle_one,
    );
    insert_dummy_ref_peer(
        &mut network,
        peer_two,
        socket_addr!(127.0.0.1:45700),
        102,
        handle_two,
    );
    network.broadcast(Broadcast {
        data: DummyMsg,
        priority: Priority::High,
    });
    for received in [
        receivers_one
            .try_recv_other()
            .expect("first peer should receive broadcast"),
        receivers_two
            .try_recv_other()
            .expect("second peer should receive broadcast"),
    ] {
        assert_eq!(received.origin, network.self_id);
        assert!(matches!(received.target, RelayTarget::Broadcast));
    }
}
#[test]
fn forwarded_low_topic_uses_semantic_priority_for_egress() {
    let_deferred_test_network!(network);
    let incoming_peer = test_peer(socket_addr!(127.0.0.1:45701));
    let other_id = random_peer_id();
    let (incoming_handle, mut incoming_receivers) = test_wire_peer_handle::<DummyMsg>(4);
    let (other_handle, mut other_receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(
        &mut network,
        incoming_peer.id().clone(),
        incoming_peer.address().clone(),
        103,
        incoming_handle,
    );
    insert_dummy_ref_peer(
        &mut network,
        other_id,
        socket_addr!(127.0.0.1:45702),
        104,
        other_handle,
    );
    let origin_key_pair = random_node_key_pair();
    let origin = PeerId::from(origin_key_pair.public_key().clone());
    let relay = RelayMessage::new_signed(
        &origin_key_pair,
        RelayTarget::Broadcast,
        DEFAULT_RELAY_TTL,
        DummyMsg,
    );
    assert_eq!(
        message::ClassifyTopic::priority(&relay),
        Priority::Low,
        "relay egress priority must come from payload semantics"
    );
    network.forward_broadcast(
        &incoming_peer,
        &relay,
        DEFAULT_RELAY_TTL - 1,
        message::Topic::Other,
    );
    assert!(matches!(
        incoming_receivers.try_recv_other(),
        Err(TryRecvError::Empty)
    ));
    let received = other_receivers
        .try_recv_other()
        .expect("low-semantic relay should use the low egress lane");
    assert!(matches!(
        other_receivers.try_recv_high_control(),
        Err(TryRecvError::Empty)
    ));
    assert_eq!(received.origin, origin);
    assert!(matches!(received.target, RelayTarget::Broadcast));
    assert_eq!(received.ttl, DEFAULT_RELAY_TTL - 1);
    received
        .verify_origin_signature()
        .expect("TTL-only forwarding must preserve the origin signature");
}
#[test]
fn forward_direct_drops_frame_targeted_at_sender() {
    let_deferred_test_network!(network);
    let incoming_peer = test_peer(socket_addr!(127.0.0.1:45703));
    let (handle, mut receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(
        &mut network,
        incoming_peer.id().clone(),
        incoming_peer.address().clone(),
        105,
        handle,
    );
    let origin_key_pair = random_node_key_pair();
    let relay = RelayMessage::new_signed(
        &origin_key_pair,
        RelayTarget::Direct(incoming_peer.id().clone()),
        DEFAULT_RELAY_TTL,
        DummyMsg,
    );
    network.forward_direct(
        &incoming_peer,
        &relay,
        incoming_peer.id(),
        DEFAULT_RELAY_TTL - 1,
        message::Topic::Other,
    );
    assert!(matches!(receivers.try_recv_any(), Err(TryRecvError::Empty)));
}
#[test]
fn relay_hub_selection_requires_trusted_peer_when_allowlist_present() {
    let_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
    let hub_addr = socket_addr!(127.0.0.1:45704);
    let hub_id = random_peer_id();
    let trusted_other = random_peer_id();
    let target = random_peer_id();
    network.relay_hub_addresses.push(hub_addr.clone());
    network
        .current_peers_addresses
        .push((hub_id.clone(), hub_addr));
    network.current_topology.insert(hub_id);
    network.relay_trusted_peers.insert(trusted_other);
    assert_eq!(
        network.relay_route_for_unconnected_post_target(&target),
        None,
        "configured hubs outside the trusted relay set should not be selected"
    );
    assert!(
        network.relay_hub_peer.is_none(),
        "untrusted configured hub should leave no selected relay hub"
    );
}
#[test]
fn relay_hub_selection_clears_when_mode_disabled() {
    let_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
    let hub_addr = socket_addr!(127.0.0.1:45705);
    let hub_id = random_peer_id();
    network.relay_hub_addresses.push(hub_addr.clone());
    network.relay_trusted_peers.insert(hub_id.clone());
    let (handle, _receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(&mut network, hub_id.clone(), hub_addr, 45705, handle);
    network
        .peers
        .get_mut(&hub_id)
        .expect("authenticated hub peer")
        .relay_role = RelayRole::Hub;
    network.relay_hub_peer = Some(hub_id.clone());
    assert_eq!(network.ensure_hub_peer(), Some(hub_id));
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Disabled;
    assert_eq!(network.ensure_hub_peer(), None);
    assert!(
        network.relay_hub_peer.is_none(),
        "relay hub selection should be cleared outside relay modes"
    );
}
#[test]
fn spoke_startup_grants_hub_authority_only_after_exact_outbound_dial() {
    let_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
    replace_test_authenticated_source_geometry(&mut network, 1, Some(HashSet::new()));
    let hub = test_peer(socket_addr!(127.0.0.1:45707));
    let arbitrary = test_peer(socket_addr!(127.0.0.1:45708));
    network.relay_hub_addresses.push(hub.address().clone());
    network.set_current_peers_addresses(UpdatePeers(vec![
        (hub.id().clone(), hub.address().clone()),
        (arbitrary.id().clone(), arbitrary.address().clone()),
    ]));
    assert!(network.relay_hub_peer.is_none());
    assert!(network.current_topology.is_empty());
    assert!(network.relay_hub_candidates.contains(hub.id()));
    assert!(!network.relay_trusted_peers.contains(hub.id()));
    assert!(
        network
            .pending_connects
            .iter()
            .any(|(_, candidate)| candidate == &hub),
        "address resolution should schedule the configured hub candidate"
    );
    assert!(
        network
            .pending_connects
            .iter()
            .all(|(_, candidate)| candidate.id() != arbitrary.id()),
        "spoke startup must not dial an arbitrary resolved peer"
    );
    assert_eq!(
        network.inbound_frame_byte_budgets.protected_sources(),
        Some(HashSet::new())
    );
    let arbitrary_conn_id = 45_708;
    reserve_test_incoming(&mut network, arbitrary_conn_id);
    connect_test_peer!(network, arbitrary, arbitrary_conn_id, 0, Hub => arbitrary_receivers, mut arbitrary_receiver);
    assert!(arbitrary_receivers.termination_requested());
    assert!(matches!(
        arbitrary_receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    assert!(!network.peers.contains_key(arbitrary.id()));
    assert_eq!(
        network.inbound_frame_byte_budgets.protected_sources(),
        Some(HashSet::new())
    );
    let wrong_role_conn_id = 45_709;
    reserve_test_incoming(&mut network, wrong_role_conn_id);
    connect_test_peer!(network, hub, wrong_role_conn_id, 0, Spoke => wrong_role_receivers, mut wrong_role_receiver);
    assert!(wrong_role_receivers.termination_requested());
    assert!(matches!(
        wrong_role_receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    assert!(network.relay_hub_peer.is_none());
    let inbound_hub_conn_id = 45_710;
    reserve_test_incoming(&mut network, inbound_hub_conn_id);
    connect_test_peer!(network, hub, inbound_hub_conn_id, 1, Hub => inbound_hub_receivers, mut inbound_hub_receiver);
    assert!(inbound_hub_receivers.termination_requested());
    assert!(matches!(
        inbound_hub_receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    assert!(
        !network.relay_trusted_peers.contains(hub.id()),
        "an inbound-first identity must not gain authority from address gossip"
    );
    let hub_conn_id = 45_710;
    let hub_conn_id = hub_conn_id + 1;
    network.connecting_peers.insert(hub_conn_id, hub.clone());
    network.outbound_connections.insert(hub_conn_id);
    connect_test_peer!(network, hub, hub_conn_id, 1, Hub => hub_receivers, mut hub_receiver);
    assert!(hub_receiver.try_recv().is_ok());
    assert!(!hub_receivers.termination_requested());
    assert!(network.relay_trusted_peers.contains(hub.id()));
    assert_eq!(network.relay_hub_peer, Some(hub.id().clone()));
    assert_eq!(network.current_topology, HashSet::from([hub.id().clone()]));
    assert_eq!(
        network.inbound_frame_byte_budgets.protected_sources(),
        Some(HashSet::from([hub.id().clone()]))
    );

    let refreshed_address = socket_addr!(127.0.0.1:45709);
    network.set_current_peers_addresses(UpdatePeers(vec![(hub.id().clone(), refreshed_address)]));
    assert!(
        !network.relay_hub_candidates.contains(hub.id()),
        "a refreshed non-hub address must not remain an unproven dial candidate"
    );
    assert!(
        network.relay_trusted_peers.contains(hub.id()),
        "address gossip must not revoke authority established by an exact authenticated dial"
    );
    assert_eq!(network.relay_hub_peer, Some(hub.id().clone()));
}
#[test]
fn configured_hub_detection_prefers_trusted_peer_allowlist() {
    let_test_network!(network);
    let trusted_peer = test_peer(socket_addr!(127.0.0.1:45706));
    let untrusted_peer = test_peer(socket_addr!(127.0.0.1:45706));
    network
        .relay_trusted_peers
        .insert(trusted_peer.id().clone());
    assert!(network.is_configured_hub_peer(&trusted_peer, RelayRole::Hub));
    assert!(
        !network.is_configured_hub_peer(&untrusted_peer, RelayRole::Hub),
        "trusted relay allowlist should override address-only hub matching"
    );
    assert!(
        !network.is_configured_hub_peer(&trusted_peer, RelayRole::Spoke),
        "non-hub relay roles should not be treated as configured hubs"
    );
}
#[test]
fn malformed_runtime_acl_is_rejected_before_staging() {
    let_test_network!(network);
    let allowed_peer = random_peer_id();
    assert!(network.set_reply_source_acl(message::UpdateAcl {
        allowlist_only: true,
        allow_keys: vec![allowed_peer.public_key().clone()],
        allow_cidrs: vec!["10.0.0.0/8".to_owned()],
        ..message::UpdateAcl::default()
    }));
    assert!(network.pending_reply_source_authority.is_empty());
    assert!(network.projected_reply_source_acl_allows(&allowed_peer));
    assert_eq!(network.allow_nets.len(), 1);

    assert!(!network.set_reply_source_acl(message::UpdateAcl {
        deny_keys: vec![allowed_peer.public_key().clone()],
        allow_cidrs: vec!["10.0.0.0/33".to_owned()],
        ..message::UpdateAcl::default()
    }));

    assert!(
        network.pending_reply_source_authority.is_empty(),
        "a malformed update must not enter the pending authority state"
    );
    assert!(network.allowlist_only);
    assert!(network.allow_keys.contains(allowed_peer.public_key()));
    assert!(network.deny_keys.is_empty());
    assert_eq!(network.allow_nets.len(), 1);
    assert!(network.projected_reply_source_acl_allows(&allowed_peer));
}
#[test]
fn acl_revoked_hub_address_cannot_recreate_a_dial_candidate() {
    let_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Assist;
    let hub = test_peer(socket_addr!(127.0.0.1:45710));
    network.relay_hub_addresses.push(hub.address().clone());
    network.apply_reply_source_acl(
        ValidatedAclUpdate::parse(message::UpdateAcl {
            deny_keys: vec![hub.id().public_key().clone()],
            ..message::UpdateAcl::default()
        })
        .expect("test ACL is valid"),
    );

    network
        .set_current_peers_addresses(UpdatePeers(vec![(hub.id().clone(), hub.address().clone())]));

    assert!(!network.relay_hub_candidates.contains(hub.id()));
    assert!(!network.relay_trusted_peers.contains(hub.id()));
    assert!(
        network
            .pending_connects
            .iter()
            .all(|(_, candidate)| candidate.id() != hub.id())
    );

    network.apply_reply_source_acl(
        ValidatedAclUpdate::parse(message::UpdateAcl::default()).expect("default ACL is valid"),
    );

    assert!(
        network.relay_hub_candidates.contains(hub.id()),
        "broadening the ACL should immediately restore the configured hub dial identity"
    );
}
#[test]
fn malformed_runtime_acl_update_preserves_applied_policy() {
    let_test_network!(network);
    let denied_key = random_node_key_pair().public_key().clone();

    network.set_reply_source_acl(message::UpdateAcl {
        allowlist_only: true,
        deny_keys: vec![denied_key.clone()],
        allow_cidrs: vec!["10.0.0.0/33".to_owned()],
        ..message::UpdateAcl::default()
    });

    assert!(!network.allowlist_only);
    assert!(!network.deny_keys.contains(&denied_key));
    assert!(network.pending_reply_source_authority.is_empty());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_message_hub_forwards_direct_frame_with_decremented_ttl() {
    let_test_network!(network, DummyMsg);
    network.relay_role = RelayRole::Hub;
    network.relay_ttl = 3;
    let incoming_key_pair = random_node_key_pair();
    let incoming_peer = Peer::new(
        socket_addr!(127.0.0.1:45707),
        incoming_key_pair.public_key().clone(),
    );
    let target_id = random_peer_id();
    let (target_handle, mut target_receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(
        &mut network,
        target_id.clone(),
        socket_addr!(127.0.0.1:45708),
        106,
        target_handle,
    );
    network
        .peer_message(PeerMessage::new(
            incoming_peer.clone(),
            RelayMessage::new_signed(
                &incoming_key_pair,
                RelayTarget::Direct(target_id.clone()),
                u8::MAX,
                DummyMsg,
            ),
            1,
        ))
        .await;
    let forwarded = target_receivers
        .try_recv_other()
        .expect("hub should forward direct relay frame to target");
    assert!(matches!(
        target_receivers.try_recv_high_control(),
        Err(TryRecvError::Empty)
    ));
    assert_eq!(forwarded.origin, *incoming_peer.id());
    assert_eq!(
        forwarded.ttl, 2,
        "inbound hop metadata must be clamped to the local relay limit before forwarding"
    );
    match forwarded.target {
        RelayTarget::Direct(target) => assert_eq!(target, target_id),
        RelayTarget::Broadcast => panic!("expected direct relay target"),
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_message_hub_drops_expired_direct_frame_for_remote_target() {
    let_test_network!(network, DummyMsg);
    network.relay_role = RelayRole::Hub;
    let incoming_key_pair = random_node_key_pair();
    let incoming_peer = Peer::new(
        socket_addr!(127.0.0.1:45709),
        incoming_key_pair.public_key().clone(),
    );
    let target_id = random_peer_id();
    let (target_handle, mut target_receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(
        &mut network,
        target_id.clone(),
        socket_addr!(127.0.0.1:45710),
        107,
        target_handle,
    );
    network
        .peer_message(PeerMessage::new(
            incoming_peer.clone(),
            RelayMessage::new_signed(
                &incoming_key_pair,
                RelayTarget::Direct(target_id),
                0,
                DummyMsg,
            ),
            1,
        ))
        .await;
    assert!(matches!(
        target_receivers.try_recv_other(),
        Err(TryRecvError::Empty)
    ));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_message_hub_broadcast_forwards_and_delivers_locally() {
    let_test_network!(network, DummyMsg);
    network.relay_role = RelayRole::Hub;
    let incoming_key_pair = random_node_key_pair();
    let incoming_peer = Peer::new(
        socket_addr!(127.0.0.1:45711),
        incoming_key_pair.public_key().clone(),
    );
    let other_id = random_peer_id();
    let (other_handle, mut other_receivers) = test_wire_peer_handle::<DummyMsg>(4);
    insert_dummy_ref_peer(
        &mut network,
        other_id,
        socket_addr!(127.0.0.1:45712),
        108,
        other_handle,
    );
    let (subscriber_tx, mut subscriber_rx) = mpsc::channel(1);
    network.subscribe_to_peers_messages(Subscriber::new(subscriber_tx, SubscriberFilter::All, 1));
    network
        .peer_message(PeerMessage::new(
            incoming_peer.clone(),
            RelayMessage::new_signed(&incoming_key_pair, RelayTarget::Broadcast, 2, DummyMsg),
            1,
        ))
        .await;
    let forwarded = other_receivers
        .try_recv_other()
        .expect("hub should forward broadcast relay frame");
    assert_eq!(forwarded.origin, *incoming_peer.id());
    assert_eq!(forwarded.ttl, 1);
    assert!(matches!(forwarded.target, RelayTarget::Broadcast));
    let delivered = subscriber_rx
        .try_recv()
        .expect("hub should deliver broadcast locally");
    assert_eq!(delivered.peer.id(), incoming_peer.id());
}
#[test]
fn missing_session_consensus_burst_is_bounded_and_coalesces_reconnect() {
    let_deferred_test_network!(network);
    let peer_id = random_peer_id();
    let peer_addr = socket_addr!(127.0.0.1:45680);
    network.current_topology.insert(peer_id.clone());
    network
        .current_peers_addresses
        .push((peer_id.clone(), peer_addr.clone()));
    let now = tokio::time::Instant::now();
    network.retry_backoff.insert(
        peer_id.clone(),
        HashMap::from([(
            peer_addr.to_string(),
            (now + Duration::from_secs(2), Duration::from_millis(50)),
        )]),
    );
    let reconnect_before = session_reconnect_total();
    let capacity = network.deferred_send_queue.max_per_peer;
    let lane_capacity = network.deferred_send_queue.progress_count_capacity(
        &peer_id,
        message::Topic::Consensus,
        message::SubscriberRoute::General,
    );
    assert_eq!(
        lane_capacity,
        capacity
            .checked_sub(2)
            .expect("deferred geometry reserves safety and bulk slots"),
        "a lane flood must leave one exact service rank for safety and bulk progress"
    );
    let attempts = capacity.saturating_add(8);
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for _ in 0..attempts {
        let frame = direct_frame!(network.self_id.clone(), peer_id, DummyMsg,);
        if network.send_frame_to_peer(&peer_id, frame, message::Topic::Consensus) {
            accepted = accepted.saturating_add(1);
        } else {
            rejected = rejected.saturating_add(1);
        }
    }
    assert_eq!(
        accepted, lane_capacity,
        "bounded lane admission must stop at its exact class-isolated capacity"
    );
    assert_eq!(
        rejected,
        attempts.saturating_sub(lane_capacity),
        "every lane attempt beyond its reserved share must report failure"
    );
    {
        let entries =
            network.deferred_send_queue.by_peer.get(&peer_id).expect(
                "accepted progress frames should remain source-owned by the deferred queue",
            );
        assert_eq!(entries.len(), lane_capacity);
        assert!(
            entries
                .iter()
                .all(|entry| entry.bound_connection_id.is_none())
        );
    }
    for topic in [message::Topic::BlockSync, message::Topic::ConsensusSafety] {
        let frame = direct_frame!(network.self_id.clone(), peer_id, DummyMsg,);
        assert!(
            network.send_frame_to_peer(&peer_id, frame, topic),
            "the count ranks reserved from the lane flood must admit {topic:?}"
        );
    }
    let (retained, _, safety_retained, _) = network
        .deferred_send_queue
        .peer_retained(&peer_id)
        .expect("class-isolated progress entries remain accounted");
    assert_eq!(retained, capacity);
    assert_eq!(safety_retained, 1);
    assert_eq!(
        network.deferred_send_queue.by_peer[&peer_id].len(),
        capacity.saturating_sub(1)
    );
    assert!(
        network.deferred_send_queue.by_peer[&peer_id]
            .iter()
            .chain(network.deferred_send_queue.safety_by_peer[&peer_id].iter())
            .all(|entry| entry.bound_connection_id.is_none())
    );
    let overflow = direct_frame!(network.self_id.clone(), peer_id, DummyMsg,);
    assert!(
        !network.send_frame_to_peer(&peer_id, overflow, message::Topic::Consensus),
        "no progress class may exceed the full aggregate count owner"
    );
    assert_eq!(
        network
            .deferred_send_queue
            .peer_retained(&peer_id)
            .map(|(retained, _, _, _)| retained),
        Some(capacity),
        "overflow must preserve every previously admitted progress witness"
    );
    assert!(
        network.pending_connects.len() <= 1,
        "consensus burst should not schedule duplicate reconnect attempts"
    );
    assert!(
        network
            .connecting_peers
            .values()
            .filter(|peer| peer.id() == &peer_id)
            .count()
            <= 1,
        "consensus burst should not spawn duplicate active reconnects"
    );
    assert_eq!(
        session_reconnect_total(),
        reconnect_before.saturating_add(1),
        "consensus burst should trigger one reconnect per unsatisfied peer session"
    );
}
#[test]
fn allowlist_only_does_not_gate_ip_without_cidr_allowlist() {
    let ip = IpAddr::from([10, 0, 0, 1]);
    let mut prefix = HashMap::new();
    let mut ip_buckets = HashMap::new();
    assert!(
        allow_ip_with_policy(
            &[],
            &[],
            true,
            default_accept_params(),
            &mut prefix,
            &mut ip_buckets,
            ip
        ),
        "allowlist-only toggle must not block IPs when no CIDR allowlist is configured"
    );
}
#[test]
fn malformed_runtime_acl_update_preserves_the_installed_policy() {
    let_test_network!(network);
    network.apply_reply_source_acl(
        ValidatedAclUpdate::parse(message::UpdateAcl {
            deny_cidrs: vec!["10.0.0.0/8".to_owned()],
            ..message::UpdateAcl::default()
        })
        .expect("test ACL is valid"),
    );
    assert!(!network.allow_ip(IpAddr::from([10, 4, 3, 2])));
    assert!(network.allow_ip(IpAddr::from([192, 0, 2, 1])));

    network.set_reply_source_acl(message::UpdateAcl {
        allow_cidrs: vec!["not-a-cidr".to_owned()],
        ..message::UpdateAcl::default()
    });

    assert!(
        !network.allow_ip(IpAddr::from([10, 4, 3, 2])),
        "invalid hot reload must retain the prior deny network"
    );
    assert!(
        network.allow_ip(IpAddr::from([192, 0, 2, 1])),
        "invalid hot reload must not partially install its allow dimension"
    );
}
#[test]
fn cidr_allowlist_enforced_when_present() {
    let ip = IpAddr::from([10, 0, 0, 1]);
    let other = IpAddr::from([10, 0, 1, 1]);
    let allow = parse_cidrs(&["10.0.0.0/24".to_string()]).expect("valid IPv4 CIDR");
    let mut prefix = HashMap::new();
    let mut ip_buckets = HashMap::new();
    assert!(
        allow_ip_with_policy(
            &allow,
            &[],
            false,
            default_accept_params(),
            &mut prefix,
            &mut ip_buckets,
            ip
        ),
        "IP inside allowlist CIDR should be accepted"
    );
    assert!(
        !allow_ip_with_policy(
            &allow,
            &[],
            false,
            default_accept_params(),
            &mut prefix,
            &mut ip_buckets,
            other
        ),
        "IP outside allowlist CIDR should be rejected"
    );
}
#[test]
fn ipv6_cidr_byte_boundary_is_respected() {
    let allow = parse_cidrs(&["2001:db8::/64".to_string()]).expect("valid IPv6 CIDR");
    let inside: IpAddr = "2001:db8::1".parse().expect("valid IPv6");
    let outside: IpAddr = "2001:db8:0:1::1".parse().expect("valid IPv6");
    let mut prefix = HashMap::new();
    let mut ip_buckets = HashMap::new();
    assert!(
        allow_ip_with_policy(
            &allow,
            &[],
            false,
            default_accept_params(),
            &mut prefix,
            &mut ip_buckets,
            inside
        ),
        "IPv6 address inside the /64 should be accepted"
    );
    assert!(
        !allow_ip_with_policy(
            &allow,
            &[],
            false,
            default_accept_params(),
            &mut prefix,
            &mut ip_buckets,
            outside
        ),
        "IPv6 address outside the /64 should be rejected"
    );
}
#[test]
fn prefix_bucket_throttles_before_per_ip() {
    let mut prefix = HashMap::new();
    let mut ip_buckets = HashMap::new();
    let params = accept_params_with(8, Duration::from_secs(1), Some(1.0), Some(5.0));
    assert!(
        allow_ip_with_policy(
            &[],
            &[],
            false,
            params,
            &mut prefix,
            &mut ip_buckets,
            IpAddr::from([192, 168, 10, 1])
        ),
        "first connection in prefix should pass"
    );
    assert!(
        !allow_ip_with_policy(
            &[],
            &[],
            false,
            params,
            &mut prefix,
            &mut ip_buckets,
            IpAddr::from([192, 168, 10, 2])
        ),
        "second connection in prefix should be throttled by prefix bucket before per-IP bucket"
    );
}
#[tokio::test(start_paused = true)]
async fn accept_idle_buckets_are_evicted() {
    let mut prefix = HashMap::new();
    let mut ip_buckets = HashMap::new();
    let params = accept_params_with(4, Duration::from_millis(5), Some(10.0), Some(10.0));
    let ip_a = IpAddr::from([10, 0, 0, 1]);
    let ip_b = IpAddr::from([10, 0, 1, 1]);
    assert!(allow_ip_with_policy(
        &[],
        &[],
        false,
        params,
        &mut prefix,
        &mut ip_buckets,
        ip_a
    ));
    assert_eq!(prefix.len(), 1);
    tokio::time::advance(Duration::from_millis(10)).await;
    assert!(allow_ip_with_policy(
        &[],
        &[],
        false,
        params,
        &mut prefix,
        &mut ip_buckets,
        ip_b
    ));
    assert!(
        prefix.len() <= 1 && ip_buckets.len() <= 1,
        "idle buckets should be evicted before inserting new ones"
    );
}
#[test]
fn allowlist_bypasses_throttle_state() {
    let allow = parse_cidrs(&["10.1.0.0/24".to_string()]).expect("valid IPv4 CIDR");
    let ip = IpAddr::from([10, 1, 0, 9]);
    let mut prefix = HashMap::new();
    let mut ip_buckets = HashMap::new();
    let params = accept_params_with(1, Duration::from_secs(30), Some(1.0), Some(1.0));
    assert!(allow_ip_with_policy(
        &allow,
        &[],
        false,
        params,
        &mut prefix,
        &mut ip_buckets,
        ip
    ));
    assert!(
        prefix.is_empty() && ip_buckets.is_empty(),
        "allowlisted IPs should bypass throttle buckets entirely"
    );
}
#[test]
fn accept_bucket_cap_enforced_under_churn() {
    let mut prefix = HashMap::new();
    let mut ip_buckets = HashMap::new();
    let params = accept_params_with(1, Duration::from_secs(60), None, Some(5.0));
    let evicted_before = accept_bucket_evictions_count();
    for octet in 1..20 {
        let _ = allow_ip_with_policy(
            &[],
            &[],
            false,
            params,
            &mut prefix,
            &mut ip_buckets,
            IpAddr::from([172, 16, 0, octet]),
        );
    }
    assert!(
        prefix.len() <= 1 && ip_buckets.len() <= 1,
        "bucket map must stay within configured cap"
    );
    assert!(
        accept_bucket_evictions_count() > evicted_before,
        "evictions counter should increase when cap forces churn"
    );
}
#[tokio::test(flavor = "current_thread")]
async fn trust_gossip_send_skips_when_disabled() {
    let _guard = trust_gossip_test_guard().await;
    let_test_network!(network, TrustGossipMsg);
    network.trust_gossip = false;
    let before = trust_skip_count("send", "local_capability_off");
    let peer_id = random_peer_id();
    network.post(Post {
        data: TrustGossipMsg,
        peer_id: peer_id.clone(),
        priority: Priority::Low,
    });
    network.broadcast(Broadcast {
        data: TrustGossipMsg,
        priority: Priority::Low,
    });
    let after = trust_skip_count("send", "local_capability_off");
    assert!(
        after >= before + 2,
        "post + broadcast should both be skipped when trust gossip is disabled (before={before}, after={after})"
    );
}
#[tokio::test(flavor = "current_thread")]
async fn peer_gossip_not_counted_as_trust_skip() {
    let _guard = trust_gossip_test_guard().await;
    let_test_network!(network, PeerGossipMsg);
    network.trust_gossip = false;
    let before = trust_skip_count("send", "local_capability_off");
    network.broadcast(Broadcast {
        data: PeerGossipMsg,
        priority: Priority::Low,
    });
    let after = trust_skip_count("send", "local_capability_off");
    assert_eq!(
        before, after,
        "peer gossip should not bump trust-gossip skip counters"
    );
}
async fn assert_trust_gossip_receive_skipped(
    peer_addr: SocketAddr,
    disable_local: bool,
    reason: &'static str,
    diagnostic: &'static str,
) {
    let_test_network!(network, TrustGossipMsg);
    if disable_local {
        network.trust_gossip = false;
    }
    let peer = Peer::new(peer_addr, random_node_key_pair().public_key().clone());
    let payload = direct_frame!(peer.id().clone(), network.self_id, TrustGossipMsg,);
    let msg = PeerMessage::new(peer, payload, 1);
    let before = trust_skip_count("recv", reason);
    network.peer_message(msg).await;
    let after = trust_skip_count("recv", reason);
    assert_eq!(after, before + 1, "{diagnostic}");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trust_gossip_recv_skips_when_local_capability_disabled() {
    let _guard = trust_gossip_test_guard().await;
    assert_trust_gossip_receive_skipped(
        socket_addr!(127.0.0.1:200),
        true,
        "local_capability_off",
        "local trust-gossip disablement should drop inbound frames",
    )
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trust_gossip_recv_skips_when_peer_lacks_capability() {
    let _guard = trust_gossip_test_guard().await;
    assert_trust_gossip_receive_skipped(
        socket_addr!(127.0.0.1:201),
        false,
        "peer_capability_off",
        "trust gossip from peers without negotiated support should be rejected",
    )
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_message_drops_mismatched_origin_without_hub() {
    let_test_network!(network, DummyMsg);
    let (tx, mut rx) = mpsc::channel(1);
    network.subscribe_to_peers_messages(Subscriber::new(tx, SubscriberFilter::All, 1));
    let incoming_peer = test_peer(socket_addr!(127.0.0.1:202));
    let connection_id = 20_200;
    let (handle, receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(
        &mut network,
        incoming_peer.id().clone(),
        incoming_peer.address().clone(),
        connection_id,
        handle,
    );
    let origin = random_peer_id();
    let payload = direct_frame!(origin, network.self_id, DummyMsg,);
    let msg = PeerMessage::new(incoming_peer.clone(), payload, 1);
    network.peer_message(msg).await;
    assert!(
        matches!(rx.try_recv(), Err(TryRecvError::Empty)),
        "mismatched origin should be dropped when not relaying from the hub"
    );
    assert!(network.peers.contains_key(incoming_peer.id()));
    assert!(
        !receivers.termination_requested(),
        "a legacy message without exact tenure must not evict a healthy connection"
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_message_quarantines_exact_tenure_on_mismatched_origin() {
    let_test_network!(network, DummyMsg);
    let incoming_peer = test_peer(socket_addr!(127.0.0.1:20_201));
    let connection_id = 20_201;
    let (handle, receivers) = test_wire_peer_handle::<DummyMsg>(1);
    insert_dummy_ref_peer(
        &mut network,
        incoming_peer.id().clone(),
        incoming_peer.address().clone(),
        connection_id,
        handle,
    );
    network.reply_route_tenures.insert(
        connection_id,
        test_reply_tenure(
            &network.reply_route_owner,
            incoming_peer.id().clone(),
            connection_id,
            0,
        ),
    );
    let payload = direct_frame!(random_peer_id(), network.self_id, DummyMsg,);
    network
        .peer_message(PeerMessage::new_for_connection(
            incoming_peer.clone(),
            payload,
            1,
            connection_id,
        ))
        .await;
    assert!(receivers.termination_requested());
    assert!(!network.peers.contains_key(incoming_peer.id()));
    assert!(
        network
            .protocol_rejected_connections
            .contains(&connection_id)
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_message_accepts_origin_signed_multi_hop_frame_from_selected_hub() {
    let_test_network!(network, DummyMsg);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
    let hub_key_pair = random_node_key_pair();
    let hub_peer = Peer::new(
        socket_addr!(127.0.0.1:203),
        hub_key_pair.public_key().clone(),
    );
    network.relay_hub_peer = Some(hub_peer.id().clone());
    let (tx, mut rx) = mpsc::channel(1);
    network.subscribe_to_peers_messages(Subscriber::new(tx, SubscriberFilter::All, 1));
    let origin_key_pair = random_node_key_pair();
    let origin = PeerId::from(origin_key_pair.public_key().clone());
    let payload = RelayMessage::new_signed(
        &origin_key_pair,
        RelayTarget::Direct(network.self_id.clone()),
        DEFAULT_RELAY_TTL,
        DummyMsg,
    )
    .forwarded_with_ttl(DEFAULT_RELAY_TTL - 1);
    let msg = PeerMessage::new(hub_peer, payload, 1);
    network.peer_message(msg).await;
    let received = rx.try_recv().expect("expected relay message");
    assert_eq!(
        received.peer.id(),
        &origin,
        "origin should be preserved when relaying through the hub"
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_message_rejects_hub_rewritten_semantic_origin() {
    let_test_network!(network, DummyMsg);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
    let hub_key_pair = random_node_key_pair();
    let hub_peer = Peer::new(
        socket_addr!(127.0.0.1:203),
        hub_key_pair.public_key().clone(),
    );
    network.relay_hub_peer = Some(hub_peer.id().clone());
    let (tx, mut rx) = mpsc::channel(1);
    network.subscribe_to_peers_messages(Subscriber::new(tx, SubscriberFilter::All, 1));
    let mut forged = RelayMessage::new_signed(
        &hub_key_pair,
        RelayTarget::Direct(network.self_id.clone()),
        DEFAULT_RELAY_TTL,
        DummyMsg,
    );
    forged.origin = random_peer_id();
    network
        .peer_message(PeerMessage::new(hub_peer, forged, 1))
        .await;
    assert!(
        matches!(rx.try_recv(), Err(TryRecvError::Empty)),
        "a selected hub must not acquire semantic-origin signing authority"
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_origin_signature_quarantines_and_disconnects_exact_tenure() {
    let_test_network!(network, SafetyMsg);
    let signer = random_node_key_pair();
    let peer = Peer::new(socket_addr!(127.0.0.1:20_301), signer.public_key().clone());
    let connection_id = 20_301;
    let (handle, receivers) = test_wire_peer_handle::<SafetyMsg>(4);
    insert_ref_peer(
        &mut network,
        peer.id().clone(),
        peer.address().clone(),
        connection_id,
        handle,
        true,
    );
    network.reply_route_tenures.insert(
        connection_id,
        test_reply_tenure(
            &network.reply_route_owner,
            peer.id().clone(),
            connection_id,
            0,
        ),
    );
    network
        .last_active
        .insert(peer.id().clone(), tokio::time::Instant::now());
    let (tx, mut rx) = mpsc::channel(2);
    network.subscribe_to_peers_messages(Subscriber::new(tx, SubscriberFilter::All, 2));

    let mut forged = RelayMessage::new_signed(
        &signer,
        RelayTarget::Direct(network.self_id.clone()),
        DEFAULT_RELAY_TTL,
        SafetyMsg(7),
    );
    forged.payload = SafetyMsg(8);
    network
        .peer_message(PeerMessage::new_for_connection(
            peer.clone(),
            forged,
            1,
            connection_id,
        ))
        .await;

    assert!(receivers.termination_requested());
    assert!(!network.peers.contains_key(peer.id()));
    assert!(!network.last_active.contains_key(peer.id()));
    assert!(
        network
            .protocol_rejected_connections
            .contains(&connection_id)
    );
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));

    let valid = RelayMessage::new_signed(
        &signer,
        RelayTarget::Direct(network.self_id.clone()),
        DEFAULT_RELAY_TTL,
        SafetyMsg(9),
    );
    network
        .peer_message(PeerMessage::new_for_connection(
            peer,
            valid,
            1,
            connection_id,
        ))
        .await;
    assert!(
        matches!(rx.try_recv(), Err(TryRecvError::Empty)),
        "queued frames from the rejected tenure must bypass validation and delivery"
    );

    network.finish_reply_route_tenure(connection_id);
    assert!(
        !network
            .protocol_rejected_connections
            .contains(&connection_id)
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_signature_from_replaced_tenure_does_not_disconnect_replacement() {
    let_test_network!(network, SafetyMsg);
    let signer = random_node_key_pair();
    let peer = Peer::new(socket_addr!(127.0.0.1:20_302), signer.public_key().clone());
    let old_connection_id = 20_302;
    let replacement_connection_id = 20_303;
    let (replacement_handle, replacement_receivers) = test_wire_peer_handle::<SafetyMsg>(4);
    insert_ref_peer(
        &mut network,
        peer.id().clone(),
        peer.address().clone(),
        replacement_connection_id,
        replacement_handle,
        true,
    );
    network.reply_route_tenures.insert(
        old_connection_id,
        test_reply_tenure(
            &network.reply_route_owner,
            peer.id().clone(),
            old_connection_id,
            0,
        ),
    );

    let mut forged = RelayMessage::new_signed(
        &signer,
        RelayTarget::Direct(network.self_id.clone()),
        DEFAULT_RELAY_TTL,
        SafetyMsg(7),
    );
    forged.payload = SafetyMsg(8);
    network
        .peer_message(PeerMessage::new_for_connection(
            peer.clone(),
            forged,
            1,
            old_connection_id,
        ))
        .await;

    assert!(
        network
            .protocol_rejected_connections
            .contains(&old_connection_id)
    );
    assert_eq!(
        network.peers.get(peer.id()).map(|current| current.conn_id),
        Some(replacement_connection_id)
    );
    assert!(!replacement_receivers.termination_requested());
}
#[test]
fn relay_origin_signature_binds_payload_and_target_but_not_ttl() {
    let origin_key_pair = random_node_key_pair();
    let target = random_peer_id();
    let frame = RelayMessage::new_signed(
        &origin_key_pair,
        RelayTarget::Direct(target),
        DEFAULT_RELAY_TTL,
        TamperableMsg { tag: 7 },
    );
    frame
        .verify_origin_signature()
        .expect("fresh origin signature must verify");
    let forwarded = frame.forwarded_with_ttl(DEFAULT_RELAY_TTL - 1);
    forwarded
        .verify_origin_signature()
        .expect("TTL is mutable hop metadata outside the origin signature");
    let mut payload_tampered = frame.clone();
    payload_tampered.payload.tag = 8;
    assert!(payload_tampered.verify_origin_signature().is_err());
    let mut target_tampered = frame.clone();
    target_tampered.target = RelayTarget::Broadcast;
    assert!(target_tampered.verify_origin_signature().is_err());
}
#[test]
fn relay_routes_unconnected_spoke_posts_via_configured_hub() {
    let_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
    let hub_addr = socket_addr!(127.0.0.1:204);
    let hub_id = random_peer_id();
    let target = random_peer_id();
    let (hub_handle, _hub_receivers) = test_wire_peer_handle::<DummyMsg>(1);
    network.relay_hub_addresses.push(hub_addr.clone());
    network
        .current_peers_addresses
        .push((hub_id.clone(), hub_addr.clone()));
    network.relay_trusted_peers.insert(hub_id.clone());
    network.current_topology.insert(hub_id.clone());
    insert_dummy_ref_peer(&mut network, hub_id.clone(), hub_addr, 20_400, hub_handle);
    network
        .peers
        .get_mut(&hub_id)
        .expect("authenticated relay hub")
        .relay_role = RelayRole::Hub;
    network.relay_hub_peer = Some(hub_id.clone());
    assert_eq!(
        network.relay_route_for_unconnected_post_target(&target),
        Some(hub_id),
        "spoke mode should route unknown direct targets through the selected hub"
    );
}
#[test]
fn relay_keeps_direct_hub_posts_out_of_hub_reroute() {
    let_test_network!(network);
    network.relay_mode = iroha_config::parameters::actual::RelayMode::Spoke;
    let hub_addr = socket_addr!(127.0.0.1:205);
    let hub_id = random_peer_id();
    network.relay_hub_addresses.push(hub_addr.clone());
    network
        .current_peers_addresses
        .push((hub_id.clone(), hub_addr));
    network.current_topology.insert(hub_id.clone());
    assert_eq!(
        network.relay_route_for_unconnected_post_target(&hub_id),
        None,
        "posts addressed to the hub itself should stay on the direct path"
    );
}
#[test]
fn clear_low_buckets_removes_entries() {
    let peer_id = random_peer_id();
    let mut low = HashMap::new();
    let mut low_bytes = HashMap::new();
    low.insert(peer_id.clone(), TokenBucket::new(1.0, 1.0));
    low_bytes.insert(peer_id.clone(), TokenBucket::new(1.0, 1.0));
    // Exercise the helper without requiring a full network instance.
    let_test_network!(network);
    network.low_buckets = low;
    network.low_bytes_buckets = low_bytes;
    network.clear_low_buckets(&peer_id);
    assert!(
        !network.low_buckets.contains_key(&peer_id),
        "per-peer token bucket should be removed"
    );
    assert!(
        !network.low_bytes_buckets.contains_key(&peer_id),
        "per-peer byte bucket should be removed"
    );
}
#[test]
fn reliable_subscriber_is_single_consumer_under_clone_budget_pressure() {
    let_test_network!(network, DeferredProgressMsg);
    let (first_tx, mut first_rx) = mpsc::channel(1);
    let (overlap_tx, mut overlap_rx) = mpsc::channel(1);
    network.subscribe_to_peers_messages(Subscriber::new(first_tx, SubscriberFilter::All, 1));
    network.subscribe_to_peers_messages(Subscriber::new(overlap_tx, SubscriberFilter::All, 1));
    assert_eq!(
        network.subscribers_to_peers_messages.len(),
        1,
        "overlapping reliable filters must never create a fan-out clone obligation"
    );
    let peer = test_peer(socket_addr!(127.0.0.1:2122));
    let budget = SharedByteBudget::new(1, 0).expect("one-copy dispatch budget");
    let msg = PeerMessage::new_dispatch_retained_for_test(
        peer,
        DeferredProgressMsg::Lane(41),
        1,
        Arc::clone(&budget),
    );
    assert_eq!(budget.retained_total(), 1);
    assert!(
        msg.try_clone_retained().is_none(),
        "the adversarial fixture leaves no bytes for a second retained copy"
    );
    network.dispatch_to_subscribers(msg);
    let received = first_rx
        .try_recv()
        .expect("the first reliable owner receives the exact original");
    assert_eq!(received.payload, DeferredProgressMsg::Lane(41));
    assert!(matches!(
        overlap_rx.try_recv(),
        Err(TryRecvError::Disconnected)
    ));
    assert_eq!(budget.retained_total(), 1);
    drop(received);
    assert_eq!(budget.retained_total(), 0);
}
#[test]
fn reliable_delivery_waits_for_its_route_subscriber() {
    let_test_network!(network, DeferredProgressMsg);
    let peer = test_peer(socket_addr!(127.0.0.1:2126));
    network.dispatch_to_subscribers(PeerMessage::new(
        peer,
        DeferredProgressMsg::BlockSync(17),
        1,
    ));
    assert_eq!(network.unrouted_reliable_deliveries.len(), 1);
    let (tx, mut rx) = mpsc::channel(1);
    network.subscribe_to_peers_messages(Subscriber::new(tx, SubscriberFilter::All, 1));
    assert_eq!(
        rx.try_recv().expect("retained route delivery").payload,
        DeferredProgressMsg::BlockSync(17)
    );
    assert!(network.unrouted_reliable_deliveries.is_empty());
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}
#[test]
fn closed_reliable_subscriber_transfers_actor_pending_backlog_to_replacement() {
    let_test_network!(network, DeferredProgressMsg);
    let peer = test_peer(socket_addr!(127.0.0.1:2127));
    let (first_tx, first_rx) = mpsc::channel(1);
    first_tx
        .try_send(PeerMessage::new(
            peer.clone(),
            DeferredProgressMsg::BlockSync(0),
            1,
        ))
        .expect("prefill first subscriber channel");
    // Tag 0 already crossed the actor/subscriber ownership boundary. This
    // regression covers only the actor-side pending suffix; consumer ACK
    // tracking for an item inside a closed subscriber channel remains a
    // separate durable-retransmission obligation.
    network.subscribe_to_peers_messages(Subscriber::new(first_tx, SubscriberFilter::All, 1));
    for tag in 1..=2 {
        network.dispatch_to_subscribers(PeerMessage::new(
            peer.clone(),
            DeferredProgressMsg::BlockSync(tag),
            1,
        ));
    }
    assert_eq!(
        network.subscribers_to_peers_messages[0].progress_pending_len,
        2
    );
    drop(first_rx);
    let (replacement_tx, mut replacement_rx) = mpsc::channel(2);
    network.subscribe_to_peers_messages(Subscriber::new(replacement_tx, SubscriberFilter::All, 2));
    for tag in 1..=2 {
        assert_eq!(
            replacement_rx
                .try_recv()
                .expect("replacement receives exact retained suffix")
                .payload,
            DeferredProgressMsg::BlockSync(tag)
        );
    }
    assert!(matches!(
        replacement_rx.try_recv(),
        Err(TryRecvError::Empty)
    ));
    assert!(network.unrouted_reliable_deliveries.is_empty());
    assert_eq!(network.subscribers_to_peers_messages.len(), 1);
}
#[test]
fn dispatch_to_subscribers_keeps_subscriber_on_full_channel() {
    let_test_network!(network, DummyMsg);
    let (tx, mut rx) = mpsc::channel(1);
    let peer = test_peer(socket_addr!(127.0.0.1:2121));
    let msg = PeerMessage::new(peer, DummyMsg, 1);
    tx.try_send(msg.try_clone_retained().expect("synthetic clone"))
        .expect("fill channel");
    network
        .subscribers_to_peers_messages
        .push(Subscriber::new(tx, SubscriberFilter::All, 1));
    network.dispatch_to_subscribers(msg);
    assert_eq!(
        network.subscribers_to_peers_messages.len(),
        1,
        "subscriber should be retained when queue is full"
    );
    let first = rx.try_recv().expect("expected buffered message");
    let PeerMessage {
        payload: DummyMsg, ..
    } = first;
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}
#[test]
fn progress_subscriber_full_retains_consensus_but_control_stays_lossy() {
    let_test_network!(network, RouteMsg);
    let peer = test_peer(socket_addr!(127.0.0.1:2122));
    network.current_topology.insert(peer.id().clone());
    let (tx, mut rx) = mpsc::channel(1);
    tx.try_send(PeerMessage::new(peer.clone(), RouteMsg::Control, 1))
        .expect("prefill subscriber channel");
    network.subscribe_to_peers_messages(Subscriber::new(tx, SubscriberFilter::All, 2));
    network.dispatch_to_subscribers(PeerMessage::new(peer.clone(), RouteMsg::Lane, 1));
    network.dispatch_to_subscribers(PeerMessage::new(peer.clone(), RouteMsg::Control, 1));
    assert_eq!(
        network.subscribers_to_peers_messages[0].progress_pending_len, 1,
        "only consensus progress may occupy the bounded progress backlog"
    );
    assert_eq!(
        rx.try_recv().expect("prefilled delivery").payload,
        RouteMsg::Control
    );
    network.flush_safety_subscribers();
    assert_eq!(
        rx.try_recv().expect("retained consensus progress").payload,
        RouteMsg::Lane
    );
    assert_eq!(
        network.subscribers_to_peers_messages[0].progress_pending_len,
        0
    );
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}
#[test]
fn progress_subscriber_backlog_preserves_fifo_against_fresh_arrivals() {
    let_test_network!(network, DeferredProgressMsg);
    let peer = test_peer(socket_addr!(127.0.0.1:2123));
    network.current_topology.insert(peer.id().clone());
    let (tx, mut rx) = mpsc::channel(1);
    tx.try_send(PeerMessage::new(
        peer.clone(),
        DeferredProgressMsg::BlockSync(0),
        1,
    ))
    .expect("prefill subscriber channel");
    network.subscribe_to_peers_messages(Subscriber::new(tx, SubscriberFilter::All, 4));
    for tag in 1..=2 {
        network.dispatch_to_subscribers(PeerMessage::new(
            peer.clone(),
            DeferredProgressMsg::BlockSync(tag),
            1,
        ));
    }
    assert_eq!(
        network.subscribers_to_peers_messages[0].progress_pending_len,
        2
    );
    assert_eq!(
        rx.try_recv().expect("prefilled delivery").payload,
        DeferredProgressMsg::BlockSync(0)
    );
    network.flush_safety_subscribers();
    assert_eq!(
        rx.try_recv().expect("oldest retained progress").payload,
        DeferredProgressMsg::BlockSync(1)
    );
    network.dispatch_to_subscribers(PeerMessage::new(peer, DeferredProgressMsg::BlockSync(3), 1));
    network.flush_safety_subscribers();
    assert_eq!(
        rx.try_recv().expect("second retained progress").payload,
        DeferredProgressMsg::BlockSync(2),
        "fresh progress must not barge ahead of the retained FIFO predecessor"
    );
    network.flush_safety_subscribers();
    assert_eq!(
        rx.try_recv()
            .expect("fresh progress eventually follows")
            .payload,
        DeferredProgressMsg::BlockSync(3)
    );
}
#[test]
fn reliable_subscriber_backlog_survives_topology_rotation() {
    let_test_network!(network, DeferredProgressMsg);
    let old_validator = test_peer(socket_addr!(127.0.0.1:2125));
    network.current_topology.insert(old_validator.id().clone());
    let (tx, mut rx) = mpsc::channel(1);
    tx.try_send(PeerMessage::new(
        old_validator.clone(),
        DeferredProgressMsg::BlockSync(0),
        1,
    ))
    .expect("prefill subscriber channel");
    network.subscribe_to_peers_messages(Subscriber::new(tx, SubscriberFilter::All, 1));
    network.dispatch_to_subscribers(PeerMessage::new(
        old_validator,
        DeferredProgressMsg::Lane(7),
        1,
    ));
    network.current_topology.clear();
    network.flush_safety_subscribers();
    assert_eq!(
        network.subscribers_to_peers_messages[0].progress_pending_len, 1,
        "topology rotation must not orphan an already admitted reliable delivery"
    );
    assert_eq!(
        rx.try_recv().expect("prefilled item remains first").payload,
        DeferredProgressMsg::BlockSync(0)
    );
    network.flush_safety_subscribers();
    assert_eq!(
        rx.try_recv()
            .expect("old-round progress survives the topology change")
            .payload,
        DeferredProgressMsg::Lane(7)
    );
}
#[test]
fn progress_subscriber_chunk_flood_preserves_lane_capacity_and_service() {
    let_test_network!(network, DeferredProgressMsg);
    let peer = test_peer(socket_addr!(127.0.0.1:2124));
    network.current_topology.insert(peer.id().clone());
    let (tx, mut rx) = mpsc::channel(1);
    tx.try_send(PeerMessage::new(
        peer.clone(),
        DeferredProgressMsg::BlockSync(0),
        1,
    ))
    .expect("prefill subscriber channel");
    network.subscribe_to_peers_messages(Subscriber::new(tx, SubscriberFilter::All, 64));
    for tag in 1..=64 {
        network.dispatch_to_subscribers(PeerMessage::new(
            peer.clone(),
            DeferredProgressMsg::Chunk(tag),
            1,
        ));
    }
    network.dispatch_to_subscribers(PeerMessage::new(peer, DeferredProgressMsg::Lane(99), 1));
    assert_eq!(
        network.subscribers_to_peers_messages[0].progress_pending_len, 65,
        "all byte-admitted bulk work and the independent lane witness must remain retained"
    );
    assert_eq!(
        rx.try_recv().expect("prefilled delivery").payload,
        DeferredProgressMsg::BlockSync(0)
    );
    network.flush_safety_subscribers();
    assert_eq!(
        rx.try_recv()
            .expect("bulk queue gets its existing turn")
            .payload,
        DeferredProgressMsg::Chunk(1)
    );
    network.flush_safety_subscribers();
    assert_eq!(
        rx.try_recv()
            .expect("lane queue receives the next fair turn")
            .payload,
        DeferredProgressMsg::Lane(99),
        "a chunk flood must not starve a consensus-lane progress witness"
    );
}
#[test]
fn byzantine_safety_flood_cannot_starve_another_peers_subscriber_message() {
    let_test_network!(network, SafetyMsg);
    let attacker = test_peer(socket_addr!(127.0.0.1:2201));
    let honest = test_peer(socket_addr!(127.0.0.1:2202));
    network.current_topology = HashSet::from([attacker.id().clone(), honest.id().clone()]);
    let (tx, mut rx) = mpsc::channel(1);
    tx.try_send(PeerMessage::new(attacker.clone(), SafetyMsg(0), 1))
        .expect("prefill safety subscriber channel");
    network.subscribe_to_peers_messages(Subscriber::new(
        tx,
        SubscriberFilter::topics([message::Topic::ConsensusSafety]),
        2,
    ));
    let relayed_origin = test_peer(socket_addr!(127.0.0.1:2203));
    for tag in 1..=8 {
        network.dispatch_to_subscribers_from(
            PeerMessage::new(relayed_origin.clone(), SafetyMsg(tag), 1),
            attacker.id().clone(),
        );
    }
    network.dispatch_to_subscribers(PeerMessage::new(honest.clone(), SafetyMsg(99), 1));
    assert_eq!(
        rx.try_recv().expect("prefilled message").payload,
        SafetyMsg(0)
    );
    network.flush_safety_subscribers();
    assert_eq!(
        rx.try_recv()
            .expect("attacker's byte-bounded backlog turn")
            .payload,
        SafetyMsg(1)
    );
    network.flush_safety_subscribers();
    let delivered = rx.try_recv().expect("honest peer must retain its turn");
    assert_eq!(delivered.peer.id(), honest.id());
    assert_eq!(delivered.payload, SafetyMsg(99));
    assert_eq!(
        network.subscribers_to_peers_messages[0].safety_pending_len, 7,
        "the retained attacker suffix remains byte-owned after the honest source gets service"
    );
}
#[test]
fn dispatch_to_subscribers_tracks_unmatched_topics() {
    let_test_network!(network, TopicMsg);
    let (tx, mut rx) = mpsc::channel(1);
    network.subscribe_to_peers_messages(Subscriber::new(
        tx,
        SubscriberFilter::topics([message::Topic::TrustGossip]),
        1,
    ));
    let peer = test_peer(socket_addr!(127.0.0.1:303));
    let before = subscriber_unrouted_count();
    network.dispatch_to_subscribers(PeerMessage::new(peer, TopicMsg::Peer, 1));
    let after = subscriber_unrouted_count();
    assert!(
        after > before,
        "unmatched topics should increment the unrouted counter"
    );
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}
#[test]
fn subscriber_queue_full_counts_increment_by_topic() {
    let before_total = subscriber_queue_full_count();
    let before_safety = subscriber_queue_full_consensus_safety_count();
    let before_consensus = subscriber_queue_full_consensus_count();
    let before_chunks = subscriber_queue_full_consensus_chunk_count();
    inc_subscriber_queue_full_for_test(message::Topic::ConsensusSafety, 1);
    inc_subscriber_queue_full_for_test(message::Topic::Consensus, 2);
    inc_subscriber_queue_full_for_test(message::Topic::ConsensusChunk, 1);
    let after_total = subscriber_queue_full_count();
    let after_safety = subscriber_queue_full_consensus_safety_count();
    let after_consensus = subscriber_queue_full_consensus_count();
    let after_chunks = subscriber_queue_full_consensus_chunk_count();
    assert!(
        after_total >= before_total + 4,
        "queue-full counter should increase by at least the increment"
    );
    assert!(
        after_safety > before_safety,
        "safety drops must not be merged into ordinary consensus metrics"
    );
    assert!(
        after_consensus >= before_consensus + 2,
        "queue-full per-topic counter should track consensus drops"
    );
    assert!(
        after_chunks > before_chunks,
        "queue-full per-topic counter should track consensus chunk drops"
    );
}
include!("queue_depth_tests.rs");
#[test]
fn pending_connects_drop_outside_topology() {
    let mut network = match bare_network() {
        Some(net) => net,
        None => return,
    };
    let peer = Peer::new(socket_addr!(127.0.0.1:9), random_peer_id());
    network
        .pending_connects
        .push((tokio::time::Instant::now(), peer));
    network.process_pending_connects();
    assert!(
        network.pending_connects.is_empty(),
        "pending connects for peers outside topology should be dropped"
    );
    assert!(
        network.connecting_peers.is_empty(),
        "connect should not be attempted for peers outside topology"
    );
}
include!("link_frame_tests.rs");
include!("actor_window_tests.rs");
