//! Raw and typed semantic classification across the signed relay envelope.

use super::{
    RelayMessage, RelayTarget,
    message::{ClassifyTopic, Topic, TransportAdmissionClass as A},
};
use iroha_crypto::{Algorithm, KeyPair};
use norito::{Decode, Encode, core as ncore};

/// Canonical test payload exercising classes independently of shared topics.
#[derive(Clone, Debug, Encode, Decode, norito::NoritoSchema)]
#[norito(decode_from_slice)]
#[norito_schema(name = "iroha_p2p::network::admission_class_tests::AdmissionFixture")]
pub enum AdmissionFixture {
    Safety(u8),
    Lane(u8),
    Payload(u8),
    Control(u8),
    BlockSync(u8),
    Low(u8),
}
impl AdmissionFixture {
    pub(crate) fn all() -> [Self; A::COUNT] {
        [
            Self::Safety(1),
            Self::Lane(2),
            Self::Payload(3),
            Self::Control(4),
            Self::BlockSync(5),
            Self::Low(6),
        ]
    }
}
impl ClassifyTopic for AdmissionFixture {
    fn topic(&self) -> Topic {
        match self {
            Self::Safety(_) => Topic::ConsensusSafety,
            Self::Lane(_) => Topic::Consensus,
            Self::Payload(_) => Topic::ConsensusPayload,
            Self::Control(_) => Topic::Control,
            Self::BlockSync(_) => Topic::BlockSync,
            Self::Low(_) => Topic::Health,
        }
    }
    fn inbound_topic(payload: &[u8], flags: u8) -> Result<Option<Topic>, ncore::Error> {
        Ok(Some(match Self::inbound_admission_class(payload, flags)? {
            A::Safety => Topic::ConsensusSafety,
            A::Lane => Topic::Consensus,
            A::Payload => Topic::ConsensusPayload,
            A::Control => Topic::Control,
            A::BlockSync => Topic::BlockSync,
            A::Low => Topic::Health,
        }))
    }
    fn inbound_admission_class(payload: &[u8], flags: u8) -> Result<A, ncore::Error> {
        ncore::validate_header_flags(flags)?;
        let tag = u32::from_le_bytes(
            payload
                .get(..4)
                .ok_or(ncore::Error::LengthMismatch)?
                .try_into()
                .map_err(|_| ncore::Error::LengthMismatch)?,
        );
        let remaining = &payload[4..];
        let (len, prefix) = ncore::read_len_from_slice_with_flags(remaining, flags)?;
        if len != 1 || prefix.checked_add(len) != Some(remaining.len()) {
            return Err(ncore::Error::LengthMismatch);
        }
        A::ALL
            .get(tag as usize)
            .copied()
            .ok_or_else(|| ncore::Error::Message("unknown admission fixture tag".to_owned()))
    }
}

#[test]
fn raw_admission_fixture_honors_declared_fixed_scalar_layout() {
    for fixture in AdmissionFixture::all() {
        for requested in [0, ncore::header_flags::COMPACT_LEN] {
            let (bare, flags) = {
                let _guard = ncore::DecodeFlagsGuard::enter(requested);
                norito::codec::encode_with_header_flags(&fixture)
            };
            let field_len = ncore::len_prefix_len_with_flags(1, flags) + 1;
            assert_eq!(bare.len(), 4 + field_len);
            assert_eq!(
                AdmissionFixture::inbound_admission_class(&bare, flags).unwrap(),
                fixture.admission_class()
            );
            let mut trailing = bare.clone();
            trailing.push(0);
            assert!(AdmissionFixture::inbound_admission_class(&trailing, flags).is_err());
            assert!(
                AdmissionFixture::inbound_admission_class(&bare[..bare.len() - 1], flags).is_err()
            );
            let mut unknown = bare;
            unknown[..4].copy_from_slice(&99_u32.to_le_bytes());
            assert!(AdmissionFixture::inbound_admission_class(&unknown, flags).is_err());
        }
    }
}

#[test]
fn admission_class_indices_and_ordinary_topics_are_total() {
    struct Ordinary(Topic);
    impl ClassifyTopic for Ordinary {
        fn topic(&self) -> Topic {
            self.0
        }
    }
    for (index, class) in A::ALL.into_iter().enumerate() {
        assert_eq!(class.index(), index);
    }
    let topics = [
        (Topic::ConsensusSafety, A::Safety),
        (Topic::Consensus, A::Lane),
        (Topic::ConsensusChunk, A::Payload),
        (Topic::ConsensusPayload, A::Payload),
        (Topic::BlockSync, A::BlockSync),
        (Topic::Control, A::Control),
        (Topic::TxGossip, A::Low),
        (Topic::TxGossipRestricted, A::Low),
        (Topic::PeerGossip, A::Low),
        (Topic::TrustGossip, A::Low),
        (Topic::Health, A::Low),
        (Topic::Connect, A::Low),
        (Topic::Other, A::Low),
    ];
    for (topic, expected) in topics {
        assert_eq!(A::ordinary_for_topic(topic), expected);
        assert_eq!(Ordinary(topic).admission_class(), expected);
    }
    assert!(
        Ordinary::inbound_admission_class(&[], 0).is_err(),
        "an absent raw classifier cannot fall back to the decoded topic"
    );
}

#[test]
fn ordinary_raw_admission_uses_only_the_raw_topic_owner() {
    struct Ordinary;
    impl ClassifyTopic for Ordinary {
        fn inbound_topic(payload: &[u8], _flags: u8) -> Result<Option<Topic>, ncore::Error> {
            match payload {
                [0] => Ok(Some(Topic::ConsensusChunk)),
                [1] => Ok(Some(Topic::Consensus)),
                [2] => Ok(None),
                _ => Err(ncore::Error::LengthMismatch),
            }
        }
    }
    assert_eq!(
        Ordinary::inbound_admission_class(&[0], 0).unwrap(),
        A::Payload
    );
    assert_eq!(Ordinary::inbound_admission_class(&[1], 0).unwrap(), A::Lane);
    assert!(Ordinary::inbound_admission_class(&[2], 0).is_err());
    assert!(Ordinary::inbound_admission_class(&[3], 0).is_err());
}

#[test]
fn relay_envelope_preserves_admission_classes_and_rejects_malformed_fields() {
    let key = KeyPair::try_from_seed(vec![61; 32], Algorithm::BlsNormal).unwrap();
    for fixture in AdmissionFixture::all() {
        let expected = fixture.admission_class();
        for target in [
            RelayTarget::Broadcast,
            RelayTarget::Direct(key.public_key().clone().into()),
        ] {
            let relay = RelayMessage::new_signed(&key, target, 1, fixture.clone());
            relay
                .verify_origin_signature()
                .expect("real signed relay fixture");
            assert_eq!(relay.admission_class(), expected);
            for requested in [0, ncore::header_flags::COMPACT_LEN] {
                let (bare, flags) = {
                    let _encode_guard = ncore::DecodeFlagsGuard::enter(requested);
                    norito::codec::encode_with_header_flags(&relay)
                };
                let decode_guard = ncore::DecodeFlagsGuard::enter(flags);
                let (decoded, consumed) =
                    ncore::decode_field_canonical::<RelayMessage<AdmissionFixture>>(&bare)
                        .expect("decode canonical relay under its advertised flags");
                assert_eq!(consumed, bare.len());
                assert_eq!(decoded.admission_class(), expected);
                assert_eq!(decoded.topic(), relay.topic());
                assert_eq!(
                    super::relay_message_wire_payload_len(
                        matches!(&relay.target, RelayTarget::Direct(_)),
                        ncore::encoded_payload_len(&relay.payload).unwrap(),
                        flags,
                    ),
                    Some(bare.len()),
                    "exact relay size witness follows its declared layout"
                );
                // Origin signatures bind canonical payload semantics. Restore
                // the signing context after decoding the selected frame layout.
                drop(decode_guard);
                decoded
                    .verify_origin_signature()
                    .expect("decoded relay retains its real origin signature");
                assert_eq!(
                    RelayMessage::<AdmissionFixture>::inbound_admission_class(&bare, flags)
                        .unwrap_or_else(|error| {
                            panic!(
                                "relay raw classification failed for flags {flags:#04x}: {error}"
                            )
                        }),
                    expected
                );
                let mut trailing = bare.clone();
                trailing.push(0);
                assert!(
                    RelayMessage::<AdmissionFixture>::inbound_admission_class(&trailing, flags)
                        .is_err()
                );
                assert!(
                    RelayMessage::<AdmissionFixture>::inbound_admission_class(
                        &bare[..bare.len() - 1],
                        flags
                    )
                    .is_err()
                );
                let nested = super::relay_message_payload_field(&bare, flags).unwrap();
                let offset = bare.len() - nested.len();
                let mut unknown = bare.clone();
                unknown[offset..offset + 4].copy_from_slice(&99_u32.to_le_bytes());
                assert!(
                    RelayMessage::<AdmissionFixture>::inbound_admission_class(&unknown, flags)
                        .is_err()
                );
            }
        }
    }
}

#[test]
fn semantic_subscribers_separate_classes_and_reject_overlap() {
    use super::SubscriberFilter;
    use super::message::SubscriberRoute;
    for expected in A::ALL {
        let filter = SubscriberFilter::semantic_class(expected);
        for fixture in AdmissionFixture::all() {
            assert_eq!(
                filter.matches(
                    fixture.topic(),
                    SubscriberRoute::General,
                    fixture.admission_class()
                ),
                expected == fixture.admission_class()
            );
            assert!(!filter.matches(
                fixture.topic(),
                SubscriberRoute::ToriiProxy,
                fixture.admission_class()
            ));
        }
        for other in A::ALL {
            if expected != other {
                assert!(!filter.overlaps_reliable(&SubscriberFilter::semantic_class(other)));
            }
        }
    }
    let broad_chunk = SubscriberFilter::topics([Topic::ConsensusChunk]);
    assert!(broad_chunk.overlaps_reliable(&SubscriberFilter::semantic_class(A::Payload)));
    assert!(!broad_chunk.overlaps_reliable(&SubscriberFilter::semantic_class(A::Safety)));
    assert!(
        SubscriberFilter::topics([Topic::Consensus])
            .overlaps_reliable(&SubscriberFilter::semantic_class(A::Lane))
    );
}

#[test]
fn admission_schedule_preserves_low_priority_without_starving_low_service() {
    for class in A::ALL {
        let ranks = A::SCHEDULE
            .into_iter()
            .filter(|rank| *rank == class)
            .count();
        assert_eq!(ranks, if class.is_low() { 1 } else { 2 });
        assert_eq!(class.is_low(), A::LOW.contains(&class));
    }
    assert_eq!(A::ordinary_for_topic(Topic::BlockSync), A::BlockSync);
    assert_eq!(
        Topic::BlockSync.scheduling_priority(),
        super::message::Priority::Low
    );
    assert!(!A::Payload.is_low());
}

#[test]
fn actor_semantic_sources_map_every_admission_class() {
    use super::ActorProgressClass as C;
    let expected = [
        Some(C::Safety),
        Some(C::Lane),
        Some(C::Payload),
        None,
        Some(C::BlockSync),
        None,
    ];
    for (fixture, expected) in AdmissionFixture::all().into_iter().zip(expected) {
        assert_eq!(C::for_payload(&fixture), expected);
    }
}

#[test]
fn actor_waiters_give_every_class_the_full_per_source_envelope() {
    use super::{
        ActorProgressByteLimits, ActorProgressClass as C, NetworkActorProgressBudget,
        RELIABLE_PROGRESS_WAITERS_PER_SOURCE, actor_waiter_limits,
    };
    let limits = actor_waiter_limits().unwrap();
    assert_eq!(
        limits[C::Lane.index()],
        RELIABLE_PROGRESS_WAITERS_PER_SOURCE
    );
    assert_eq!(
        limits.into_iter().sum::<usize>(),
        4 * RELIABLE_PROGRESS_WAITERS_PER_SOURCE
    );
    assert!(
        C::ALL
            .into_iter()
            .all(|class| limits[class.index()] == RELIABLE_PROGRESS_WAITERS_PER_SOURCE)
    );
    let total = 4 * 4 * RELIABLE_PROGRESS_WAITERS_PER_SOURCE;
    assert!(
        NetworkActorProgressBudget::new_classed(ActorProgressByteLimits::uniform(1024), 4, total)
            .is_some()
    );
    assert!(
        NetworkActorProgressBudget::new_classed(
            ActorProgressByteLimits::uniform(1024),
            4,
            total + 1
        )
        .is_none()
    );
}

/// The shipping default configuration funds every admission class: topic geometry, the
/// classed actor budget, the receive-credit pool, the semantic post pool and the writer
/// partitions all construct from the default maxima.
#[test]
fn shipping_default_geometry_funds_every_admission_class() {
    use super::{
        DeferredSendLimits, NetworkActorProgressBudget, OutboundFrameQueueLimits, TopicFrameCaps,
        TransportChannelCapacities, inbound_source_credit_capacity,
        network_actor_progress_target_capacity, network_actor_progress_waiter_capacity,
        validate_transport_queue_geometry,
    };
    use iroha_config::parameters::defaults::network as d;
    use iroha_crypto::encryption::ChaCha20Poly1305 as Cipher;
    let caps = TopicFrameCaps {
        consensus: d::MAX_FRAME_BYTES_CONSENSUS.get(),
        control: d::MAX_FRAME_BYTES_CONTROL.get(),
        block_sync: d::MAX_FRAME_BYTES_BLOCK_SYNC.get(),
        tx_gossip: d::MAX_FRAME_BYTES_TX_GOSSIP.get(),
        peer_gossip: d::MAX_FRAME_BYTES_PEER_GOSSIP.get(),
        health: d::MAX_FRAME_BYTES_HEALTH.get(),
        connect: d::MAX_FRAME_BYTES_CONNECT.get(),
        other: d::MAX_FRAME_BYTES_OTHER.get(),
    };
    let high = d::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_BYTES.get();
    let low = d::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_BYTES.get();
    let connections = d::lane_profile::CORE_MAX_TOTAL_CONNECTIONS;
    let geometry = validate_transport_queue_geometry::<Cipher>(
        d::MAX_FRAME_BYTES.get(),
        caps,
        high,
        low,
        DeferredSendLimits {
            total_bytes: d::DEFERRED_SEND_MAX_BYTES_TOTAL,
            per_peer_bytes: d::DEFERRED_SEND_MAX_BYTES_PER_PEER,
            per_peer_frames: d::DEFERRED_SEND_MAX_PER_PEER,
        },
        TransportChannelCapacities {
            high: d::P2P_QUEUE_CAP_HIGH.get(),
            low: d::P2P_QUEUE_CAP_LOW.get(),
            post: d::P2P_POST_QUEUE_CAP.get(),
            subscriber: d::P2P_SUBSCRIBER_QUEUE_CAP.get(),
        },
    )
    .unwrap();
    let maxima = caps
        .admission_maxima(crate::frame_plaintext_cap_for::<Cipher>(
            d::MAX_FRAME_BYTES.get(),
        ))
        .unwrap();
    assert_eq!(maxima[A::Safety.index()], caps.control);
    assert_eq!(maxima[A::Lane.index()], caps.consensus);
    assert_eq!(maxima[A::Payload.index()], caps.block_sync);
    assert_eq!(maxima[A::BlockSync.index()], caps.block_sync);
    let targets = network_actor_progress_target_capacity(connections).unwrap();
    NetworkActorProgressBudget::new_classed(
        geometry.actor_progress_bytes,
        targets,
        network_actor_progress_waiter_capacity(connections).unwrap(),
    )
    .unwrap();
    let source_geometry = crate::peer::AuthenticatedSourceGeometry::new(connections);
    let source = crate::peer::InboundFrameByteBudgets::new_with_source_geometry(
        high,
        low,
        geometry.progress_reserve_bytes,
        source_geometry.clone(),
    )
    .unwrap();
    let dispatch =
        crate::peer::InboundDispatchByteBudgets::new(high, low, geometry.safety_reserve_bytes)
            .unwrap();
    crate::peer::receive_credit::Pool::new(
        source,
        dispatch,
        inbound_source_credit_capacity(d::P2P_SUBSCRIBER_QUEUE_CAP.get(), connections).unwrap(),
        maxima,
    )
    .unwrap();
    let posts = crate::peer::OutboundPostByteBudgets::new_with_source_geometry(
        high,
        low,
        geometry.progress_reserve_bytes,
        source_geometry,
    )
    .unwrap();
    posts.install_semantic(maxima).unwrap();
    let writer = OutboundFrameQueueLimits::new_with_progress_reserve(
        high,
        low,
        geometry.progress_reserve_bytes,
        d::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_FRAMES.get(),
        d::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_FRAMES.get(),
    );
    crate::peer::receive_credit::writer_partitions(maxima, writer).unwrap();
}

#[test]
fn admission_class_codes_bind_geometry_and_record_order() {
    let expected = [
        (A::Safety, 0_u8),
        (A::Lane, 1),
        (A::Payload, 2),
        (A::Control, 3),
        (A::BlockSync, 4),
        (A::Low, 5),
    ];
    assert_eq!(A::ALL, expected.map(|(class, _)| class));
    for (class, code) in expected {
        assert_eq!(class.wire_code(), code);
        assert_eq!(class.index(), usize::from(code));
    }
}

/// The Sumeragi route is variant-disjoint: its semantic FIFOs never receive the general
/// route's messages and never overlap a general subscriber of the same class, while a second
/// Sumeragi subscriber of a class it already owns is an overlap (single consumer).
#[test]
fn sumeragi_route_owns_its_semantic_fifos() {
    use super::SubscriberFilter;
    use super::message::SubscriberRoute;
    for class in [A::Safety, A::Payload, A::BlockSync] {
        let sumeragi = SubscriberFilter::SemanticClass {
            class,
            route: SubscriberRoute::Sumeragi,
        };
        let general = SubscriberFilter::semantic_class(class);
        for fixture in AdmissionFixture::all() {
            let (topic, fixture_class) = (fixture.topic(), fixture.admission_class());
            assert_eq!(
                sumeragi.matches(topic, SubscriberRoute::Sumeragi, fixture_class),
                fixture_class == class
            );
            assert!(!sumeragi.matches(topic, SubscriberRoute::General, fixture_class));
            assert!(!general.matches(topic, SubscriberRoute::Sumeragi, fixture_class));
        }
        assert!(!sumeragi.overlaps_reliable(&general));
        assert!(sumeragi.overlaps_reliable(&sumeragi.clone()));
        assert!(sumeragi.overlaps_reliable(&SubscriberFilter::All));
    }
    assert!(
        !SubscriberFilter::topics([Topic::ConsensusSafety]).overlaps_reliable(
            &SubscriberFilter::SemanticClass {
                class: A::Safety,
                route: SubscriberRoute::Sumeragi,
            }
        ),
        "topic-only subscribers own the general route"
    );
}
