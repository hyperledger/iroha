#[cfg(test)]
mod handle_update_tests {
    use super::*;
    use iroha_config::parameters::actual::SoranetHandshake as ActualSoranetHandshake;
    use iroha_crypto::encryption::ChaCha20Poly1305;
    use iroha_primitives::addr::socket_addr;
    use norito::codec::{Decode, DecodeAll, Encode};
    use std::{
        collections::HashSet,
        sync::{Barrier, atomic::AtomicUsize},
    };
    use tokio::sync::{mpsc, watch};
    fn random_node_key_pair() -> KeyPair {
        KeyPair::random_with_algorithm(Algorithm::BlsNormal)
    }
    fn random_node_peer_id() -> PeerId {
        PeerId::from(random_node_key_pair().public_key().clone())
    }
    #[test]
    fn captured_original_test_payload_identities() {
        crate::frame_identity_tests::manual_test_payload_identity::<FailingSerializerPayload>(
            "iroha_p2p::network::handle_update_tests::FailingSerializerPayload",
        );
        crate::frame_identity_tests::manual_test_payload_identity::<BadLengthHintPayload>(
            "iroha_p2p::network::handle_update_tests::BadLengthHintPayload",
        );
        crate::frame_identity_tests::test_payload_identity::<Dummy>(
            "iroha_p2p::network::handle_update_tests::Dummy",
        );
        crate::frame_identity_tests::test_payload_identity::<CloneCountingPayload>(
            "iroha_p2p::network::handle_update_tests::CloneCountingPayload",
        );
        crate::frame_identity_tests::test_payload_identity::<RoutedActorDummy>(
            "iroha_p2p::network::handle_update_tests::RoutedActorDummy",
        );
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_p2p::network::handle_update_tests::Dummy")]
    #[derive(Clone, Debug, Decode, Encode)]
    struct Dummy;
    impl message::ClassifyTopic for Dummy {}
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_p2p::network::handle_update_tests::CloneCountingPayload")]
    #[derive(Debug, Decode, Encode)]
    struct CloneCountingPayload(Vec<u8>);
    static ACTOR_SIZE_CLONES: AtomicUsize = AtomicUsize::new(0);
    impl Clone for CloneCountingPayload {
        fn clone(&self) -> Self {
            ACTOR_SIZE_CLONES.fetch_add(1, Ordering::Relaxed);
            Self(self.0.clone())
        }
    }
    impl message::ClassifyTopic for CloneCountingPayload {}
    impl<'a> norito::core::DecodeFromSlice<'a> for CloneCountingPayload {
        fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
            let mut slice = bytes;
            let value = <Self as DecodeAll>::decode_all(&mut slice).map_err(|error| {
                norito::core::Error::Message(format!("codec decode error: {error}"))
            })?;
            Ok((value, bytes.len() - slice.len()))
        }
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_p2p::network::handle_update_tests::BadLengthHintPayload")]
    #[derive(Clone, Debug)]
    struct BadLengthHintPayload;
    impl ncore::SerializePayload for BadLengthHintPayload {
        fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
            writer.write_all(&[1, 2, 3, 4])?;
            Ok(())
        }
        fn encoded_len_exact(&self) -> Option<usize> {
            Some(1)
        }
    }
    impl<'a> ncore::DeserializePayload<'a> for BadLengthHintPayload {
        fn deserialize(_archived: &'a ncore::Archived<Self>) -> Self {
            Self
        }
    }
    impl<'a> ncore::DecodeFromSlice<'a> for BadLengthHintPayload {
        fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
            if bytes.len() < 4 {
                return Err(ncore::Error::LengthMismatch);
            }
            Ok((Self, 4))
        }
    }
    impl message::ClassifyTopic for BadLengthHintPayload {}
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_p2p::network::handle_update_tests::FailingSerializerPayload")]
    #[derive(Clone, Debug)]
    struct FailingSerializerPayload;
    impl ncore::SerializePayload for FailingSerializerPayload {
        fn serialize(&self, _writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
            Err(ncore::Error::Message(
                "intentional actor-admission serialization failure".to_owned(),
            ))
        }
    }
    impl<'a> ncore::DeserializePayload<'a> for FailingSerializerPayload {
        fn deserialize(_archived: &'a ncore::Archived<Self>) -> Self {
            Self
        }
    }
    impl<'a> ncore::DecodeFromSlice<'a> for FailingSerializerPayload {
        fn decode_from_slice(_bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
            Err(ncore::Error::Message(
                "intentional actor-admission decode failure".to_owned(),
            ))
        }
    }
    impl message::ClassifyTopic for FailingSerializerPayload {}
    impl<'a> norito::core::DecodeFromSlice<'a> for Dummy {
        fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
            let mut slice = bytes;
            let value = <Self as DecodeAll>::decode_all(&mut slice).map_err(|error| {
                norito::core::Error::Message(format!("codec decode error: {error}"))
            })?;
            Ok((value, bytes.len() - slice.len()))
        }
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_p2p::network::handle_update_tests::RoutedActorDummy")]
    #[derive(Clone, Debug, Decode, Encode, PartialEq, Eq)]
    enum RoutedActorDummy {
        Safety,
        Control,
        Lane,
        LaneAlternate,
        BlockSync,
    }
    impl message::ClassifyTopic for RoutedActorDummy {
        fn topic(&self) -> message::Topic {
            match self {
                Self::Safety => message::Topic::ConsensusSafety,
                Self::Control => message::Topic::Control,
                Self::Lane | Self::LaneAlternate => message::Topic::Consensus,
                Self::BlockSync => message::Topic::BlockSync,
            }
        }
        fn progress_reconstruction(&self) -> message::ProgressReconstruction {
            message::ProgressReconstruction::Retransmit
        }
    }
    impl<'a> norito::core::DecodeFromSlice<'a> for RoutedActorDummy {
        fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
            let mut slice = bytes;
            let value = <Self as DecodeAll>::decode_all(&mut slice).map_err(|error| {
                norito::core::Error::Message(format!("codec decode error: {error}"))
            })?;
            Ok((value, bytes.len() - slice.len()))
        }
    }
    #[test]
    fn actor_admission_fixture_uses_exact_semantic_geometry_and_releases_queue_ownership() {
        let peer = |seed| {
            PeerId::new(
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                    .expect("canonical relay node key")
                    .public_key()
                    .clone(),
            )
        };
        let self_id = peer(1);
        let targets = (2..5).map(peer).collect::<BTreeSet<_>>();
        let capacity = std::num::NonZeroUsize::new(1).expect("one actor slot");
        for selected_targets in [BTreeSet::new(), targets] {
            let (handle, mut fixture) =
                NetworkBaseHandle::<RoutedActorDummy, ChaCha20Poly1305>::actor_admission_for_tests(
                    self_id.clone(),
                    selected_targets.clone(),
                    capacity,
                );
            let limits = actor_waiter_limits().expect("production waiter geometry");
            let target_count = selected_targets.len().max(1);
            let budget = &handle.network_actor_progress_budget;
            assert_eq!(budget.max_sources_per_class, target_count);
            assert_eq!(budget.max_waiters_per_source, limits);
            assert_eq!(
                budget.max_waiters,
                target_count * limits.into_iter().sum::<usize>()
            );
            for class in ActorProgressClass::ALL {
                assert_eq!(
                    budget.max_waiters_per_class[class.index()],
                    target_count * limits[class.index()]
                );
            }
            for target in &selected_targets {
                for _ in 0..2 {
                    handle
                        .post_recoverable(
                            Post {
                                data: RoutedActorDummy::Safety,
                                peer_id: target.clone(),
                                priority: Priority::High,
                            },
                            None,
                        )
                        .expect("admit into the real capacity-one actor queue");
                    assert_eq!(
                        fixture.drain_posts(|post| {
                            assert_eq!(&post.peer_id, target);
                            assert_eq!(post.data, RoutedActorDummy::Safety);
                        }),
                        1
                    );
                }
            }
            assert_eq!(fixture.drain_posts(|_| panic!("all posts were drained")), 0);
        }
    }

    fn test_network_actor_byte_budget() -> Arc<NetworkActorByteBudget> {
        NetworkActorByteBudget::new(usize::MAX, 0)
            .expect("zero safety reserve must fit the test actor budget")
    }
    fn test_topic_frame_caps() -> TopicFrameCaps {
        TopicFrameCaps {
            consensus: usize::MAX,
            control: usize::MAX,
            block_sync: usize::MAX,
            tx_gossip: usize::MAX,
            peer_gossip: usize::MAX,
            connect: usize::MAX,
            health: usize::MAX,
            other: usize::MAX,
        }
    }
    #[test]
    fn network_actor_byte_budget_preserves_additive_safety_reserve() {
        assert!(NetworkActorByteBudget::new(usize::MAX, 0).is_some());
        assert!(
            NetworkActorByteBudget::new(usize::MAX, 1).is_none(),
            "aggregate capacity overflow must fail closed"
        );
        let budget = NetworkActorByteBudget::new(10, 4).expect("small exact budget");
        let ordinary = budget
            .try_reserve(10, false)
            .expect("ordinary traffic owns its complete configured subcap");
        assert_eq!(
            budget.retained(),
            NetworkActorRetainedBytes {
                total: 10,
                ordinary: 10,
            }
        );
        assert!(budget.try_reserve(1, false).is_none());
        let safety = budget
            .try_reserve(4, true)
            .expect("ordinary saturation must leave the safety reserve available");
        assert_eq!(
            budget.retained(),
            NetworkActorRetainedBytes {
                total: 14,
                ordinary: 10,
            }
        );
        assert!(budget.try_reserve(1, true).is_none());
        drop(ordinary);
        assert_eq!(
            budget.retained(),
            NetworkActorRetainedBytes {
                total: 4,
                ordinary: 0,
            }
        );
        let replacement = budget
            .try_reserve(10, false)
            .expect("released ordinary ownership must be reusable while safety is retained");
        drop((replacement, safety));
        assert_eq!(budget.retained(), NetworkActorRetainedBytes::default());
    }
    #[test]
    fn progress_budget_bounds_unregistered_waiters_without_fresh_barging() {
        assert!(
            NetworkActorProgressBudget::new(usize::MAX, 2, 2).is_none(),
            "per-source reserve multiplication must fail closed"
        );
        let classed = NetworkActorProgressBudget::new_classed(
            ActorProgressByteLimits {
                safety: 1,
                lane: 2,
                bulk: 4,
            },
            2,
            390,
        )
        .expect("small classed geometry must fit");
        assert_eq!(classed.max_sources, 6);
        assert_eq!(classed.max_sources_per_class, 2);
        assert_eq!(classed.max_total_bytes, 14);
        assert_eq!(classed.max_waiters_per_source, [65, 65, 65]);
        let budget = NetworkActorProgressBudget::new(10, 1, 1).expect("small progress budget");
        let shape = ProgressTicketShape {
            topic: message::Topic::BlockSync,
            stream_wire_bytes: 10,
            broadcast: false,
            reply_writer_timeout_attempt: None,
            request_digest: Hash::new(b"progress-budget-waiter"),
            authority: None,
        };
        let ProgressLeaseAttempt::Ready {
            lease: full_lease,
            ticket: mut accepted_ticket,
        } = budget.try_reserve(10, shape, None)
        else {
            panic!("the exact progress maximum must be admitted");
        };
        accepted_ticket.commit();
        assert_eq!(budget.retained(), 10);
        let ProgressLeaseAttempt::Waiting {
            ticket: Some(first_ticket),
            rank: 1,
        } = budget.try_reserve(1, shape, None)
        else {
            panic!("the first blocked source must receive rank one");
        };
        let ProgressLeaseAttempt::Waiting {
            ticket: None,
            rank: 2,
        } = budget.try_reserve(1, shape, None)
        else {
            panic!("a second blocked producer must not consume another waiter slot");
        };
        drop(full_lease);
        let ProgressLeaseAttempt::Ready {
            lease,
            ticket: mut first_ticket,
        } = budget.try_reserve(1, shape, Some(first_ticket))
        else {
            panic!("the live source ticket must acquire released capacity");
        };
        first_ticket.commit();
        drop(lease);
        assert_eq!(budget.retained(), 0);
    }
    #[test]
    fn progress_budget_preserves_fifo_for_three_registered_producers() {
        let budget = NetworkActorProgressBudget::new(1, 1, 4)
            .expect("one source with four registered waiter ranks");
        let shape = |tag| ProgressTicketShape {
            topic: message::Topic::Consensus,
            stream_wire_bytes: 1,
            broadcast: false,
            reply_writer_timeout_attempt: None,
            request_digest: Hash::new([tag]),
            authority: None,
        };
        let ProgressLeaseAttempt::Ready {
            lease: occupied,
            ticket: mut admitted,
        } = budget.try_reserve(1, shape(0), None)
        else {
            panic!("fixture must occupy the source slot");
        };
        admitted.commit();
        let mut tickets = Vec::new();
        for expected_rank in 1..=3 {
            let ProgressLeaseAttempt::Waiting {
                ticket: Some(ticket),
                rank,
            } = budget.try_reserve(1, shape(expected_rank), None)
            else {
                panic!("each bounded producer must receive a persistent rank");
            };
            assert_eq!(rank, usize::from(expected_rank));
            tickets.push(ticket);
        }
        let first = tickets.remove(0);
        drop(first);
        assert_eq!(tickets[0].rank(), Some(1));
        assert_eq!(tickets[1].rank(), Some(2));
        drop(occupied);
        let second = tickets.remove(0);
        let ProgressLeaseAttempt::Ready {
            lease: second_lease,
            ticket: mut second,
        } = budget.try_reserve(1, shape(2), Some(second))
        else {
            panic!("oldest surviving producer must acquire the released source");
        };
        second.commit();
        drop(second_lease);
        assert_eq!(tickets[0].rank(), Some(1));
        let third = tickets.remove(0);
        let ProgressLeaseAttempt::Ready {
            lease: third_lease,
            ticket: mut third,
        } = budget.try_reserve(1, shape(3), Some(third))
        else {
            panic!("the final producer's rank must decrease to service");
        };
        third.commit();
        drop(third_lease);
        assert_eq!(budget.retained(), 0);
    }
    #[test]
    fn configured_producer_geometry_gives_six_same_source_waiters_decreasing_ranks() {
        let waiters_per_source = RELIABLE_PROGRESS_WAITERS_PER_SOURCE;
        assert!(
            waiters_per_source >= 6,
            "the complete production geometry must cover the adversarial waiter set"
        );
        let target_sources = 2_usize;
        let per_target = actor_waiter_limits().expect("production class waiter geometry");
        assert_eq!(
            per_target[ActorProgressClass::Lane.index()],
            waiters_per_source
        );
        let max_waiters = per_target
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .and_then(|count| count.checked_mul(target_sources))
            .expect("small test producer/source geometry");
        let budget = NetworkActorProgressBudget::new_classed(
            ActorProgressByteLimits::uniform(1),
            target_sources,
            max_waiters,
        )
        .expect("checked production-derived waiter geometry");
        let source_a = ActorProgressSource {
            target: Some(random_node_peer_id()),
            class: ActorProgressClass::Lane,
        };
        let source_b = ActorProgressSource {
            target: Some(random_node_peer_id()),
            class: ActorProgressClass::Lane,
        };
        let shape = |tag| ProgressTicketShape {
            topic: message::Topic::Consensus,
            stream_wire_bytes: 1,
            broadcast: false,
            reply_writer_timeout_attempt: None,
            request_digest: Hash::new([tag]),
            authority: None,
        };
        let ProgressLeaseAttempt::Ready {
            lease: occupied_a,
            ticket: mut admitted_a,
        } = budget.try_reserve_for_source(1, shape(0), source_a.clone(), None, None)
        else {
            panic!("source A fixture must occupy its actor lane");
        };
        admitted_a.commit();
        let mut waiters = Vec::new();
        for expected_rank in 1_u8..=6 {
            let request_shape = shape(expected_rank);
            let ProgressLeaseAttempt::Waiting {
                ticket: Some(ticket),
                rank,
            } = budget.try_reserve_for_source(1, request_shape, source_a.clone(), None, None)
            else {
                panic!("every admitted source-A producer must receive a persistent rank");
            };
            assert_eq!(rank, usize::from(expected_rank));
            waiters.push((request_shape, ticket));
        }
        let ProgressLeaseAttempt::Ready {
            lease: independent_b,
            ticket: mut admitted_b,
        } = budget.try_reserve_for_source(1, shape(100), source_b, None, None)
        else {
            panic!("source A saturation must not consume source B's reserved lane");
        };
        admitted_b.commit();
        drop(independent_b);
        drop(occupied_a);
        while !waiters.is_empty() {
            for (index, (_, ticket)) in waiters.iter().enumerate() {
                assert_eq!(
                    ticket.rank(),
                    Some(index + 1),
                    "each service step must strictly decrease every surviving rank"
                );
            }
            let (request_shape, ticket) = waiters.remove(0);
            let ProgressLeaseAttempt::Ready {
                lease,
                ticket: mut ready,
            } = budget.try_reserve_for_source(
                1,
                request_shape,
                source_a.clone(),
                None,
                Some(ticket),
            )
            else {
                panic!("the exact source-A head must acquire released actor ownership");
            };
            ready.commit();
            drop(lease);
        }
        assert_eq!(budget.retained(), 0);
    }
    #[test]
    fn targetized_broadcast_coalesces_only_the_same_digest_and_membership() {
        let budget =
            NetworkActorProgressBudget::new_classed(ActorProgressByteLimits::uniform(1), 1, 195)
                .expect("one target per class must fit");
        let target = random_node_peer_id();
        let source = ActorProgressSource {
            target: Some(target.clone()),
            class: ActorProgressClass::Lane,
        };
        let membership = |generation| {
            Arc::new(ReliableProgressMembership {
                peer_id: target.clone(),
                generation,
                active: AtomicBool::new(true),
            })
        };
        let generation_seven = membership(7);
        let generation_eight = membership(8);
        let generation_seven_authority =
            ProgressDeliveryAuthority::Topology(Arc::clone(&generation_seven));
        let generation_eight_authority =
            ProgressDeliveryAuthority::Topology(Arc::clone(&generation_eight));
        let shape = |request_digest, generation| ProgressTicketShape {
            topic: message::Topic::Consensus,
            stream_wire_bytes: 1,
            broadcast: true,
            reply_writer_timeout_attempt: None,
            request_digest,
            authority: Some(ProgressAuthorityIdentity::Topology(generation)),
        };
        let first_digest = Hash::new(b"first-broadcast-request");
        let ProgressLeaseAttempt::Ready {
            lease: first,
            ticket: mut admitted,
        } = budget.try_reserve_for_source(
            1,
            shape(first_digest, 7),
            source.clone(),
            Some(&generation_seven_authority),
            None,
        )
        else {
            panic!("first targetized request must own the lane");
        };
        admitted.commit();
        assert!(matches!(
            budget.try_reserve_for_source(
                1,
                shape(first_digest, 7),
                source.clone(),
                Some(&generation_seven_authority),
                None,
            ),
            ProgressLeaseAttempt::SameRequestAlreadyOwned
        ));
        assert!(matches!(
            budget.try_reserve_for_source(
                1,
                shape(Hash::new(b"second-broadcast-request"), 7),
                source.clone(),
                Some(&generation_seven_authority),
                None,
            ),
            ProgressLeaseAttempt::Waiting { rank: 1, .. }
        ));
        assert!(matches!(
            budget.try_reserve_for_source(
                1,
                shape(first_digest, 8),
                source,
                Some(&generation_eight_authority),
                None,
            ),
            ProgressLeaseAttempt::Waiting { rank: 1, .. }
        ));
        drop(first);
        assert_eq!(budget.retained(), 0);
    }
    #[test]
    fn removed_membership_cancellation_is_race_safe_across_ticket_id_reuse() {
        let target = random_node_peer_id();
        let source = ActorProgressSource {
            target: Some(target.clone()),
            class: ActorProgressClass::Lane,
        };
        let membership = |generation| {
            Arc::new(ReliableProgressMembership {
                peer_id: target.clone(),
                generation,
                active: AtomicBool::new(true),
            })
        };
        let broadcast_shape = |generation, tag| ProgressTicketShape {
            topic: message::Topic::Consensus,
            stream_wire_bytes: 1,
            broadcast: true,
            reply_writer_timeout_attempt: None,
            request_digest: Hash::new([tag]),
            authority: Some(ProgressAuthorityIdentity::Topology(generation)),
        };
        let direct_shape = ProgressTicketShape {
            topic: message::Topic::Consensus,
            stream_wire_bytes: 1,
            broadcast: false,
            reply_writer_timeout_attempt: None,
            request_digest: Hash::new(b"membership-cancellation-direct-owner"),
            authority: None,
        };
        let budget =
            NetworkActorProgressBudget::new_classed(ActorProgressByteLimits::uniform(1), 1, 195)
                .expect("one target with production class waiter ranks must fit");
        let ProgressLeaseAttempt::Ready {
            lease: direct_lease,
            ticket: mut direct_ticket,
        } = budget.try_reserve_for_source(1, direct_shape, source.clone(), None, None)
        else {
            panic!("direct fixture must retain the shared target lane");
        };
        direct_ticket.commit();
        let old_membership = membership(7);
        let old_authority = ProgressDeliveryAuthority::Topology(Arc::clone(&old_membership));
        let old_shape = broadcast_shape(7, 7);
        let ProgressLeaseAttempt::Waiting {
            ticket: Some(old_ticket),
            rank: 1,
        } = budget.try_reserve_for_source(1, old_shape, source.clone(), Some(&old_authority), None)
        else {
            panic!("old membership must own the first blocked rank");
        };
        old_membership.cancel();
        assert_eq!(budget.cancel_membership(&old_membership, true), 1);
        assert_eq!(old_ticket.rank(), None);
        let new_membership = membership(8);
        let new_authority = ProgressDeliveryAuthority::Topology(Arc::clone(&new_membership));
        let new_shape = broadcast_shape(8, 8);
        let ProgressLeaseAttempt::Waiting {
            ticket: Some(new_ticket),
            rank: 1,
        } = budget.try_reserve_for_source(1, new_shape, source.clone(), Some(&new_authority), None)
        else {
            panic!("new membership must reuse the released rank exactly");
        };
        assert_eq!(old_ticket.id, new_ticket.id, "empty waiter set resets ids");
        drop(old_ticket);
        assert_eq!(
            new_ticket.rank(),
            Some(1),
            "delayed old-ticket drop must match its complete old shape"
        );
        drop(direct_lease);
        let ProgressLeaseAttempt::Ready {
            lease: new_lease,
            ticket: mut new_ticket,
        } = budget.try_reserve_for_source(
            1,
            new_shape,
            source.clone(),
            Some(&new_authority),
            Some(new_ticket),
        )
        else {
            panic!("new membership must acquire the released target lane");
        };
        new_ticket.commit();
        drop(new_lease);
        // Reconciliation can remove the waiter after `Ready` installs its
        // lease but before the channel handoff commits the ticket. That exact
        // cancelled commit is a no-op, not a panic or a cancellation of later
        // work.
        let commit_race_membership = membership(9);
        let commit_race_authority =
            ProgressDeliveryAuthority::Topology(Arc::clone(&commit_race_membership));
        let commit_race_shape = broadcast_shape(9, 9);
        let ProgressLeaseAttempt::Ready {
            lease: commit_race_lease,
            ticket: mut commit_race_ticket,
        } = budget.try_reserve_for_source(
            1,
            commit_race_shape,
            source.clone(),
            Some(&commit_race_authority),
            None,
        )
        else {
            panic!("commit-race membership must initially acquire the lane");
        };
        commit_race_membership.cancel();
        assert_eq!(budget.cancel_membership(&commit_race_membership, true), 1);
        commit_race_ticket.commit();
        drop(commit_race_lease);
        // Force reservation to wait on the budget lock, publish cancellation,
        // then race reservation against the reconciliation sweep. Since the
        // membership check happens under the same budget lock, neither order
        // can install a post-sweep stale waiter.
        let cancelled_membership = membership(10);
        let cancelled_shape = broadcast_shape(10, 10);
        let barrier = Arc::new(Barrier::new(2));
        let state_guard = budget
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::thread::scope(|scope| {
            let worker_budget = Arc::clone(&budget);
            let worker_membership = Arc::clone(&cancelled_membership);
            let worker_source = source.clone();
            let worker_barrier = Arc::clone(&barrier);
            let worker = scope.spawn(move || {
                worker_barrier.wait();
                let worker_authority = ProgressDeliveryAuthority::Topology(worker_membership);
                worker_budget.try_reserve_for_source(
                    1,
                    cancelled_shape,
                    worker_source,
                    Some(&worker_authority),
                    None,
                )
            });
            barrier.wait();
            cancelled_membership.cancel();
            drop(state_guard);
            let swept = budget.cancel_membership(&cancelled_membership, true);
            assert!(matches!(
                worker.join().expect("reservation race thread"),
                ProgressLeaseAttempt::CancelledMembership
            ));
            assert_eq!(swept, 0, "cancelled reservation never creates a waiter");
        });
        let state = budget
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.waiter_count, 0);
        assert!(state.waiters.is_empty());
        assert_eq!(state.retained_items, 0);
    }
    #[test]
    fn progress_class_geometry_reserves_safety_from_arbitrary_lane_sources() {
        let budget =
            NetworkActorProgressBudget::new_classed(ActorProgressByteLimits::uniform(1), 1, 195)
                .expect("single-target class geometry must fit");
        let first_target = random_node_peer_id();
        let second_target = random_node_peer_id();
        let lane_shape = ProgressTicketShape {
            topic: message::Topic::Consensus,
            stream_wire_bytes: 1,
            broadcast: false,
            reply_writer_timeout_attempt: None,
            request_digest: Hash::new(b"lane-progress-budget"),
            authority: None,
        };
        let ProgressLeaseAttempt::Ready {
            lease: lane_lease,
            ticket: mut lane_admission,
        } = budget.try_reserve_for_source(
            1,
            lane_shape,
            ActorProgressSource {
                target: Some(first_target),
                class: ActorProgressClass::Lane,
            },
            None,
            None,
        )
        else {
            panic!("first lane source must be admitted");
        };
        lane_admission.commit();
        let ProgressLeaseAttempt::Waiting {
            ticket: Some(lane_waiter),
            rank: 1,
        } = budget.try_reserve_for_source(
            1,
            lane_shape,
            ActorProgressSource {
                target: Some(second_target.clone()),
                class: ActorProgressClass::Lane,
            },
            None,
            None,
        )
        else {
            panic!("a second arbitrary lane target must remain with its caller");
        };
        let ProgressLeaseAttempt::Ready {
            lease: safety_lease,
            ticket: mut safety_admission,
        } = budget.try_reserve_for_source(
            1,
            ProgressTicketShape {
                topic: message::Topic::ConsensusSafety,
                stream_wire_bytes: 1,
                broadcast: false,
                reply_writer_timeout_attempt: None,
                request_digest: Hash::new(b"safety-progress-budget"),
                authority: None,
            },
            ActorProgressSource {
                target: Some(second_target),
                class: ActorProgressClass::Safety,
            },
            None,
            None,
        )
        else {
            panic!("lane-source saturation must leave the safety class available");
        };
        safety_admission.commit();
        drop((lane_waiter, lane_lease, safety_lease));
        assert_eq!(budget.retained(), 0);
    }
    #[test]
    fn progress_ticket_allocation_never_wraps_and_resets_only_when_empty() {
        let budget = NetworkActorProgressBudget::new(1, 2, 2).expect("small progress budget");
        let shape = ProgressTicketShape {
            topic: message::Topic::BlockSync,
            stream_wire_bytes: 1,
            broadcast: false,
            reply_writer_timeout_attempt: None,
            request_digest: Hash::new(b"progress-ticket-wrap"),
            authority: None,
        };
        let ProgressLeaseAttempt::Ready {
            lease,
            ticket: mut accepted_ticket,
        } = budget.try_reserve(1, shape, None)
        else {
            panic!("fixture must fill the one-byte owner");
        };
        accepted_ticket.commit();
        let ProgressLeaseAttempt::Waiting {
            ticket: Some(waiting_ticket),
            rank: 1,
        } = budget.try_reserve(1, shape, None)
        else {
            panic!("fixture must install a live waiter");
        };
        budget
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .next_ticket = u64::MAX;
        assert!(matches!(
            budget.try_reserve(1, shape, None),
            ProgressLeaseAttempt::Waiting {
                ticket: None,
                rank: 2
            }
        ));
        drop(waiting_ticket);
        let ProgressLeaseAttempt::Waiting {
            ticket: Some(reset_ticket),
            rank: 1,
        } = budget.try_reserve(1, shape, None)
        else {
            panic!("an empty waiter queue must reset allocation safely");
        };
        assert_eq!(reset_ticket.id, 0);
        drop((reset_ticket, lease));
        assert_eq!(budget.retained(), 0);
    }
    #[test]
    fn admitted_network_message_releases_byte_ownership_on_drop() {
        let budget = NetworkActorByteBudget::new(8, 2).expect("small exact budget");
        let lease = budget
            .try_reserve(7, false)
            .expect("fixture must fit ordinary subcap");
        let message = AdmittedNetworkMessage::new(
            NetworkMessage::Broadcast(Broadcast {
                data: Dummy,
                priority: Priority::High,
            }),
            lease,
        );
        assert_eq!(budget.retained().total, 7);
        drop(message);
        assert_eq!(budget.retained(), NetworkActorRetainedBytes::default());
    }
    #[test]
    fn outbound_actor_admission_enforces_plaintext_cap_and_stream_charge_exactly() {
        let (mut handle, _safety_rx, _progress_rx, mut high_rx, _low_rx) =
            handle_with_network_receivers::<Dummy>();
        let message = NetworkMessage::Broadcast(Broadcast {
            data: Dummy,
            priority: Priority::High,
        });
        let plaintext_frame_bytes =
            outbound_actor_message_wire_bytes(&message, &handle.self_id, handle.relay_ttl)
                .expect("count exact actor fixture");
        let stream_wire_bytes = crate::frame_queue_charge(plaintext_frame_bytes)
            .expect("small actor fixture must have a stream charge");
        handle.topic_frame_caps.other = plaintext_frame_bytes;
        handle.network_actor_byte_budget =
            NetworkActorByteBudget::new(stream_wire_bytes, 0).expect("exact actor fixture budget");
        handle.broadcast(Broadcast {
            data: Dummy,
            priority: Priority::High,
        });
        assert_eq!(
            handle.network_actor_byte_budget.retained().total,
            stream_wire_bytes,
            "actor ownership must use the downstream encrypted stream charge"
        );
        let admitted = high_rx
            .try_recv()
            .expect("exact topic cap and byte budget must admit the message");
        drop(admitted);
        assert_eq!(
            handle.network_actor_byte_budget.retained(),
            NetworkActorRetainedBytes::default()
        );
        handle.topic_frame_caps.other = plaintext_frame_bytes - 1;
        handle.broadcast(Broadcast {
            data: Dummy,
            priority: Priority::High,
        });
        assert!(matches!(
            high_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(
            handle.network_actor_byte_budget.retained(),
            NetworkActorRetainedBytes::default(),
            "rejected over-cap traffic must not retain actor ownership"
        );
    }
    struct ControlUpdateReceivers {
        topology: ControlUpdateReceiver<message::UpdateTopology>,
        peers: ControlUpdateReceiver<message::UpdatePeers>,
        validator_dial_roster: ControlUpdateReceiver<ValidatorDialControlUpdate>,
        peer_capabilities: ControlUpdateReceiver<message::UpdatePeerCapabilities>,
        trusted_peers: ControlUpdateReceiver<message::UpdateTrustedPeers>,
        acl: ControlUpdateReceiver<message::UpdateAcl>,
        handshake: mpsc::Receiver<message::UpdateHandshake>,
    }
    fn handle_with_control_update_receivers() -> (
        NetworkBaseHandle<Dummy, ChaCha20Poly1305>,
        ControlUpdateReceivers,
    ) {
        let (subscribe_tx, _subscribe_rx) = mpsc::channel::<Subscriber<Dummy>>(1);
        let (update_topology_tx, update_topology_rx) = control_update_channel();
        let (update_peers_tx, update_peers_rx) = control_update_channel();
        let (update_validator_dial_roster_tx, update_validator_dial_roster_rx) =
            control_update_channel();
        let (update_peer_capabilities_tx, update_peer_capabilities_rx) = control_update_channel();
        let (update_trusted_tx, update_trusted_rx) = control_update_channel();
        let (update_acl_tx, update_acl_rx) = control_update_channel();
        let (update_handshake_tx, update_handshake_rx) =
            mpsc::channel(HANDSHAKE_UPDATE_CHANNEL_CAPACITY);
        let (network_message_high_sender, _network_message_high_rx) =
            net_channel::channel_with_capacity(1);
        let (network_message_safety_sender, _network_message_safety_rx) =
            net_channel::channel_with_capacity(1);
        let (network_message_progress_sender, _network_message_progress_rx) =
            net_channel::channel_with_capacity(1);
        let (network_message_low_sender, _network_message_low_rx) =
            net_channel::channel_with_capacity(1);
        let (_online_peers_tx, online_peers_receiver) = watch::channel(HashSet::new());
        let (_online_peer_capabilities_tx, online_peer_capabilities_receiver) =
            watch::channel(HashMap::new());
        (
            NetworkBaseHandle {
                subscribe_to_peers_messages_sender: subscribe_tx,
                online_peers_receiver,
                online_peer_capabilities_receiver,
                reliable_broadcast_topology: Arc::new(
                    Mutex::new(ReliableProgressTopology::empty()),
                ),
                reliable_direct_topology: Arc::new(Mutex::new(ReliableProgressTopology::empty())),
                configured_peer_ids: Arc::new(Mutex::new(ConfiguredPeerState::default())),
                reply_route_owner: Arc::new(()),
                reply_route_source_capacity: 8,
                update_topology_sender: update_topology_tx,
                update_peers_sender: update_peers_tx,
                update_validator_dial_roster_sender: update_validator_dial_roster_tx,
                update_peer_capabilities_sender: update_peer_capabilities_tx,
                update_trusted_peers_sender: update_trusted_tx,
                update_acl_sender: update_acl_tx,
                update_handshake_sender: update_handshake_tx,
                network_message_high_sender,
                network_message_safety_sender,
                network_message_progress_sender,
                network_message_low_sender,
                network_message_high_deferred_permits: Arc::new(Semaphore::new(1)),
                network_message_safety_deferred_permits: Arc::new(Semaphore::new(1)),
                network_message_progress_deferred_permits: Arc::new(Semaphore::new(1)),
                network_actor_byte_budget: test_network_actor_byte_budget(),
                network_actor_progress_budget: test_network_actor_progress_budget(),
                network_actor_low_byte_budget: test_network_actor_byte_budget(),
                self_id: random_node_peer_id(),
                relay_ttl: 0,
                topic_frame_caps: test_topic_frame_caps(),
                subscriber_queue_cap: core::num::NonZeroUsize::new(1).expect("nonzero"),
                _encryptor: core::marker::PhantomData,
            },
            ControlUpdateReceivers {
                topology: update_topology_rx,
                peers: update_peers_rx,
                validator_dial_roster: update_validator_dial_roster_rx,
                peer_capabilities: update_peer_capabilities_rx,
                trusted_peers: update_trusted_rx,
                acl: update_acl_rx,
                handshake: update_handshake_rx,
            },
        )
    }
    fn closed_handle() -> NetworkBaseHandle<Dummy, ChaCha20Poly1305> {
        let (handle, receivers) = handle_with_control_update_receivers();
        drop(receivers);
        handle
    }
    pub(super) fn handle_with_network_receivers<T: Pload>() -> (
        NetworkBaseHandle<T, ChaCha20Poly1305>,
        net_channel::Receiver<AdmittedNetworkMessage<T>>,
        net_channel::Receiver<AdmittedNetworkMessage<T>>,
        net_channel::Receiver<AdmittedNetworkMessage<T>>,
        net_channel::Receiver<AdmittedNetworkMessage<T>>,
    ) {
        let (subscribe_tx, _subscribe_rx) = mpsc::channel::<Subscriber<T>>(1);
        let (update_topology_tx, update_topology_rx) = control_update_channel();
        let (update_peers_tx, update_peers_rx) = control_update_channel();
        let (update_validator_dial_roster_tx, update_validator_dial_roster_rx) =
            control_update_channel();
        let (update_peer_capabilities_tx, update_peer_capabilities_rx) = control_update_channel();
        let (update_trusted_tx, update_trusted_rx) = control_update_channel();
        let (update_acl_tx, update_acl_rx) = control_update_channel();
        let (update_handshake_tx, update_handshake_rx) =
            mpsc::channel(HANDSHAKE_UPDATE_CHANNEL_CAPACITY);
        let (network_message_high_sender, network_message_high_rx) =
            net_channel::channel_with_capacity(1);
        let (network_message_safety_sender, network_message_safety_rx) =
            net_channel::channel_with_capacity(1);
        let (network_message_progress_sender, network_message_progress_rx) =
            net_channel::channel_with_capacity(1);
        let (network_message_low_sender, network_message_low_rx) =
            net_channel::channel_with_capacity(1);
        let (_online_peers_tx, online_peers_receiver) = watch::channel(HashSet::new());
        let (_online_peer_capabilities_tx, online_peer_capabilities_receiver) =
            watch::channel(HashMap::new());
        drop(update_topology_rx);
        drop(update_peers_rx);
        drop(update_validator_dial_roster_rx);
        drop(update_peer_capabilities_rx);
        drop(update_trusted_rx);
        drop(update_acl_rx);
        drop(update_handshake_rx);
        let handle = NetworkBaseHandle {
            subscribe_to_peers_messages_sender: subscribe_tx,
            online_peers_receiver,
            online_peer_capabilities_receiver,
            reliable_broadcast_topology: Arc::new(Mutex::new(ReliableProgressTopology::empty())),
            reliable_direct_topology: Arc::new(Mutex::new(ReliableProgressTopology::empty())),
            configured_peer_ids: Arc::new(Mutex::new(ConfiguredPeerState::default())),
            reply_route_owner: Arc::new(()),
            reply_route_source_capacity: 8,
            update_topology_sender: update_topology_tx,
            update_peers_sender: update_peers_tx,
            update_validator_dial_roster_sender: update_validator_dial_roster_tx,
            update_peer_capabilities_sender: update_peer_capabilities_tx,
            update_trusted_peers_sender: update_trusted_tx,
            update_acl_sender: update_acl_tx,
            update_handshake_sender: update_handshake_tx,
            network_message_high_sender,
            network_message_safety_sender,
            network_message_progress_sender,
            network_message_low_sender,
            network_message_high_deferred_permits: Arc::new(Semaphore::new(1)),
            network_message_safety_deferred_permits: Arc::new(Semaphore::new(1)),
            network_message_progress_deferred_permits: Arc::new(Semaphore::new(1)),
            network_actor_byte_budget: test_network_actor_byte_budget(),
            network_actor_progress_budget: test_network_actor_progress_budget(),
            network_actor_low_byte_budget: test_network_actor_byte_budget(),
            self_id: random_node_peer_id(),
            relay_ttl: 0,
            topic_frame_caps: test_topic_frame_caps(),
            subscriber_queue_cap: core::num::NonZeroUsize::new(1).expect("nonzero"),
            _encryptor: core::marker::PhantomData,
        };
        (
            handle,
            network_message_safety_rx,
            network_message_progress_rx,
            network_message_high_rx,
            network_message_low_rx,
        )
    }
    fn accept_direct_targets<T: Pload>(
        handle: &NetworkBaseHandle<T, ChaCha20Poly1305>,
        targets: HashSet<PeerId>,
    ) {
        let _ = handle
            .reliable_direct_topology
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reconcile(&targets, &handle.self_id);
    }
    fn handle_with_subscriber_receiver() -> (
        NetworkBaseHandle<Dummy, ChaCha20Poly1305>,
        mpsc::Receiver<Subscriber<Dummy>>,
    ) {
        let (subscribe_tx, subscribe_rx) = mpsc::channel::<Subscriber<Dummy>>(1);
        let (update_topology_tx, update_topology_rx) = control_update_channel();
        let (update_peers_tx, update_peers_rx) = control_update_channel();
        let (update_validator_dial_roster_tx, update_validator_dial_roster_rx) =
            control_update_channel();
        let (update_peer_capabilities_tx, update_peer_capabilities_rx) = control_update_channel();
        let (update_trusted_tx, update_trusted_rx) = control_update_channel();
        let (update_acl_tx, update_acl_rx) = control_update_channel();
        let (update_handshake_tx, update_handshake_rx) =
            mpsc::channel(HANDSHAKE_UPDATE_CHANNEL_CAPACITY);
        let (network_message_high_sender, _network_message_high_rx) =
            net_channel::channel_with_capacity(1);
        let (network_message_low_sender, _network_message_low_rx) =
            net_channel::channel_with_capacity(1);
        let (_online_peers_tx, online_peers_receiver) = watch::channel(HashSet::new());
        let (_online_peer_capabilities_tx, online_peer_capabilities_receiver) =
            watch::channel(HashMap::new());
        drop(update_topology_rx);
        drop(update_peers_rx);
        drop(update_validator_dial_roster_rx);
        drop(update_peer_capabilities_rx);
        drop(update_trusted_rx);
        drop(update_acl_rx);
        drop(update_handshake_rx);
        (
            NetworkBaseHandle {
                subscribe_to_peers_messages_sender: subscribe_tx,
                online_peers_receiver,
                online_peer_capabilities_receiver,
                reliable_broadcast_topology: Arc::new(
                    Mutex::new(ReliableProgressTopology::empty()),
                ),
                reliable_direct_topology: Arc::new(Mutex::new(ReliableProgressTopology::empty())),
                configured_peer_ids: Arc::new(Mutex::new(ConfiguredPeerState::default())),
                reply_route_owner: Arc::new(()),
                reply_route_source_capacity: 8,
                update_topology_sender: update_topology_tx,
                update_peers_sender: update_peers_tx,
                update_validator_dial_roster_sender: update_validator_dial_roster_tx,
                update_peer_capabilities_sender: update_peer_capabilities_tx,
                update_trusted_peers_sender: update_trusted_tx,
                update_acl_sender: update_acl_tx,
                update_handshake_sender: update_handshake_tx,
                network_message_high_sender,
                network_message_safety_sender: net_channel::channel_with_capacity(1).0,
                network_message_progress_sender: net_channel::channel_with_capacity(1).0,
                network_message_low_sender,
                network_message_high_deferred_permits: Arc::new(Semaphore::new(1)),
                network_message_safety_deferred_permits: Arc::new(Semaphore::new(1)),
                network_message_progress_deferred_permits: Arc::new(Semaphore::new(1)),
                network_actor_byte_budget: test_network_actor_byte_budget(),
                network_actor_progress_budget: test_network_actor_progress_budget(),
                network_actor_low_byte_budget: test_network_actor_byte_budget(),
                self_id: random_node_peer_id(),
                relay_ttl: 0,
                topic_frame_caps: test_topic_frame_caps(),
                subscriber_queue_cap: core::num::NonZeroUsize::new(1).expect("nonzero"),
                _encryptor: core::marker::PhantomData,
            },
            subscribe_rx,
        )
    }
    #[tokio::test(flavor = "current_thread")]
    async fn control_update_channel_keeps_newest_unconsumed_value() {
        let (tx, mut rx) = control_update_channel();
        for value in 0..=65 {
            send_control_update(&tx, "test", value);
        }
        assert_eq!(receive_control_update(&mut rx).await, Some(65));
        assert!(
            !rx.has_changed()
                .expect("control update sender should remain open")
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn control_update_receive_is_cancellation_safe_and_reusable() {
        let (tx, mut rx) = control_update_channel();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), receive_control_update(&mut rx),)
                .await
                .is_err(),
            "an untouched control slot must remain pending"
        );
        send_control_update(&tx, "test", 1);
        assert_eq!(receive_control_update(&mut rx).await, Some(1));
        send_control_update(&tx, "test", 2);
        assert_eq!(receive_control_update(&mut rx).await, Some(2));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), receive_control_update(&mut rx),)
                .await
                .is_err(),
            "an applied snapshot must not be delivered twice"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn control_update_receive_preserves_final_value_across_close() {
        let (empty_tx, mut empty_rx) = control_update_channel::<u8>();
        drop(empty_tx);
        assert_eq!(receive_control_update(&mut empty_rx).await, None);
        let (tx, mut rx) = control_update_channel();
        send_control_update(&tx, "test", 7_u8);
        drop(tx);
        assert_eq!(receive_control_update(&mut rx).await, Some(7));
        assert_eq!(receive_control_update(&mut rx).await, None);
    }
    #[test]
    fn control_update_channel_releases_superseded_snapshots() {
        #[derive(Clone)]
        struct DropProbe(Arc<AtomicUsize>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = control_update_channel();
        for _ in 0..1_024 {
            send_control_update(&tx, "test", DropProbe(Arc::clone(&dropped)));
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 1_023);
        drop(tx);
        assert_eq!(dropped.load(Ordering::SeqCst), 1_023);
        drop(rx);
        assert_eq!(dropped.load(Ordering::SeqCst), 1_024);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn publisher_does_not_wait_for_receiver_payload_clone() {
        struct CloneGate(bool);
        struct SlowClone {
            marker: u8,
            clone_started: tokio::sync::mpsc::UnboundedSender<()>,
            gate: Arc<(std::sync::Mutex<CloneGate>, std::sync::Condvar)>,
        }
        impl Clone for SlowClone {
            fn clone(&self) -> Self {
                let _ = self.clone_started.send(());
                let (lock, ready) = &*self.gate;
                let mut released = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while !released.0 {
                    released = ready
                        .wait(released)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                Self {
                    marker: self.marker,
                    clone_started: self.clone_started.clone(),
                    gate: Arc::clone(&self.gate),
                }
            }
        }
        let (clone_started_tx, mut clone_started_rx) = tokio::sync::mpsc::unbounded_channel();
        let gate = Arc::new((
            std::sync::Mutex::new(CloneGate(false)),
            std::sync::Condvar::new(),
        ));
        let (tx, mut rx) = control_update_channel();
        send_control_update(
            &tx,
            "test",
            SlowClone {
                marker: 1,
                clone_started: clone_started_tx.clone(),
                gate: Arc::clone(&gate),
            },
        );
        let receive_task = tokio::spawn(async move {
            let first = receive_control_update(&mut rx).await.expect("first update");
            (first, rx)
        });
        clone_started_rx
            .recv()
            .await
            .expect("receiver must begin cloning");
        let send_tx = tx.clone();
        let send_gate = Arc::clone(&gate);
        let (send_done_tx, mut send_done_rx) = tokio::sync::oneshot::channel();
        let send_task = tokio::spawn(async move {
            send_control_update(
                &send_tx,
                "test",
                SlowClone {
                    marker: 2,
                    clone_started: clone_started_tx,
                    gate: send_gate,
                },
            );
            let _ = send_done_tx.send(());
        });
        let send_completed = tokio::time::timeout(Duration::from_secs(1), &mut send_done_rx)
            .await
            .is_ok();
        let (lock, ready) = &*gate;
        lock.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0 = true;
        ready.notify_all();
        send_task.await.expect("sender task must not panic");
        let (first, mut rx) = receive_task.await.expect("receiver task must not panic");
        assert!(
            send_completed,
            "publishing a newer snapshot blocked on a full payload clone"
        );
        assert_eq!(first.marker, 1);
        assert_eq!(
            receive_control_update(&mut rx)
                .await
                .expect("second update")
                .marker,
            2
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_control_update_writers_publish_the_latest_completed_write() {
        let (tx, mut rx) = control_update_channel();
        let mut writers = Vec::new();
        for writer in 0..8_u32 {
            let tx = tx.clone();
            writers.push(tokio::spawn(async move {
                for sequence in 0..256_u32 {
                    send_control_update(&tx, "test", (writer, sequence));
                    tokio::task::yield_now().await;
                }
            }));
        }
        for writer in writers {
            writer.await.expect("control update writer must not panic");
        }
        let (writer, sequence) =
            tokio::time::timeout(Duration::from_secs(1), receive_control_update(&mut rx))
                .await
                .expect("a concurrent write must reach the retained slot")
                .expect("control update sender remains open");
        assert!(writer < 8);
        assert_eq!(
            sequence, 255,
            "the globally last completed writer must have published its final sequence"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn update_topology_overflow_keeps_newest_snapshot() {
        let mut handle = closed_handle();
        let (update_topology_tx, mut update_topology_rx) = control_update_channel();
        handle.update_topology_sender = update_topology_tx;
        for _ in 0..64 {
            handle.update_topology(message::UpdateTopology(HashSet::new()));
        }
        let superseded_peer = random_node_peer_id();
        handle.update_topology(message::UpdateTopology(HashSet::from([superseded_peer])));
        let newest_peer = random_node_peer_id();
        let expected = HashSet::from([newest_peer]);
        handle.update_topology(message::UpdateTopology(expected.clone()));
        let message::UpdateTopology(actual) = receive_control_update(&mut update_topology_rx)
            .await
            .expect("newest topology update should remain pending");
        assert_eq!(actual, expected);
        assert!(
            !update_topology_rx
                .has_changed()
                .expect("topology sender should remain open")
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn validator_membership_and_dial_roster_share_one_retained_snapshot() {
        let (handle, mut receivers) = handle_with_control_update_receivers();
        let self_id = handle.self_id.clone();
        let peer_id = random_node_peer_id();
        let topology = HashSet::from([self_id.clone(), peer_id.clone()]);
        let validator_dial_roster = topology.clone();
        handle.update_validator_topology(message::UpdateValidatorTopology {
            topology: topology.clone(),
            validator_dial_roster: validator_dial_roster.clone(),
        });
        let ValidatorDialControlUpdate::Topology(message::UpdateValidatorTopology {
            topology: actual_topology,
            validator_dial_roster: actual_roster,
        }) = receive_control_update(&mut receivers.validator_dial_roster)
            .await
            .expect("coupled validator topology update")
        else {
            panic!("expected coupled validator topology update");
        };
        assert_eq!(actual_topology, topology);
        assert_eq!(actual_roster, validator_dial_roster);
        assert!(
            !receivers
                .topology
                .has_changed()
                .expect("ordinary topology channel remains open"),
            "membership must not race ownership through an independent topology snapshot"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn snapshot_control_updates_keep_newest_category_value() {
        let (handle, mut receivers) = handle_with_control_update_receivers();
        let newest_handle = handle.clone();
        let stale_peer = random_node_peer_id();
        let newest_peer = random_node_peer_id();
        let stale_addr = socket_addr!(127.0.0.1:11_001);
        let newest_addr = socket_addr!(127.0.0.1:11_002);
        handle.update_topology(message::UpdateTopology(HashSet::from([stale_peer.clone()])));
        handle.update_peers_addresses(message::UpdatePeers(vec![(stale_peer.clone(), stale_addr)]));
        handle.update_validator_dial_roster(message::UpdateValidatorDialRoster(HashSet::from([
            stale_peer.clone(),
        ])));
        handle.update_peer_capabilities(message::UpdatePeerCapabilities(vec![(
            stale_peer.clone(),
            message::PeerTransportCapabilities {
                scion_supported: false,
            },
        )]));
        handle.update_trusted_peers(message::UpdateTrustedPeers(HashSet::from([
            stale_peer.clone()
        ])));
        handle.update_acl(message::UpdateAcl {
            allowlist_only: false,
            allow_keys: vec![stale_peer.public_key().clone()],
            deny_keys: Vec::new(),
            allow_cidrs: vec!["10.0.0.0/8".to_owned()],
            deny_cidrs: Vec::new(),
        });
        newest_handle.update_topology(message::UpdateTopology(HashSet::from(
            [newest_peer.clone()],
        )));
        newest_handle.update_peers_addresses(message::UpdatePeers(vec![(
            newest_peer.clone(),
            newest_addr.clone(),
        )]));
        newest_handle.update_validator_dial_roster(message::UpdateValidatorDialRoster(
            HashSet::from([newest_peer.clone()]),
        ));
        newest_handle.update_peer_capabilities(message::UpdatePeerCapabilities(vec![(
            newest_peer.clone(),
            message::PeerTransportCapabilities {
                scion_supported: true,
            },
        )]));
        newest_handle.update_trusted_peers(message::UpdateTrustedPeers(HashSet::from([
            newest_peer.clone(),
        ])));
        newest_handle.update_acl(message::UpdateAcl {
            allowlist_only: true,
            allow_keys: vec![newest_peer.public_key().clone()],
            deny_keys: Vec::new(),
            allow_cidrs: vec!["192.0.2.0/24".to_owned()],
            deny_cidrs: vec!["198.51.100.0/24".to_owned()],
        });
        assert!(receivers.topology.has_changed().expect("topology open"));
        assert!(receivers.peers.has_changed().expect("peers open"));
        assert!(
            receivers
                .validator_dial_roster
                .has_changed()
                .expect("validator dial roster open")
        );
        assert!(
            receivers
                .peer_capabilities
                .has_changed()
                .expect("peer capabilities open")
        );
        assert!(
            receivers
                .trusted_peers
                .has_changed()
                .expect("trusted peers open")
        );
        assert!(receivers.acl.has_changed().expect("ACL open"));
        let message::UpdateTopology(topology) = receive_control_update(&mut receivers.topology)
            .await
            .expect("topology update");
        assert_eq!(topology, HashSet::from([newest_peer.clone()]));
        let message::UpdatePeers(peers) = receive_control_update(&mut receivers.peers)
            .await
            .expect("peer-address update");
        assert_eq!(peers, vec![(newest_peer.clone(), newest_addr)]);
        let ValidatorDialControlUpdate::Roster(message::UpdateValidatorDialRoster(
            validator_dial_roster,
        )) = receive_control_update(&mut receivers.validator_dial_roster)
            .await
            .expect("validator dial roster update")
        else {
            panic!("expected standalone validator dial roster update");
        };
        assert_eq!(validator_dial_roster, HashSet::from([newest_peer.clone()]));
        let message::UpdatePeerCapabilities(capabilities) =
            receive_control_update(&mut receivers.peer_capabilities)
                .await
                .expect("peer-capability update");
        assert_eq!(
            capabilities,
            vec![(
                newest_peer.clone(),
                message::PeerTransportCapabilities {
                    scion_supported: true,
                },
            )]
        );
        let message::UpdateTrustedPeers(trusted) =
            receive_control_update(&mut receivers.trusted_peers)
                .await
                .expect("trusted-peer update");
        assert_eq!(trusted, HashSet::from([newest_peer.clone()]));
        let acl = receive_control_update(&mut receivers.acl)
            .await
            .expect("ACL update");
        assert!(acl.allowlist_only);
        assert_eq!(acl.allow_keys, vec![newest_peer.public_key().clone()]);
        assert_eq!(acl.allow_cidrs, vec!["192.0.2.0/24"]);
        assert_eq!(acl.deny_cidrs, vec!["198.51.100.0/24"]);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_update_returns_the_exact_actor_result() {
        let (handle, mut receivers) = handle_with_control_update_receivers();
        let accepted = ActualSoranetHandshake {
            kem_id: 11,
            ..Default::default()
        };
        let accepted_task = tokio::spawn({
            let handle = handle.clone();
            async move { handle.update_soranet_handshake(accepted).await }
        });
        let accepted_request = receivers
            .handshake
            .recv()
            .await
            .expect("accepted handshake request");
        assert_eq!(accepted_request.handshake.kem_id, 11);
        accepted_request
            .respond_to
            .send(Ok(()))
            .expect("accepted requester should remain active");
        accepted_task
            .await
            .expect("accepted update task")
            .expect("accepted actor result");

        let rejected = ActualSoranetHandshake {
            kem_id: 12,
            ..Default::default()
        };
        let rejected_task = tokio::spawn({
            let handle = handle.clone();
            async move { handle.update_soranet_handshake(rejected).await }
        });
        let rejected_request = receivers
            .handshake
            .recv()
            .await
            .expect("rejected handshake request");
        assert_eq!(rejected_request.handshake.kem_id, 12);
        rejected_request
            .respond_to
            .send(Err(Error::HandshakeSoranet("restart required".to_owned())))
            .expect("rejected requester should remain active");
        let error = rejected_task
            .await
            .expect("rejected update task")
            .expect_err("actor rejection must reach the caller");
        assert!(matches!(error, Error::HandshakeSoranet(message) if message == "restart required"));
    }
    #[test]
    fn subscriber_registration_queue_is_bounded() {
        let (handle, _subscribe_rx) = handle_with_subscriber_receiver();
        let (first_tx, _first_rx) = mpsc::channel(1);
        let (second_tx, _second_rx) = mpsc::channel(1);
        assert!(handle.subscribe_to_peers_messages(first_tx).is_ok());
        assert!(handle.subscribe_to_peers_messages(second_tx).is_err());
    }
    #[test]
    fn high_actor_drain_limit_scales_with_queue_pressure() {
        assert_eq!(high_actor_drain_limit(1), NETWORK_HIGH_ACTOR_DRAIN_BASE);
        assert_eq!(
            high_actor_drain_limit(65),
            NETWORK_HIGH_ACTOR_DRAIN_PRESSURED
        );
        assert_eq!(
            high_actor_drain_limit(257),
            NETWORK_HIGH_ACTOR_DRAIN_SATURATED
        );
    }
    #[test]
    fn saturated_high_actor_drain_yields_to_service_and_shutdown() {
        assert!(!should_stop_high_actor_drain(
            1,
            NETWORK_HIGH_ACTOR_DRAIN_SATURATED,
            false,
            false,
        ));
        assert!(should_stop_high_actor_drain(
            1,
            NETWORK_HIGH_ACTOR_DRAIN_SATURATED,
            true,
            false,
        ));
        assert!(should_stop_high_actor_drain(
            1,
            NETWORK_HIGH_ACTOR_DRAIN_SATURATED,
            false,
            true,
        ));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn high_priority_post_waits_for_actor_queue_capacity() {
        let (handle, _safety_rx, _progress_rx, mut high_rx, _low_rx) =
            handle_with_network_receivers::<Dummy>();
        let peer_id = random_node_peer_id();
        handle.post(Post {
            data: Dummy,
            peer_id: peer_id.clone(),
            priority: Priority::High,
        });
        handle.post(Post {
            data: Dummy,
            peer_id: peer_id.clone(),
            priority: Priority::High,
        });
        let first = high_rx
            .recv()
            .await
            .expect("first post should be queued")
            .into_inner();
        assert!(matches!(first, NetworkMessage::Post(_)));
        let second = tokio::time::timeout(Duration::from_secs(1), high_rx.recv())
            .await
            .expect("deferred high-priority post should enqueue after capacity opens")
            .expect("deferred high-priority post should be present")
            .into_inner();
        match second {
            NetworkMessage::Post(post) => {
                assert_eq!(post.peer_id, peer_id);
                assert_eq!(post.priority, Priority::High);
            }
            NetworkMessage::Broadcast(_) => panic!("expected deferred post"),
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn high_priority_actor_overflow_waiters_are_bounded() {
        let (handle, _safety_rx, _progress_rx, mut high_rx, _low_rx) =
            handle_with_network_receivers::<Dummy>();
        let peer_id = random_node_peer_id();
        let post = || Post {
            data: Dummy,
            peer_id: peer_id.clone(),
            priority: Priority::High,
        };
        handle.post(post());
        handle.post(post());
        handle.post(post());
        assert_eq!(
            handle
                .network_message_high_deferred_permits
                .available_permits(),
            0,
            "only one overflow waiter may retain a message for a capacity-one actor queue"
        );
        assert!(matches!(
            high_rx.recv().await.map(AdmittedNetworkMessage::into_inner),
            Some(NetworkMessage::Post(_))
        ));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), high_rx.recv())
                .await
                .map(|message| message.map(AdmittedNetworkMessage::into_inner)),
            Ok(Some(NetworkMessage::Post(_)))
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), high_rx.recv())
                .await
                .is_err(),
            "messages beyond the bounded actor queue and overflow allowance must be dropped"
        );
        tokio::task::yield_now().await;
        assert_eq!(
            handle
                .network_message_high_deferred_permits
                .available_permits(),
            1,
            "the overflow permit must be released after delivery"
        );
    }
    #[test]
    fn outbound_actor_sizing_does_not_clone_large_payloads() {
        let origin = random_node_peer_id();
        let target = random_node_peer_id();
        let payload = CloneCountingPayload(vec![0xA5; 4 * 1024 * 1024]);
        let payload_len = ncore::encoded_payload_len(&payload)
            .expect("large test payload must have a representable encoded length");
        let message = NetworkMessage::Post(Post {
            data: payload,
            peer_id: target.clone(),
            priority: Priority::High,
        });
        let clones_before = ACTOR_SIZE_CLONES.load(Ordering::Relaxed);
        let measured = outbound_actor_message_wire_bytes(&message, &origin, DEFAULT_RELAY_TTL)
            .expect("large actor payload must have a representable wire length");
        assert_eq!(ACTOR_SIZE_CLONES.load(Ordering::Relaxed), clones_before);
        assert_eq!(
            measured,
            data_frame_wire_len_from_payload_len::<CloneCountingPayload>(
                &origin,
                Some(&target),
                payload_len,
            )
        );
    }
    #[test]
    fn outbound_actor_sizing_ignores_understated_exact_length_hints() {
        let origin = random_node_peer_id();
        let target = random_node_peer_id();
        let message = NetworkMessage::Post(Post {
            data: BadLengthHintPayload,
            peer_id: target.clone(),
            priority: Priority::High,
        });
        let measured = outbound_actor_message_wire_bytes(&message, &origin, DEFAULT_RELAY_TTL)
            .expect("a bad optimization hint must not break fallible wire counting");
        assert_eq!(
            measured,
            data_frame_wire_len_from_payload_len::<BadLengthHintPayload>(&origin, Some(&target), 4,)
        );
    }
    #[test]
    fn outbound_actor_sizing_propagates_serializer_failure_without_panicking() {
        let origin = random_node_peer_id();
        let target = random_node_peer_id();
        let message = NetworkMessage::Post(Post {
            data: FailingSerializerPayload,
            peer_id: target,
            priority: Priority::High,
        });
        assert!(outbound_actor_message_wire_bytes(&message, &origin, DEFAULT_RELAY_TTL).is_err());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn deferred_actor_message_retains_and_releases_exact_byte_ownership() {
        let (mut handle, _safety_rx, _progress_rx, mut high_rx, _low_rx) =
            handle_with_network_receivers::<Dummy>();
        let peer_id = random_node_peer_id();
        let fixture = NetworkMessage::Post(Post {
            data: Dummy,
            peer_id: peer_id.clone(),
            priority: Priority::High,
        });
        let plaintext_frame_bytes =
            outbound_actor_message_wire_bytes(&fixture, &handle.self_id, handle.relay_ttl)
                .expect("count exact deferred actor fixture");
        let stream_wire_bytes = crate::frame_queue_charge(plaintext_frame_bytes)
            .expect("small deferred actor fixture must have a stream charge");
        let two_message_bytes = stream_wire_bytes
            .checked_mul(2)
            .expect("small two-message actor budget");
        handle.network_actor_byte_budget = NetworkActorByteBudget::new(two_message_bytes, 0)
            .expect("exact two-message actor budget");
        let post = || Post {
            data: Dummy,
            peer_id: peer_id.clone(),
            priority: Priority::High,
        };
        handle.post(post());
        handle.post(post());
        handle.post(post());
        assert_eq!(
            handle.network_actor_byte_budget.retained().total,
            two_message_bytes,
            "one queued item and one waiter must retain exactly two charges; the third must fail admission"
        );
        let first = high_rx.recv().await.expect("first item must be queued");
        drop(first);
        let second = tokio::time::timeout(Duration::from_secs(1), high_rx.recv())
            .await
            .expect("deferred waiter must make progress after queue capacity opens")
            .expect("deferred item must enter the actor channel");
        assert_eq!(
            handle.network_actor_byte_budget.retained().total,
            stream_wire_bytes,
            "handoff must release only the consumed first item"
        );
        drop(second);
        assert_eq!(
            handle.network_actor_byte_budget.retained(),
            NetworkActorRetainedBytes::default()
        );
        let (
            mut closed_handle,
            _closed_safety_rx,
            _closed_progress_rx,
            closed_high_rx,
            _closed_low_rx,
        ) = handle_with_network_receivers::<Dummy>();
        let closed_fixture = NetworkMessage::Post(post());
        let closed_plaintext_bytes = outbound_actor_message_wire_bytes(
            &closed_fixture,
            &closed_handle.self_id,
            closed_handle.relay_ttl,
        )
        .expect("count exact closed actor fixture");
        let closed_stream_bytes = crate::frame_queue_charge(closed_plaintext_bytes)
            .expect("small closed actor fixture must have a stream charge");
        closed_handle.network_actor_byte_budget =
            NetworkActorByteBudget::new(closed_stream_bytes, 0)
                .expect("single-message closed-channel budget");
        drop(closed_high_rx);
        closed_handle.post(post());
        assert_eq!(
            closed_handle.network_actor_byte_budget.retained(),
            NetworkActorRetainedBytes::default(),
            "a closed actor channel must release the reservation exactly once"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn high_priority_broadcast_waits_for_actor_queue_capacity() {
        let (handle, _safety_rx, _progress_rx, mut high_rx, _low_rx) =
            handle_with_network_receivers::<Dummy>();
        handle.broadcast(Broadcast {
            data: Dummy,
            priority: Priority::High,
        });
        handle.broadcast(Broadcast {
            data: Dummy,
            priority: Priority::High,
        });
        let first = high_rx
            .recv()
            .await
            .expect("first broadcast should be queued")
            .into_inner();
        assert!(matches!(first, NetworkMessage::Broadcast(_)));
        let second = tokio::time::timeout(Duration::from_secs(1), high_rx.recv())
            .await
            .expect("deferred high-priority broadcast should enqueue after capacity opens")
            .expect("deferred high-priority broadcast should be present")
            .into_inner();
        match second {
            NetworkMessage::Broadcast(broadcast) => {
                assert_eq!(broadcast.priority, Priority::High);
            }
            NetworkMessage::Post(_) => panic!("expected deferred broadcast"),
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn recoverable_best_effort_post_reports_queue_cap_and_closed_without_losing_source() {
        let (handle, _safety_rx, _progress_rx, mut high_rx, _low_rx) =
            handle_with_network_receivers::<RoutedActorDummy>();
        let target = random_node_peer_id();
        let post = || Post {
            data: RoutedActorDummy::Control,
            peer_id: target.clone(),
            priority: Priority::High,
        };
        let reliable = Post {
            data: RoutedActorDummy::Lane,
            peer_id: target.clone(),
            priority: Priority::Low,
        };
        match handle.post_best_effort_recoverable(reliable) {
            Err(NetworkPostAdmissionError::Rejected {
                message,
                reason: NetworkActorAdmissionRejection::ReliableProgressRequiresRecoverable,
            }) => {
                assert_eq!(message.data, RoutedActorDummy::Lane);
                assert_eq!(message.peer_id, target);
                assert_eq!(message.priority, Priority::Low);
            }
            other => panic!("reliable progress must reject best-effort admission: {other:?}"),
        }
        handle
            .post_best_effort_recoverable(post())
            .expect("the actor queue owns the first control post");
        handle
            .post_best_effort_recoverable(post())
            .expect("the bounded high-priority deferral owns the second control post");
        let returned = match handle.post_best_effort_recoverable(post()) {
            Err(NetworkPostAdmissionError::Backpressured { message }) => message,
            other => {
                panic!("saturated actor ownership must return the exact third post: {other:?}")
            }
        };
        assert_eq!(returned.data, RoutedActorDummy::Control);
        assert_eq!(returned.peer_id, target);
        assert_eq!(returned.priority, Priority::High);
        let first = high_rx
            .recv()
            .await
            .expect("first accepted control post remains actor-owned")
            .into_inner();
        assert!(matches!(first, NetworkMessage::Post(_)));
        let second = high_rx
            .recv()
            .await
            .expect("deferred control post transfers after actor capacity opens")
            .into_inner();
        assert!(matches!(second, NetworkMessage::Post(_)));
        let (mut capped, _safety_rx, _progress_rx, _high_rx, _low_rx) =
            handle_with_network_receivers::<RoutedActorDummy>();
        let capped_post = post();
        let plaintext_bytes = outbound_actor_message_wire_bytes(
            &NetworkMessage::Post(capped_post.clone()),
            &capped.self_id,
            capped.relay_ttl,
        )
        .expect("count exact control-post frame");
        capped.topic_frame_caps.control = plaintext_bytes - 1;
        match capped.post_best_effort_recoverable(capped_post) {
            Err(NetworkPostAdmissionError::Rejected {
                message,
                reason: NetworkActorAdmissionRejection::FrameTooLarge,
            }) => {
                assert_eq!(message.data, RoutedActorDummy::Control);
                assert_eq!(message.peer_id, target);
            }
            other => panic!("oversize post must be returned with its exact cap outcome: {other:?}"),
        }
        let (closed, _safety_rx, _progress_rx, closed_high_rx, _low_rx) =
            handle_with_network_receivers::<RoutedActorDummy>();
        drop(closed_high_rx);
        match closed.post_best_effort_recoverable(post()) {
            Err(NetworkPostAdmissionError::Closed { message }) => {
                assert_eq!(message.data, RoutedActorDummy::Control);
                assert_eq!(message.peer_id, target);
            }
            other => panic!("closed actor must return the exact post: {other:?}"),
        }
    }
    #[test]
    fn ordinary_high_saturation_does_not_consume_progress_or_safety_capacity() {
        let (handle, mut safety_rx, mut progress_rx, mut high_rx, mut low_rx) =
            handle_with_network_receivers::<RoutedActorDummy>();
        let peer_id = random_node_peer_id();
        accept_direct_targets(&handle, HashSet::from([peer_id.clone()]));
        handle.post(Post {
            data: RoutedActorDummy::Control,
            peer_id: peer_id.clone(),
            priority: Priority::High,
        });
        handle
            .post_recoverable(
                Post {
                    data: RoutedActorDummy::Lane,
                    peer_id: peer_id.clone(),
                    priority: Priority::Low,
                },
                None,
            )
            .expect("lane progress must enter its source-isolated queue");
        handle
            .post_recoverable(
                Post {
                    data: RoutedActorDummy::Safety,
                    peer_id,
                    // Safety classification must override a mistaken caller priority.
                    priority: Priority::Low,
                },
                None,
            )
            .expect("safety progress must enter its source-isolated lane");
        assert!(matches!(
            high_rx.try_recv().map(AdmittedNetworkMessage::into_inner),
            Ok(NetworkMessage::Post(Post {
                data: RoutedActorDummy::Control,
                priority: Priority::High,
                ..
            }))
        ));
        assert!(matches!(
            safety_rx.try_recv().map(AdmittedNetworkMessage::into_inner),
            Ok(NetworkMessage::Post(Post {
                data: RoutedActorDummy::Safety,
                priority: Priority::High,
                ..
            }))
        ));
        assert!(matches!(
            progress_rx
                .try_recv()
                .map(AdmittedNetworkMessage::into_inner),
            Ok(NetworkMessage::Post(Post {
                data: RoutedActorDummy::Lane,
                priority: Priority::High,
                ..
            }))
        ));
        assert!(matches!(
            low_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
    #[test]
    fn consensus_lane_and_block_sync_use_progress_and_canonical_high() {
        let (handle, _safety_rx, mut progress_rx, mut high_rx, mut low_rx) =
            handle_with_network_receivers::<RoutedActorDummy>();
        let peer_id = random_node_peer_id();
        accept_direct_targets(&handle, HashSet::from([peer_id.clone()]));
        for data in [RoutedActorDummy::Lane, RoutedActorDummy::BlockSync] {
            handle
                .post_recoverable(
                    Post {
                        data: data.clone(),
                        peer_id: peer_id.clone(),
                        priority: Priority::Low,
                    },
                    None,
                )
                .expect("reliable progress must enter its additive actor corridor");
            assert!(matches!(
                progress_rx
                    .try_recv()
                    .map(AdmittedNetworkMessage::into_inner),
                Ok(NetworkMessage::Post(Post {
                    data: admitted,
                    priority: Priority::High,
                    ..
                })) if admitted == data
            ));
        }
        assert!(matches!(
            high_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            low_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
    #[test]
    #[should_panic(expected = "requires post_recoverable")]
    fn void_post_rejects_reliable_route_at_developer_boundary() {
        let (handle, _safety_rx, _progress_rx, _high_rx, _low_rx) =
            handle_with_network_receivers::<RoutedActorDummy>();
        handle.post(Post {
            data: RoutedActorDummy::Lane,
            peer_id: random_node_peer_id(),
            priority: Priority::High,
        });
    }
    #[test]
    #[should_panic(expected = "requires broadcast_recoverable")]
    fn void_broadcast_rejects_reliable_route_at_developer_boundary() {
        let (handle, _safety_rx, _progress_rx, _high_rx, _low_rx) =
            handle_with_network_receivers::<RoutedActorDummy>();
        handle.broadcast(Broadcast {
            data: RoutedActorDummy::Lane,
            priority: Priority::High,
        });
    }
    #[test]
    fn recoverable_progress_admission_preserves_fifo_and_exact_original() {
        let (mut handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
            handle_with_network_receivers::<RoutedActorDummy>();
        let peer_id = random_node_peer_id();
        accept_direct_targets(&handle, HashSet::from([peer_id.clone()]));
        let post = || Post {
            data: RoutedActorDummy::Lane,
            peer_id: peer_id.clone(),
            priority: Priority::Low,
        };
        let fixture = NetworkMessage::Post(post());
        let plaintext_frame_bytes =
            outbound_actor_message_wire_bytes(&fixture, &handle.self_id, handle.relay_ttl)
                .expect("count exact consensus-lane actor fixture");
        let stream_wire_bytes = crate::frame_queue_charge(plaintext_frame_bytes)
            .expect("small consensus-lane fixture must have a stream charge");
        handle.topic_frame_caps.consensus = plaintext_frame_bytes;
        handle.network_actor_progress_budget =
            NetworkActorProgressBudget::new(stream_wire_bytes, 4, 4)
                .expect("small progress budget");
        handle.network_message_progress_deferred_permits = Arc::new(Semaphore::new(0));
        handle
            .post_recoverable(post(), None)
            .expect("the exact maximum must enter the empty progress corridor");
        assert_eq!(
            handle.network_actor_progress_budget.retained(),
            stream_wire_bytes
        );
        let (second, first_ticket) = match handle.post_recoverable(post(), None) {
            Err(NetworkActorAdmissionError::Backpressured {
                message,
                ticket: Some(ticket),
                rank: 1,
            }) => (message, ticket),
            other => panic!("expected rank-one recoverable pressure, got {other:?}"),
        };
        assert_eq!(second.data, RoutedActorDummy::Lane);
        assert_eq!(second.peer_id, peer_id);
        assert_eq!(second.priority, Priority::Low);
        let (third, second_ticket) = match handle.post_recoverable(post(), None) {
            Err(NetworkActorAdmissionError::Backpressured {
                message,
                ticket: Some(ticket),
                rank: 2,
            }) => (message, ticket),
            other => panic!("expected rank-two recoverable pressure, got {other:?}"),
        };
        assert_eq!(third.priority, Priority::Low);
        let first = progress_rx
            .try_recv()
            .expect("first progress post must be queued");
        assert!(matches!(
            &first.message,
            Some(AdmittedNetworkPayload::Unsigned(NetworkMessage::Post(
                Post {
                    priority: Priority::High,
                    ..
                }
            )))
        ));
        drop(first);
        assert_eq!(handle.network_actor_progress_budget.retained(), 0);
        assert!(matches!(
            handle.post_recoverable(post(), None),
            Err(NetworkActorAdmissionError::Backpressured {
                ticket: Some(_),
                rank: 3,
                ..
            })
        ));
        handle
            .post_recoverable(second, Some(first_ticket))
            .expect("the oldest ticket must acquire the released corridor");
        assert_eq!(
            second_ticket.rank(),
            Some(1),
            "committing the oldest ticket must decrease the next caller's rank"
        );
        let admitted = progress_rx
            .try_recv()
            .expect("the oldest retry must enter the progress channel")
            .into_inner();
        assert!(matches!(
            admitted,
            NetworkMessage::Post(Post {
                data: RoutedActorDummy::Lane,
                priority: Priority::High,
                ..
            })
        ));
        assert_eq!(handle.network_actor_progress_budget.retained(), 0);
        handle
            .post_recoverable(third, Some(second_ticket))
            .expect("the second ticket must acquire the released corridor");
        let admitted = progress_rx
            .try_recv()
            .expect("the second retry must enter the progress channel")
            .into_inner();
        assert!(matches!(
            admitted,
            NetworkMessage::Post(Post {
                data: RoutedActorDummy::Lane,
                priority: Priority::High,
                ..
            })
        ));
        assert_eq!(handle.network_actor_progress_budget.retained(), 0);
    }
    #[test]
    fn progress_ticket_rejects_a_different_same_length_payload() {
        let (mut handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
            handle_with_network_receivers::<RoutedActorDummy>();
        let peer_id = random_node_peer_id();
        accept_direct_targets(&handle, HashSet::from([peer_id.clone()]));
        let post = |data| Post {
            data,
            peer_id: peer_id.clone(),
            priority: Priority::Low,
        };
        let fixture = NetworkMessage::Post(post(RoutedActorDummy::Lane));
        let plaintext_frame_bytes =
            outbound_actor_message_wire_bytes(&fixture, &handle.self_id, handle.relay_ttl)
                .expect("count exact ticket-identity fixture");
        let stream_wire_bytes = crate::frame_queue_charge(plaintext_frame_bytes)
            .expect("small ticket-identity fixture must have a stream charge");
        handle.topic_frame_caps.consensus = plaintext_frame_bytes;
        handle.network_actor_progress_budget =
            NetworkActorProgressBudget::new(stream_wire_bytes, 1, 2)
                .expect("one source with two bounded waiters");
        handle.network_message_progress_deferred_permits = Arc::new(Semaphore::new(0));
        handle
            .post_recoverable(post(RoutedActorDummy::Lane), None)
            .expect("first exact request fills the retained source slot");
        let ticket = match handle.post_recoverable(post(RoutedActorDummy::Lane), None) {
            Err(NetworkActorAdmissionError::Backpressured {
                ticket: Some(ticket),
                rank: 1,
                ..
            }) => ticket,
            other => panic!("expected an identity-bound rank-one ticket, got {other:?}"),
        };
        let different = post(RoutedActorDummy::LaneAlternate);
        assert_eq!(
            outbound_actor_message_wire_bytes(
                &NetworkMessage::Post(different.clone()),
                &handle.self_id,
                handle.relay_ttl,
            )
            .expect("count alternate request"),
            plaintext_frame_bytes,
            "the adversarial replacement must have the same actor shape"
        );
        match handle.post_recoverable(different, Some(ticket)) {
            Err(NetworkActorAdmissionError::Rejected { message, reason }) => {
                assert_eq!(reason, NetworkActorAdmissionRejection::InvalidTicket);
                assert_eq!(message.data, RoutedActorDummy::LaneAlternate);
                assert_eq!(message.peer_id, peer_id);
                assert_eq!(message.priority, Priority::Low);
            }
            other => panic!("same-length payload substitution must be rejected: {other:?}"),
        }
        drop(
            progress_rx
                .try_recv()
                .expect("release the first retained request"),
        );
        assert_eq!(handle.network_actor_progress_budget.retained(), 0);
    }
    #[test]
    fn distinct_direct_posts_to_the_same_target_remain_exactly_backpressured() {
        let (mut handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
            handle_with_network_receivers::<RoutedActorDummy>();
        let peer_id = random_node_peer_id();
        accept_direct_targets(&handle, HashSet::from([peer_id.clone()]));
        let post = |data| Post {
            data,
            peer_id: peer_id.clone(),
            priority: Priority::Low,
        };
        let first = post(RoutedActorDummy::Lane);
        let second = post(RoutedActorDummy::LaneAlternate);
        let first_wire = outbound_actor_message_wire_bytes(
            &NetworkMessage::Post(first.clone()),
            &handle.self_id,
            handle.relay_ttl,
        )
        .expect("count first direct progress request");
        assert_eq!(
            outbound_actor_message_wire_bytes(
                &NetworkMessage::Post(second.clone()),
                &handle.self_id,
                handle.relay_ttl,
            )
            .expect("count second direct progress request"),
            first_wire,
            "the collision fixture must differ only in its same-size payload identity"
        );
        let stream_wire_bytes = crate::frame_queue_charge(first_wire)
            .expect("small direct progress fixture must have a stream charge");
        handle.topic_frame_caps.consensus = first_wire;
        handle.network_actor_progress_budget =
            NetworkActorProgressBudget::new(stream_wire_bytes, 1, 2)
                .expect("one exact target source and one waiter must fit");
        handle.network_message_progress_deferred_permits = Arc::new(Semaphore::new(0));
        handle
            .post_recoverable(first, None)
            .expect("first direct request owns the target lane");
        let (second, ticket) = match handle.post_recoverable(second, None) {
            Err(NetworkActorAdmissionError::Backpressured {
                message,
                ticket: Some(ticket),
                rank: 1,
            }) => (message, ticket),
            other => panic!("distinct direct request must remain exact: {other:?}"),
        };
        assert_eq!(second.data, RoutedActorDummy::LaneAlternate);
        assert_eq!(second.peer_id, peer_id);
        assert_eq!(second.priority, Priority::Low);
        drop(
            progress_rx
                .try_recv()
                .expect("release the first direct request owner"),
        );
        handle
            .post_recoverable(second, Some(ticket))
            .expect("the exact distinct request acquires the released target lane");
        let admitted = progress_rx
            .try_recv()
            .expect("distinct direct request reaches the actor")
            .into_inner();
        assert!(matches!(
            admitted,
            NetworkMessage::Post(Post {
                data: RoutedActorDummy::LaneAlternate,
                priority: Priority::High,
                ..
            })
        ));
        assert_eq!(handle.network_actor_progress_budget.retained(), 0);
    }
    #[test]
    fn recoverable_progress_budget_isolates_targets_at_one_frame_per_source() {
        let (mut handle, _safety_rx, mut progress_rx, _high_rx, _low_rx) =
            handle_with_network_receivers::<RoutedActorDummy>();
        let blocked_peer = random_node_peer_id();
        let responsive_peer = random_node_peer_id();
        accept_direct_targets(
            &handle,
            HashSet::from([blocked_peer.clone(), responsive_peer.clone()]),
        );
        let post = |peer_id| Post {
            data: RoutedActorDummy::Lane,
            peer_id,
            priority: Priority::Low,
        };
        let fixture = NetworkMessage::Post(post(blocked_peer.clone()));
        let plaintext_frame_bytes =
            outbound_actor_message_wire_bytes(&fixture, &handle.self_id, handle.relay_ttl)
                .expect("count exact source-isolation fixture");
        let stream_wire_bytes = crate::frame_queue_charge(plaintext_frame_bytes)
            .expect("small source-isolation fixture must have a stream charge");
        handle.topic_frame_caps.consensus = plaintext_frame_bytes;
        handle.network_actor_progress_budget =
            NetworkActorProgressBudget::new(stream_wire_bytes, 4, 4)
                .expect("small progress budget");
        handle.network_message_progress_deferred_permits = Arc::new(Semaphore::new(0));
        handle
            .post_recoverable(post(blocked_peer), None)
            .expect("the blocked target must acquire its one-frame source reserve");
        let first = progress_rx.try_recv().expect("blocked target is retained");
        handle
            .post_recoverable(post(responsive_peer.clone()), None)
            .expect("a different target must bypass the occupied source reserve");
        assert_eq!(
            handle.network_actor_progress_budget.retained(),
            stream_wire_bytes * 2
        );
        let second = progress_rx
            .try_recv()
            .expect("responsive target is independently admitted");
        assert!(matches!(
            &second.message,
            Some(AdmittedNetworkPayload::Unsigned(NetworkMessage::Post(Post { peer_id, .. })))
                if peer_id == &responsive_peer
        ));
        drop(first);
        assert_eq!(
            handle.network_actor_progress_budget.retained(),
            stream_wire_bytes
        );
        drop(second);
        assert_eq!(handle.network_actor_progress_budget.retained(), 0);
    }
    #[test]
    fn recoverable_progress_rejects_one_over_cap_and_releases_on_close() {
        let (mut handle, _safety_rx, progress_rx, _high_rx, _low_rx) =
            handle_with_network_receivers::<RoutedActorDummy>();
        let peer_id = random_node_peer_id();
        let post = || Post {
            data: RoutedActorDummy::Lane,
            peer_id: peer_id.clone(),
            priority: Priority::Low,
        };
        let fixture = NetworkMessage::Post(post());
        let plaintext_frame_bytes =
            outbound_actor_message_wire_bytes(&fixture, &handle.self_id, handle.relay_ttl)
                .expect("count exact close fixture");
        let stream_wire_bytes = crate::frame_queue_charge(plaintext_frame_bytes)
            .expect("small close fixture must have a stream charge");
        handle.topic_frame_caps.consensus = plaintext_frame_bytes;
        handle.network_actor_progress_budget =
            NetworkActorProgressBudget::new(stream_wire_bytes, 1, 1)
                .expect("small progress budget");
        drop(progress_rx);
        let closed = handle
            .post_recoverable(post(), None)
            .expect_err("a closed progress channel must return source ownership");
        assert!(matches!(
            closed,
            NetworkActorAdmissionError::Closed {
                message: Post {
                    data: RoutedActorDummy::Lane,
                    priority: Priority::Low,
                    ..
                }
            }
        ));
        assert_eq!(handle.network_actor_progress_budget.retained(), 0);
        handle.topic_frame_caps.consensus = plaintext_frame_bytes - 1;
        let rejected = handle
            .post_recoverable(post(), None)
            .expect_err("one byte over the topic cap must be permanently rejected");
        assert!(matches!(
            rejected,
            NetworkActorAdmissionError::Rejected {
                message: Post {
                    priority: Priority::Low,
                    ..
                },
                reason: NetworkActorAdmissionRejection::FrameTooLarge,
            }
        ));
        assert_eq!(handle.network_actor_progress_budget.retained(), 0);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn ordinary_control_overflow_cannot_consume_source_isolated_safety_capacity() {
        let (handle, mut safety_rx, mut progress_rx, mut high_rx, _low_rx) =
            handle_with_network_receivers::<RoutedActorDummy>();
        let peer_id = random_node_peer_id();
        accept_direct_targets(&handle, HashSet::from([peer_id.clone()]));
        let post = |data| Post {
            data,
            peer_id: peer_id.clone(),
            priority: Priority::High,
        };
        handle.post(post(RoutedActorDummy::Control));
        handle.post(post(RoutedActorDummy::Control));
        assert_eq!(
            handle
                .network_message_high_deferred_permits
                .available_permits(),
            0
        );
        assert_eq!(
            handle
                .network_message_safety_deferred_permits
                .available_permits(),
            1,
            "ordinary control overflow must not reserve safety overflow capacity"
        );
        handle
            .post_recoverable(post(RoutedActorDummy::Safety), None)
            .expect("the safety source owns its independent progress slot");
        assert!(matches!(
            handle.post_recoverable(post(RoutedActorDummy::Safety), None),
            Err(NetworkActorAdmissionError::Backpressured {
                ticket: Some(_),
                rank: 1,
                ..
            })
        ));
        assert_eq!(
            handle
                .network_message_safety_deferred_permits
                .available_permits(),
            1,
            "a second item from one safety source must remain with its caller"
        );
        assert!(matches!(
            progress_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            high_rx.recv().await.map(AdmittedNetworkMessage::into_inner),
            Some(NetworkMessage::Post(_))
        ));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), high_rx.recv())
                .await
                .map(|message| message.map(AdmittedNetworkMessage::into_inner)),
            Ok(Some(NetworkMessage::Post(_)))
        ));
        assert!(matches!(
            safety_rx
                .recv()
                .await
                .map(AdmittedNetworkMessage::into_inner),
            Some(NetworkMessage::Post(Post {
                data: RoutedActorDummy::Safety,
                ..
            }))
        ));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn low_priority_post_still_drops_when_actor_queue_is_full() {
        let (handle, _safety_rx, _progress_rx, _high_rx, mut low_rx) =
            handle_with_network_receivers::<Dummy>();
        let peer_id = random_node_peer_id();
        handle.post(Post {
            data: Dummy,
            peer_id: peer_id.clone(),
            priority: Priority::Low,
        });
        handle.post(Post {
            data: Dummy,
            peer_id,
            priority: Priority::Low,
        });
        let first = low_rx
            .recv()
            .await
            .expect("first low-priority post should be queued")
            .into_inner();
        assert!(matches!(first, NetworkMessage::Post(_)));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), low_rx.recv())
                .await
                .is_err(),
            "low-priority overflow should remain lossy"
        );
    }
    #[tokio::test]
    async fn update_methods_ignore_closed_channels() {
        let handle = closed_handle();
        handle.update_topology(message::UpdateTopology(HashSet::new()));
        handle.update_peers_addresses(message::UpdatePeers(Vec::new()));
        handle.update_peer_capabilities(message::UpdatePeerCapabilities(Vec::new()));
        handle.update_trusted_peers(message::UpdateTrustedPeers::default());
        handle.update_acl(message::UpdateAcl::default());
        handle
            .update_soranet_handshake(ActualSoranetHandshake::default())
            .await
            .expect_err("closed actor must reject an acknowledged handshake update");
    }
    #[test]
    fn closed_handle_reports_subscriber_queue_cap() {
        let handle = closed_handle();
        assert_eq!(handle.subscriber_queue_cap().get(), 1);
        assert_eq!(handle.authenticated_source_credit_capacity().get(), 1);
    }
    #[tokio::test]
    async fn wait_online_peers_update_reports_closed_channel() {
        let mut handle = closed_handle();
        let result = handle.wait_online_peers_update(HashSet::len).await;
        assert!(result.is_err());
    }
}
