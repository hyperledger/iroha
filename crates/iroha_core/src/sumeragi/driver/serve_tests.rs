//! Scheduler, metadata boundaries and the actual signed-row serving path.
use super::*;
use crate::sumeragi::driver::{payload_worker_tests::Fixture, traits::BodyStore};
fn key(n: u8) -> PublicKey {
    PublicKey::new(vec![n; 48]).unwrap()
}
fn blocks(n: u8, h: u64) -> ServeRequest {
    ServeRequest::Blocks {
        to: key(n),
        from_height: h,
        max_count: 8,
        max_bytes: 4096,
    }
}
fn body(n: u8, h: u64) -> ServeRequest {
    ServeRequest::Payload(Box::new(PayloadWork::Serve {
        to: key(n),
        height: h,
        block_hash: Hash32([u8::try_from(h).expect("fixture value fits u8"); 32]),
    }))
}
#[test]
fn local_work_precedes_peer_requests_and_one_turn_is_in_flight() {
    let mut s = ServeSched::new(ServeLimits::default());
    s.push(blocks(1, 1), 0);
    s.push(ServeRequest::Payload(Box::new(PayloadWork::Applied(3))), 0);
    assert!(
        matches!(s.next(0),Some(ServeRequest::Payload(w)) if matches!(*w,PayloadWork::Applied(3)))
    );
    assert!(s.next(0).is_none());
    s.done(
        0,
        Served {
            payload: true,
            ..Served::default()
        },
    );
    assert_eq!(s.next(0), Some(blocks(1, 1)));
}
#[test]
fn one_request_per_peer_and_kind_replaces_only_the_same_kind() {
    let mut s = ServeSched::new(ServeLimits::default());
    s.push(blocks(1, 1), 0);
    s.push(blocks(1, 2), 0);
    s.push(body(1, 3), 0);
    s.push(blocks(2, 4), 0);
    assert_eq!(s.len(), 3);
    assert_eq!(s.dropped(), 1);
    assert_eq!(s.next(0), Some(body(1, 3)));
    s.done(0, Served::default());
    assert_eq!(s.next(0), Some(blocks(2, 4)));
    s.done(0, Served::default());
    assert_eq!(s.next(0), Some(blocks(1, 2)));
}
#[test]
fn actual_response_debt_is_per_peer_and_refills_monotonically() {
    let mut s = ServeSched::new(ServeLimits {
        bytes_per_sec: 100,
        burst_bytes: 100,
        max_peers: 2,
    });
    s.push(blocks(1, 1), 0);
    s.next(0);
    s.done(
        0,
        Served {
            charges: vec![(key(1), 150)],
            ..Served::default()
        },
    );
    assert!(!s.push(blocks(1, 2), 0));
    assert!(s.push(blocks(2, 2), 0));
    assert!(s.push(blocks(1, 3), 1000));
}
#[test]
fn peer_bound_evicts_only_idle_fully_refilled_peers() {
    let mut s = ServeSched::new(ServeLimits {
        max_peers: 1,
        ..ServeLimits::default()
    });
    assert!(s.push(blocks(1, 1), 0));
    assert!(!s.push(blocks(2, 1), 0));
    s.next(0);
    s.done(0, Served::default());
    assert!(s.push(blocks(2, 1), 0));
}
#[test]
fn ready_rows_are_immediate_resource_refusal_has_backoff_and_remote_wait_has_none() {
    let mut s = ServeSched::new(ServeLimits::default());
    s.done(
        5,
        Served {
            payload: true,
            retry: true,
            refused: false,
            ..Served::default()
        },
    );
    assert_eq!(s.wakeup(), 5);
    assert!(s.next(5).is_some());
    s.done(
        5,
        Served {
            payload: true,
            retry: true,
            refused: true,
            ..Served::default()
        },
    );
    assert_eq!(s.wakeup(), 15);
    assert!(s.next(14).is_none());
    assert!(s.next(15).is_some());
    s.done(
        15,
        Served {
            payload: true,
            ..Served::default()
        },
    );
    assert_eq!(s.wakeup(), Millis::MAX);
    assert!(s.next(100).is_none());
}
#[test]
fn metadata_completion_does_not_erase_payload_retry_and_refusal_keeps_exact_request() {
    let mut s = ServeSched::new(ServeLimits::default());
    s.done(
        0,
        Served {
            payload: true,
            retry: true,
            refused: true,
            ..Served::default()
        },
    );
    s.done(0, Served::default());
    assert_eq!(s.wakeup(), 10);
    s.done(
        0,
        Served {
            retry_request: Some(blocks(1, 17)),
            ..Served::default()
        },
    );
    assert!(s.next(9).is_none());
    assert_eq!(s.next(10), Some(blocks(1, 17)));
}
#[test]
fn only_current_payload_actions_are_routed() {
    let action = Action::ServePayload {
        to: key(1),
        height: 8,
        block_hash: Hash32::ZERO,
    };
    assert!(matches!(
        ServeRequest::from_action(action),
        Ok(ServeRequest::Payload(_))
    ));
    let other = Action::LocalFault(iroha_sumeragi::api::LocalFault::RecordMissing);
    assert_eq!(ServeRequest::from_action(other.clone()), Err(other));
}
#[test]
fn canonical_frame_carries_instance_class_and_exact_payload_request() {
    let msg = WireMessage::PayloadRequest(iroha_sumeragi::message::PayloadRequest {
        instance: Hash32([5; 32]),
        height: 1,
        block_hash: Hash32::ZERO,
    });
    let f = frame(&msg).unwrap();
    assert_eq!(f.instance, Hash32([5; 32]));
    assert_eq!(f.class, msg.traffic_class());
    assert_eq!(WireMessage::decode(&f.bytes, usize::MAX).unwrap(), msg);
}
#[derive(Default)]
struct Capture(std::sync::Mutex<Vec<(PublicKey, Frame)>>);
impl Net for Capture {
    fn send(&self, to: &PublicKey, frame: &Frame) -> SendOutcome {
        self.0.lock().unwrap().push((to.clone(), frame.clone()));
        SendOutcome::Admitted
    }
}
#[test]
fn serving_emits_original_manifest_actual_rows_and_accounts_each_frame() {
    let f = Fixture::new();
    f.bodies.put(&f.source.block_hash(), &f.body).unwrap();
    let to = f.signers[1].public_key().clone();
    let mut worker = f.worker();
    let net = Capture::default();
    let mut request = ServeRequest::Payload(Box::new(PayloadWork::Serve {
        to: to.clone(),
        height: 1,
        block_hash: f.source.block_hash(),
    }));
    let mut charged = 0;
    for _ in 0..100 {
        let served = serve(
            request,
            f.source.instance(),
            &f.bodies,
            &f.blocks,
            &net,
            &mut worker,
        )
        .unwrap();
        assert!(served.events.is_empty());
        charged += served.charges.iter().map(|(_, n)| *n).sum::<u64>();
        if !served.retry {
            break;
        }
        request = ServeRequest::Payload(Box::new(PayloadWork::Poll));
    }
    let sent = net.0.lock().unwrap();
    assert!(sent.len() > 1);
    assert_eq!(
        charged,
        sent.iter().map(|(_, f)| f.bytes.len() as u64).sum::<u64>()
    );
    assert!(
        matches!(WireMessage::decode(&sent[0].1.bytes,usize::MAX).unwrap(),WireMessage::PayloadManifest(m) if m.availability==*f.body.availability())
    );
    for (_, frame) in &sent[1..] {
        assert!(matches!(
            WireMessage::decode(&frame.bytes, usize::MAX).unwrap(),
            WireMessage::PayloadChunk(_)
        ));
    }
}

#[test]
fn full_retry_queue_cannot_drop_author_or_application_completion() {
    let f = Fixture::new();
    let mut scheduler = ServeSched::new(ServeLimits {
        max_peers: 1,
        ..ServeLimits::default()
    });
    let fetch = ServeRequest::Payload(Box::new(PayloadWork::Fetch {
        source: f.source.clone(),
        peers: vec![key(1)],
    }));
    assert!(scheduler.push(fetch.clone(), 0));
    let author = ServeRequest::Payload(Box::new(PayloadWork::Author {
        req: 19,
        config: f.source.config().clone(),
        header: f.body.header().clone(),
        payload: f.body.payload().clone(),
    }));
    assert!(scheduler.push(author.clone(), 0));
    assert!(scheduler.push(ServeRequest::Payload(Box::new(PayloadWork::Applied(3))), 0));
    assert!(scheduler.push(ServeRequest::Payload(Box::new(PayloadWork::Applied(2))), 0));
    assert_eq!(scheduler.len(), 3);
    assert!(
        matches!(scheduler.next(0), Some(ServeRequest::Payload(w)) if *w == PayloadWork::Applied(3))
    );
    scheduler.done(0, Served::default());
    assert_eq!(scheduler.next(0), Some(author));
    scheduler.done(0, Served::default());
    assert_eq!(scheduler.next(0), Some(fetch));
    assert_eq!(scheduler.dropped(), 0);
}

#[test]
fn refused_metadata_owner_cannot_be_replaced_by_another_peer_during_backoff() {
    let budget = iroha_allocation::AllocationBudget::new(1);
    let held = budget.try_reserve_bytes(1).unwrap();
    let refusal = budget.try_reserve_bytes(1).unwrap_err();
    let owner = crate::execution_attempt::ExecutionDeferred::from(refusal.clone());
    let mut scheduler = ServeSched::new(ServeLimits::default());
    let original = blocks(1, 1);
    let other = blocks(2, 2);
    assert!(scheduler.push(original.clone(), 0));
    assert_eq!(scheduler.next(0), Some(original.clone()));
    scheduler.done(
        0,
        Served {
            retry_request: Some(original.clone()),
            deferred: Some(owner),
            ..Served::default()
        },
    );
    assert!(scheduler.push(other.clone(), 0));
    assert!(
        scheduler.next(1).is_none(),
        "another refused metadata answer must not evict the only original retry slot"
    );
    assert_eq!(
        scheduler
            .failed
            .as_ref()
            .unwrap()
            .2
            .as_ref()
            .unwrap()
            .allocation_refusal(),
        Some(&refusal)
    );
    let payload = ServeRequest::Payload(Box::new(PayloadWork::Serve {
        to: key(3),
        height: 1,
        block_hash: Hash32([7; 32]),
    }));
    assert!(scheduler.push(payload.clone(), 1));
    assert_eq!(
        scheduler.next(1),
        Some(payload),
        "payload replies remain runnable during metadata backoff"
    );
    scheduler.done(
        1,
        Served {
            payload: true,
            ..Served::default()
        },
    );
    assert!(scheduler.next(1).is_none());
    assert_eq!(
        scheduler
            .failed
            .as_ref()
            .unwrap()
            .2
            .as_ref()
            .unwrap()
            .allocation_refusal(),
        Some(&refusal)
    );
    drop(held);
    assert_eq!(scheduler.next(10), Some(original));
    assert_eq!(
        scheduler
            .in_flight_refusal
            .as_ref()
            .unwrap()
            .allocation_refusal(),
        Some(&refusal)
    );
    scheduler.done(10, Served::default());
    assert!(scheduler.in_flight_refusal.is_none());
    assert_eq!(scheduler.next(10), Some(other));
}

/// Read-only committed-entry fixture: the same maximal metadata entry at every stored height.
struct RepeatedEntries {
    entry: SyncEntry,
    height: u64,
}
struct NoBody(iroha_sumeragi::availability::AvailabilitySource);
impl crate::sumeragi::body_read::BodyReadJob for NoBody {
    fn source(&self) -> &iroha_sumeragi::availability::AvailabilitySource {
        &self.0
    }
    fn poll(
        &mut self,
        _: &iroha_allocation::AllocationBudget,
    ) -> Result<crate::sumeragi::body_read::BodyReadPoll, crate::sumeragi::body_read::BodyReadError>
    {
        Ok(crate::sumeragi::body_read::BodyReadPoll::Absent)
    }
}
impl crate::sumeragi::body_read::BodyReader for RepeatedEntries {
    fn begin_read(
        &self,
        source: iroha_sumeragi::availability::AvailabilitySource,
    ) -> Result<
        Box<dyn crate::sumeragi::body_read::BodyReadJob>,
        crate::sumeragi::body_read::BodyReadError,
    > {
        Ok(Box::new(NoBody(source)))
    }
}
impl BlockStore for RepeatedEntries {
    fn retired_publication(
        self: std::sync::Arc<Self>,
    ) -> Option<std::sync::Arc<dyn crate::sumeragi::driver::traits::RetiredPublication>> {
        None
    }
    fn height(&self) -> u64 {
        self.height
    }
    fn committed_body(
        &self,
        _: u64,
    ) -> Result<
        Option<(
            iroha_sumeragi::availability::AvailableBody,
            iroha_sumeragi::message::Qc,
        )>,
        Attempt<io::Error>,
    > {
        Ok(None)
    }
    fn entry(&self, height: u64) -> Result<Option<SyncEntry>, Attempt<io::Error>> {
        Ok((1..=self.height)
            .contains(&height)
            .then(|| self.entry.clone()))
    }
    fn availability_source(
        &self,
        _: u64,
        _: Hash32,
    ) -> Result<Option<iroha_sumeragi::availability::AvailabilitySource>, Attempt<io::Error>> {
        Ok(None)
    }
    fn append(
        &self,
        _: &iroha_sumeragi::availability::AvailableBody,
        _: &iroha_sumeragi::message::Qc,
    ) -> Result<(), Attempt<io::Error>> {
        Err(io::Error::other("read-only fixture").into())
    }
}

/// Complete Sumeragi frames at the bounds this node admits, against what is enforced.
///
/// Global committees and every certifiable lane committee have at most
/// `MAX_VALIDATORS_PER_HEIGHT` members (`verify_lane_certificate` checks the same size), and
/// consensus keys are BLS-normal 48-byte core keys (`crypto::core_key`). The control witness
/// is full and the availability table has the most rows any signed layout permits. Proposals,
/// manifests and sync entries carry no payload, so each such frame fits `FRAME_OVERHEAD`.
/// These are transport maxima, not limits of any native proof catalog.
///
/// `entries` charges each entry its encoded length plus 16 bytes against the requested budget,
/// which the core clamps to the local `sync_max_bytes`. The fullest default-budget response
/// stays within that budget, and its complete P2P frame stays within the default block-sync
/// topic cap and the transport class cap that ingress decodes against. The ingress never
/// charges a proposal or sync entry against `FRAME_OVERHEAD` itself.
#[test]
fn admitted_maximum_frames_fit_frame_overhead_and_the_block_sync_frame() {
    use crate::sumeragi::net::{FrameCaps, SumeragiFrame, inbound_decode_limits, topic_of_class};
    use iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_BLOCK_SYNC;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::peer::PeerId;
    use iroha_sumeragi::{
        api::LocalParams,
        availability::{AvailabilityFrame, MAX_AVAILABILITY_FRAME_BYTES, MAX_DA_CHUNK_COUNT},
        message::{
            BlockHeader, MAX_SYNC_ENTRIES, PayloadManifest, Proposal, ProposalMessage, Qc, TcEntry,
            TimeoutCert, TrafficClass, VoteKind,
        },
        pacemaker::FRAME_OVERHEAD,
        types::{
            AggregateSignature, Bitmap, ControlWitness, EpochId, MAX_CONTROL_WITNESS_BYTES,
            SIGNATURE_LEN, Signature,
        },
    };

    let count = iroha_data_model::block::consensus::MAX_VALIDATORS_PER_HEIGHT;
    assert_eq!(count, 31);
    let keys: Vec<PublicKey> = (0..count)
        .map(|index| {
            let seed = u8::try_from(index + 1).expect("thirty-one distinct seeds");
            let pair = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
            let key = crate::sumeragi::crypto::core_key(pair.public_key()).unwrap();
            assert_eq!(
                key.as_bytes().len(),
                48,
                "compressed BLS-normal G1 core key"
            );
            key
        })
        .collect();
    let index = |position: usize| u32::try_from(position).expect("committee index");
    let h = |byte: u8| Hash32([byte; 32]);
    let epoch = EpochId {
        epoch: u64::MAX,
        context: h(0xEE),
    };
    let qc = |kind, view| Qc {
        kind,
        instance: h(1),
        epoch,
        height: u64::MAX,
        view,
        block_hash: h(7),
        result: h(8),
        signers: Bitmap::from_indices(count, (0..count).map(index)).unwrap(),
        agg_sig: AggregateSignature([9; SIGNATURE_LEN]),
    };
    let header = BlockHeader {
        instance: h(1),
        epoch,
        height: u64::MAX,
        origin_view: u64::MAX,
        parent_hash: h(2),
        parent_result: h(3),
        payload_hash: h(4),
        availability_digest: h(5),
        payload_len: u32::MAX,
        proposer: index(count - 1),
        skipped_leaders: keys,
        control_witness: ControlWitness::try_from_slice(&[3; MAX_CONTROL_WITNESS_BYTES]).unwrap(),
    };
    let table = {
        let mut bytes = vec![0; MAX_AVAILABILITY_FRAME_BYTES];
        bytes[..4].copy_from_slice(&MAX_DA_CHUNK_COUNT.to_be_bytes());
        AvailabilityFrame::from_untrusted(bytes).unwrap()
    };
    let overhead = usize::try_from(FRAME_OVERHEAD).unwrap();
    let proposal = WireMessage::Proposal(Box::new(ProposalMessage {
        proposal: Proposal {
            instance: h(1),
            height: u64::MAX,
            view: u64::MAX,
            header: header.clone(),
            justify: Some(TimeoutCert {
                instance: h(1),
                epoch,
                height: u64::MAX,
                view: u64::MAX - 1,
                entries: (0..count)
                    .map(|position| TcEntry {
                        signer: index(position),
                        hq: Some(u64::MAX - 2),
                    })
                    .collect(),
                agg_sig: AggregateSignature([10; SIGNATURE_LEN]),
                high_pqc: Some(qc(VoteKind::Prepare, u64::MAX - 2)),
            }),
            parent_qc: Some(qc(VoteKind::Commit, u64::MAX)),
            sig: Signature([13; SIGNATURE_LEN]),
        },
        availability: table.clone(),
    }));
    let entry = SyncEntry {
        manifest: PayloadManifest {
            header,
            availability: table,
        },
        commit_qc: qc(VoteKind::Commit, u64::MAX),
    };
    let one_entry = WireMessage::SyncResponse(SyncResponse {
        instance: h(1),
        blocks: vec![entry.clone()],
    });
    // Measured canonical lengths; a change to any carrier must update them deliberately.
    for (label, message, measured) in [
        ("proposal", &proposal, 136_803),
        ("one-entry sync response", &one_entry, 135_674),
    ] {
        let bytes = message.encode().unwrap();
        assert_eq!(bytes.len(), measured, "{label}");
        assert!(bytes.len() <= overhead, "{label} fits FRAME_OVERHEAD");
        assert_eq!(&WireMessage::decode(&bytes, bytes.len()).unwrap(), message);
    }
    // The outer framing of a one-entry response (header, tag, instance, count and entry
    // prefixes) beyond its serving charge fits the slack the block-sync requirement adds.
    let entry_len = norito::codec::Encode::encoded_len(&entry);
    let one_entry_framing = one_entry.encode().unwrap().len() - entry_len;
    assert_eq!(one_entry_framing, 95, "measured one-entry outer framing");
    assert!(
        one_entry_framing - ENTRY_FRAMING <= crate::sumeragi::net::SYNC_RESPONSE_FRAMING_SLACK,
        "{one_entry_framing} framing bytes"
    );

    // The fullest response the serving rule emits for the default local budget.
    let budget = LocalParams::default().sync_max_bytes;
    let store = RepeatedEntries {
        entry: entry.clone(),
        height: u64::try_from(MAX_SYNC_ENTRIES).unwrap(),
    };
    let max_count = u16::try_from(MAX_SYNC_ENTRIES).unwrap();
    let served = entries(&store, 1, max_count, budget).unwrap();
    let charge = entry_len + ENTRY_FRAMING;
    let budget_bytes = usize::try_from(budget).unwrap();
    assert_eq!(
        served.len(),
        budget_bytes / charge,
        "entries fill the budget"
    );
    assert!((served.len() + 1) * charge > budget_bytes);
    let response = WireMessage::SyncResponse(SyncResponse {
        instance: h(1),
        blocks: served,
    });
    assert_eq!(response.traffic_class(), TrafficClass::Bulk);
    let bytes = response.encode().unwrap();
    assert!(
        bytes.len() <= budget_bytes,
        "the per-entry charge covers the outer response framing: {}",
        bytes.len()
    );

    // Complete P2P frames: the Sumeragi envelope, relay and Data wrappers, direct and broadcast.
    let origin = PeerId::new(
        KeyPair::from_seed(vec![0xE5; 32], Algorithm::BlsNormal)
            .public_key()
            .clone(),
    );
    let target = PeerId::new(
        KeyPair::from_seed(vec![0xE6; 32], Algorithm::BlsNormal)
            .public_key()
            .clone(),
    );
    let topic_cap = MAX_FRAME_BYTES_BLOCK_SYNC.get();
    // The startup requirement for the block-sync topic covers the fullest default response.
    let required = crate::sumeragi::net::minimum_block_sync_frame_bytes(
        &origin,
        &iroha_config::parameters::actual::SumeragiLocalOverrides::default(),
    );
    assert!(required <= topic_cap, "{required} > {topic_cap}");
    for message in [&response, &proposal] {
        let class = message.traffic_class();
        let network = crate::NetworkMessage::Sumeragi(std::sync::Arc::new(SumeragiFrame::new(
            h(1),
            message.encode().unwrap(),
        )));
        let encoded = norito::core::to_bytes(&network).unwrap();
        let view = norito::core::from_bytes_view(&encoded).unwrap();
        let (_, remaining) = crate::inbound_enum_parts(view.as_bytes()).unwrap();
        let field = crate::inbound_owned_enum_field(remaining, view.flags()).unwrap();
        for peer in [None, Some(&target)] {
            let framed = iroha_p2p::network::data_frame_wire_len(&origin, peer, &network);
            assert!(
                framed <= topic_cap,
                "{class:?} frame {framed} > {topic_cap}"
            );
            assert!(framed <= FrameCaps::TRANSPORT.of(class));
            assert!(framed <= required, "{class:?} frame {framed} > {required}");
            assert!(inbound_decode_limits(field, framed, view.flags()).is_ok());
        }
        assert_eq!(
            topic_of_class(class),
            if class == TrafficClass::Bulk {
                iroha_p2p::network::message::Topic::BlockSync
            } else {
                iroha_p2p::network::message::Topic::ConsensusPayload
            }
        );
    }
}

/// Control-class frames at the core's generic decode bounds. Every control variant decodes at
/// exactly its measured canonical length; a frame with one more timeout entry, bitmap byte,
/// echo key byte or witness byte is refused by `WireMessage::decode`. The complete P2P frames, direct and broadcast, travel on
/// the consensus-safety topic: the longest is the startup requirement for its cap, which the
/// shipped 2 MiB control cap and the transport's control class carry.
#[test]
fn generic_maximum_control_frames_fit_the_control_topic() {
    use crate::sumeragi::net::{
        FrameCaps, SumeragiFrame, generic_maximum_control_messages, minimum_control_frame_bytes,
        topic_of_class,
    };
    use iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_CONTROL;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::peer::PeerId;
    use iroha_sumeragi::{
        message::{CodecError, Qc, Status, TimeoutCert, TrafficClass},
        types::{
            Bitmap, ControlWitness, MAX_COMMITTEE_SIZE, MAX_CONTROL_WITNESS_BYTES,
            MAX_PUBLIC_KEY_LEN,
        },
    };

    let messages = generic_maximum_control_messages().expect("the core admits its own maxima");
    // Measured canonical lengths; a change to any carrier must update them deliberately.
    let measured = [
        ("vote", 318),
        ("qc", 453),
        ("timeout", 659),
        ("timeout certificate", 18_075),
        ("status", 19_303),
        ("sync request", 96),
        ("payload request", 122),
        ("application control", 2_261),
    ];
    let origin = PeerId::new(
        KeyPair::from_seed(vec![0xE5; 32], Algorithm::BlsNormal)
            .public_key()
            .clone(),
    );
    let target = PeerId::new(
        KeyPair::from_seed(vec![0xE6; 32], Algorithm::BlsNormal)
            .public_key()
            .clone(),
    );
    let required = minimum_control_frame_bytes(&origin);
    assert_eq!(
        messages.len(),
        measured.len(),
        "one measured length per message"
    );
    let mut longest = 0;
    for (message, (label, length)) in messages.iter().zip(measured) {
        // A new wire variant must be classified here before this list can claim completeness.
        let control = match message {
            WireMessage::Vote(_)
            | WireMessage::Qc(_)
            | WireMessage::Timeout(_)
            | WireMessage::Tc(_)
            | WireMessage::Status(_)
            | WireMessage::SyncRequest(_)
            | WireMessage::PayloadRequest(_)
            | WireMessage::ApplicationControl(_) => true,
            WireMessage::Proposal(_)
            | WireMessage::SyncResponse(_)
            | WireMessage::PayloadManifest(_)
            | WireMessage::PayloadChunk(_) => false,
        };
        assert!(control, "{label}");
        assert_eq!(message.traffic_class(), TrafficClass::Control, "{label}");
        let bytes = message.encode().unwrap();
        assert_eq!(bytes.len(), length, "{label}");
        assert_eq!(
            &WireMessage::decode(&bytes, bytes.len()).unwrap(),
            message,
            "{label} is within the generic decode bounds"
        );
        let network = crate::NetworkMessage::Sumeragi(std::sync::Arc::new(SumeragiFrame::new(
            Hash32([1; 32]),
            bytes,
        )));
        for peer in [None, Some(&target)] {
            let framed = iroha_p2p::network::data_frame_wire_len(&origin, peer, &network);
            assert!(framed <= required, "{label} frame {framed} > {required}");
            longest = longest.max(framed);
        }
    }
    let variants: std::collections::BTreeSet<_> = messages
        .iter()
        .map(|message| format!("{:?}", std::mem::discriminant(message)))
        .collect();
    assert_eq!(
        variants.len(),
        messages.len(),
        "one message per control variant"
    );
    assert_eq!(
        longest, required,
        "the requirement is the longest complete control frame"
    );
    println!("CONTROL_FRAME_REQUIREMENT complete_p2p_frame={required}");
    assert!(required <= MAX_FRAME_BYTES_CONTROL.get(), "{required}");
    assert!(required <= FrameCaps::TRANSPORT.of(TrafficClass::Control));
    assert_eq!(
        topic_of_class(TrafficClass::Control),
        iroha_p2p::network::message::Topic::ConsensusSafety
    );

    // The generic bounds refuse one more of each variable part.
    let WireMessage::Tc(tc) = &messages[3] else {
        unreachable!("timeout certificate slot")
    };
    let mut entries = TimeoutCert::clone(tc);
    entries.entries.push(entries.entries[0]);
    assert!(entries.entries.len() > MAX_COMMITTEE_SIZE);
    let longer = WireMessage::Tc(Box::new(entries)).encode().unwrap();
    assert!(WireMessage::decode(&longer, longer.len()).is_err());
    let WireMessage::Qc(qc) = &messages[1] else {
        unreachable!("certificate slot")
    };
    let wider = WireMessage::Qc(Qc {
        signers: Bitmap::from_indices(MAX_COMMITTEE_SIZE + 8, [0]).unwrap(),
        ..qc.clone()
    })
    .encode()
    .unwrap();
    assert!(WireMessage::decode(&wider, wider.len()).is_err());

    // A status whose echo key is one byte longer than any core key: the key constructor refuses
    // it, so it is built through the key's own codec (field length, u64 length, key bytes, the
    // canonical layout of a maximal key), and the frame decoder refuses it by its limits.
    let key_codec = |len: usize| {
        let mut bytes = leb128(8 + len);
        bytes.extend_from_slice(&u64::try_from(len).unwrap().to_le_bytes());
        bytes.extend(std::iter::repeat_n(7_u8, len));
        bytes
    };
    let maximal_key = PublicKey::new(vec![7; MAX_PUBLIC_KEY_LEN]).unwrap();
    assert_eq!(
        norito::codec::Encode::encode(&maximal_key),
        key_codec(MAX_PUBLIC_KEY_LEN),
        "canonical key layout"
    );
    let longer_key: PublicKey =
        norito::codec::DecodeAll::decode_all(&mut key_codec(MAX_PUBLIC_KEY_LEN + 1).as_slice())
            .unwrap();
    assert_eq!(longer_key.as_bytes().len(), MAX_PUBLIC_KEY_LEN + 1);
    assert!(PublicKey::new(longer_key.as_bytes().to_vec()).is_err());
    let WireMessage::Status(status) = &messages[4] else {
        unreachable!("status slot")
    };
    let mut keyed = Status::clone(status);
    keyed.echo.as_mut().expect("maximal echo").key = longer_key;
    let frame = WireMessage::Status(Box::new(keyed)).encode().unwrap();
    assert!(matches!(
        WireMessage::decode(&frame, frame.len()),
        Err(CodecError::Limit("public key"))
    ));

    // An application partial one byte over the witness capacity: the canonical frame of the full
    // witness is rebuilt with one more witness byte and every enclosing length (variant body,
    // `bytes` field, witness length) advanced by one. The same rebuild without the extra byte
    // reproduces the original frame exactly; with it, the frame decoder refuses the witness.
    let WireMessage::ApplicationControl(_) = &messages[7] else {
        unreachable!("application control slot")
    };
    let frame = messages[7].encode().unwrap();
    let header = norito::core::Header::read(&frame[..norito::core::Header::SIZE]).unwrap();
    let payload = &frame[norito::core::Header::SIZE..];
    let (body_len, body_prefix) = read_leb128(&payload[4..]);
    let body = &payload[4 + body_prefix..];
    assert_eq!(body.len(), body_len, "one variant body");
    let witness_at = body.len() - MAX_CONTROL_WITNESS_BYTES;
    assert!(body[witness_at..].iter().all(|byte| *byte == 3));
    assert_eq!(
        body[witness_at - 8..witness_at],
        u64::try_from(MAX_CONTROL_WITNESS_BYTES)
            .unwrap()
            .to_le_bytes()
    );
    let field = leb128(8 + MAX_CONTROL_WITNESS_BYTES);
    let field_at = witness_at - 8 - field.len();
    assert_eq!(
        body[field_at..witness_at - 8],
        field,
        "the `bytes` field length"
    );
    let rebuild = |witness: usize| {
        let mut body = body[..field_at].to_vec();
        body.extend(leb128(8 + witness));
        body.extend_from_slice(&u64::try_from(witness).unwrap().to_le_bytes());
        body.extend(std::iter::repeat_n(3_u8, witness));
        let mut payload = payload[..4].to_vec();
        payload.extend(leb128(body.len()));
        payload.extend(body);
        norito::core::frame_bare_with_header_flags::<WireMessage>(&payload, header.flags).unwrap()
    };
    assert_eq!(rebuild(MAX_CONTROL_WITNESS_BYTES), frame);
    let over = rebuild(MAX_CONTROL_WITNESS_BYTES + 1);
    assert!(WireMessage::decode(&over, over.len()).is_err());
    assert!(ControlWitness::try_from_slice(&[3; MAX_CONTROL_WITNESS_BYTES + 1]).is_err());
}

/// Norito's compact length: unsigned LEB128.
fn leb128(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let low = u8::try_from(value & 0x7f).unwrap();
        value >>= 7;
        if value == 0 {
            bytes.push(low);
            return bytes;
        }
        bytes.push(low | 0x80);
    }
}

/// The value and byte length of the compact length at the start of `bytes`.
fn read_leb128(bytes: &[u8]) -> (usize, usize) {
    let mut value = 0_usize;
    for (index, byte) in bytes.iter().enumerate() {
        value |= usize::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return (value, index + 1);
        }
    }
    panic!("unterminated compact length")
}
