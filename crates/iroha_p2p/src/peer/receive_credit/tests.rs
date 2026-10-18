//! Proposed native owner, canonical framing and partial-I/O regressions.
//! These tests have not been compiled or executed during the active source freeze.
use super::*;
use crate::network::admission_class_tests::AdmissionFixture as Fixture;
use iroha_crypto::{Algorithm, KeyPair, encryption::ChaCha20Poly1305};
use iroha_data_model::peer::Peer;
use stream::CreditStream;

type Cipher = ChaCha20Poly1305;
fn key(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap()
}
pub(super) fn peer(seed: u8) -> Peer {
    Peer::new(
        "127.0.0.1:1337".parse().unwrap(),
        key(seed).public_key().clone(),
    )
}
pub(super) fn pool(count: usize) -> Arc<Pool> {
    let frames = InboundFrameByteBudgets::new(256 * 1024, 128 * 1024, 256 * 1024, 2).unwrap();
    assert!(frames.install_protected_sources(HashSet::new()));
    Pool::new(
        frames,
        InboundDispatchByteBudgets::new(256 * 1024, 128 * 1024, 4096).unwrap(),
        count,
        [1024; CLASS_COUNT],
    )
    .unwrap()
}
pub(super) fn used(budget: &SharedByteBudget) -> usize {
    budget.state.lock().unwrap().retained.total
}
pub(super) fn crypto() -> cryptographer::Cryptographer<Cipher> {
    cryptographer::Cryptographer::new_with_raw_key_bytes(&[19; 32]).unwrap()
}
fn request(binding: [u8; 32], class: Class, sequence: u64) -> Header {
    Header::request(binding, class, sequence, 200).unwrap()
}

#[test]
fn credit_geometry_preserves_all_count_and_byte_ceilings() {
    let p = pool(7);
    assert_eq!(p.counts[1..Class::HIGH.len()].iter().sum::<usize>(), 7);
    assert_eq!(p.counts[0], 7);
    assert_eq!(p.counts[Class::HIGH.len()..].iter().sum::<usize>(), 7);
    assert!(p.counts.iter().all(|n| *n > 0));
    assert!(
        p.class_bytes[..Class::HIGH.len()]
            .iter()
            .map(|b| b.max_bytes)
            .sum::<usize>()
            <= p.frames.high.max_bytes
    );
    assert_eq!(
        p.fallback[..Class::HIGH.len()].iter().sum::<usize>() + CONTROL_BYTES,
        p.frames.progress_reserve_bytes_per_peer
    );
    assert!(Pool::new(p.frames.clone(), p.dispatch.clone(), 2, [1024; CLASS_COUNT]).is_err());
    assert!(
        Pool::new(
            p.frames.clone(),
            p.dispatch.clone(),
            7,
            [usize::MAX; CLASS_COUNT]
        )
        .is_err()
    );
}

#[test]
fn private_geometry_exposes_reduced_maximum_and_rejects_unfunded_safety_frames() {
    let p = pool(3);
    let expected = p.fallback[Class::Safety.index()] / 3 - ENVELOPE_BYTES;
    assert_eq!(p.private_maximum(Class::Safety), Some(expected));
    assert!(expected < p.frames.progress_reserve_bytes_per_peer / 3);
    assert_eq!(p.private_maximum(Class::Low), None);
    // Use a new pool so this checks admission, not a changed-cache refusal.
    let frames = InboundFrameByteBudgets::new(2 * 1024 * 1024, 128 * 1024, 256 * 1024, 2).unwrap();
    let dispatch = InboundDispatchByteBudgets::new(2 * 1024 * 1024, 128 * 1024, 4096).unwrap();
    let mut maximum = [1024; CLASS_COUNT];
    maximum[Class::Safety.index()] = 100 * 1024;
    assert!(Pool::new(frames, dispatch, 3, maximum).is_err());
}

#[test]
fn protected_minimum_funds_two_mib_safety_without_raising_p() {
    let high = 128 * 1024 * 1024;
    let private = 17 * 1024 * 1024;
    let frames = InboundFrameByteBudgets::new(high, 64 * 1024 * 1024, private, 97).unwrap();
    let dispatch =
        InboundDispatchByteBudgets::new(high, 64 * 1024 * 1024, 2 * 1024 * 1024).unwrap();
    let maximum = [
        2 * 1024 * 1024,
        17 * 1024 * 1024,
        17 * 1024 * 1024,
        2 * 1024 * 1024,
        17 * 1024 * 1024,
        256 * 1024,
    ];
    let p = Pool::new(frames, dispatch, 8192, maximum).unwrap();
    let writer = writer_partitions(
        maximum,
        OutboundFrameQueueLimits::new_with_progress_reserve(
            high,
            64 * 1024 * 1024,
            private,
            8192,
            4096,
        ),
    )
    .unwrap();
    assert!(
        Class::HIGH
            .into_iter()
            .map(|class| writer[class.index()])
            .sum::<usize>()
            + CONTROL_BYTES
            <= high
    );
    assert!(
        Class::LOW
            .into_iter()
            .map(|class| writer[class.index()])
            .sum::<usize>()
            <= 64 * 1024 * 1024
    );
    assert_eq!(
        p.fallback[..Class::HIGH.len()].iter().sum::<usize>() + CONTROL_BYTES,
        private
    );
    assert!(
        p.private_maximum(Class::Safety).unwrap() >= maximum[Class::Safety.index()],
        "the Safety maximum is fully funded from the private corridor"
    );
}

#[test]
fn credit_pool_cannot_duplicate_partitions_while_guards_are_alive() {
    let p = pool(3);
    let same = Pool::new(p.frames.clone(), p.dispatch.clone(), 3, [1024; CLASS_COUNT]).unwrap();
    assert!(Arc::ptr_eq(&p, &same));
    assert!(Pool::new(p.frames.clone(), p.dispatch.clone(), 4, [1024; CLASS_COUNT]).is_err());
    let foreign = InboundDispatchByteBudgets::new(256 * 1024, 128 * 1024, 4096).unwrap();
    assert!(Pool::new(p.frames.clone(), foreign, 3, [1024; CLASS_COUNT]).is_err());
}

#[test]
fn issued_grant_already_owns_scratch_dispatch_and_exact_count() {
    let p = pool(3);
    let sender = peer(1);
    let mut ledger = Ledger::new(p.bind(sender.id()).unwrap());
    ledger.request(request([1; 32], Class::Payload, 1)).unwrap();
    let grant = ledger.next_grant().unwrap().unwrap();
    let charge = 200 + ENVELOPE_BYTES;
    assert_eq!(used(&p.frames.high), charge);
    assert_eq!(used(&p.frames.high_decode_scratch), charge);
    assert_eq!(used(&p.dispatch.high), charge);
    assert_eq!(
        used(&ledger.source.partition.counts[Class::Payload.index()]),
        1
    );
    assert!(ledger.next_grant().unwrap().is_none());
    let reservation = ledger.consume(&grant.with_kind(Kind::Data)).unwrap();
    assert!(ledger.consume(&grant.with_kind(Kind::Data)).is_err());
    drop(reservation);
    assert_eq!(used(&p.frames.high), 0);
    assert_eq!(used(&p.frames.high_decode_scratch), 0);
    assert_eq!(used(&p.dispatch.high), 0);
}

#[test]
fn failed_multiresource_reservation_releases_every_partial_owner() {
    let p = pool(3);
    let sender = peer(2);
    let source = p.bind(sender.id()).unwrap();
    let scratch = p
        .frames
        .high_decode_scratch
        .try_reserve(p.frames.high_decode_scratch.max_bytes, false)
        .unwrap();
    let private = source.partition.fallback[Class::Payload.index()]
        .try_reserve(p.fallback[Class::Payload.index()], false)
        .unwrap();
    assert!(source.reserve(Class::Payload, 200).is_none());
    assert_eq!(used(&p.frames.high), 0);
    assert_eq!(used(&source.partition.counts[Class::Payload.index()]), 0);
    assert_eq!(used(&p.class_bytes[Class::Payload.index()]), 0);
    drop((scratch, private));
    assert!(source.reserve(Class::Payload, 200).is_some());
}

#[test]
fn private_grant_survives_another_peers_same_class_and_global_scratch_reservations() {
    let maximum = 1024;
    let high = Class::HIGH.len() * (maximum + ENVELOPE_BYTES);
    let frames = InboundFrameByteBudgets::new(high, 8192, 256 * 1024, 2).unwrap();
    assert!(frames.install_protected_sources(HashSet::new()));
    let p = Pool::new(
        frames,
        InboundDispatchByteBudgets::new(high, 8192, 0).unwrap(),
        3,
        [maximum; CLASS_COUNT],
    )
    .unwrap();
    let a = peer(21);
    let b = peer(22);
    let mut first = Ledger::new(p.bind(a.id()).unwrap());
    for class in Class::HIGH {
        first
            .request(Header::request([21; 32], class, 1, maximum).unwrap())
            .unwrap();
        first
            .next_grant()
            .unwrap()
            .expect("A's exact unspent grant");
    }
    // Four genuinely issued, still-unspent grants occupy the complete primary
    // source/scratch/dispatch pools, including the same Safety class.
    assert_eq!(used(&p.frames.high), high);
    assert_eq!(used(&p.frames.high_decode_scratch), high);
    assert_eq!(used(&p.dispatch.high), high);
    let mut second = Ledger::new(p.bind(b.id()).unwrap());
    let before = used(&second.source.reserve);
    second
        .request(Header::request([22; 32], Class::Safety, 1, maximum).unwrap())
        .unwrap();
    let grant = second
        .next_grant()
        .unwrap()
        .expect("B has its own fully funded fallback");
    let reservation = second.consume(&grant.with_kind(Kind::Data)).unwrap();
    assert!(reservation.retention.class_bytes.is_none());
    assert_eq!(
        used(&second.source.reserve) - before,
        3 * (maximum + ENVELOPE_BYTES)
    );
    assert_eq!(used(&p.frames.high_decode_scratch), high);
    drop(reservation);
    assert_eq!(used(&second.source.reserve), before);
    drop((first, second));
    assert_eq!(used(&p.frames.high), 0);
    assert_eq!(used(&p.frames.high_decode_scratch), 0);
    assert_eq!(used(&p.dispatch.high), 0);
}

#[test]
fn replacement_control_owner_requires_old_reader_close_but_not_delivered_drain() {
    let p = pool(3);
    let sender = peer(23);
    let source = p.bind(sender.id()).unwrap();
    assert!(p.bind(sender.id()).is_err());
    let delivered = source.reserve(Class::Payload, 200).unwrap().delivered(
        sender.clone(),
        Fixture::Payload(1),
        77,
    );
    drop(source);
    let successor = p.bind(sender.id()).unwrap();
    assert!(successor.reserve(Class::Payload, 200).is_none());
    drop(delivered);
    assert!(successor.reserve(Class::Payload, 200).is_some());
}

#[test]
fn ordinary_count_saturation_does_not_consume_other_class_or_safety_grants() {
    let p = pool(3);
    let sender = peer(3);
    let source = p.bind(sender.id()).unwrap();
    let bulk = source.reserve(Class::Payload, 200).unwrap();
    assert!(source.reserve(Class::Payload, 200).is_none());
    let lane = source.reserve(Class::Lane, 200).unwrap();
    let control = source.reserve(Class::Control, 200).unwrap();
    let safety = source.reserve(Class::Safety, 200).unwrap();
    let low = source.reserve(Class::Low, 200).unwrap();
    drop((lane, control, safety, low));
    assert!(source.reserve(Class::Payload, 200).is_none());
    drop(bulk);
    assert!(source.reserve(Class::Payload, 200).is_some());
}

#[test]
fn dropping_tenure_reclaims_only_unspent_grants_not_delivered_owners() {
    let p = pool(3);
    let sender = peer(4);
    let source = p.bind(sender.id()).unwrap();
    let partition = Arc::downgrade(&source.partition);
    let mut ledger = Ledger::new(source);
    ledger.request(request([4; 32], Class::Payload, 1)).unwrap();
    ledger.request(request([4; 32], Class::Control, 1)).unwrap();
    let first = ledger.next_grant().unwrap().unwrap();
    assert_eq!(first.class().unwrap(), Class::Payload);
    ledger.next_grant().unwrap().unwrap(); // retained, never consumed
    let held = ledger
        .consume(&first.with_kind(Kind::Data))
        .unwrap()
        .delivered(sender.clone(), Fixture::Payload(3), 12);
    assert_eq!(used(&p.frames.high_decode_scratch), 200 + ENVELOPE_BYTES);
    drop(ledger);
    assert_eq!(used(&p.frames.high_decode_scratch), 0);
    let replacement = p.bind(sender.id()).unwrap();
    assert!(Arc::ptr_eq(
        &replacement.partition,
        &partition.upgrade().unwrap()
    ));
    assert!(replacement.reserve(Class::Payload, 200).is_none());
    assert!(replacement.reserve(Class::Control, 200).is_some());
    assert!(held.try_clone_retained().is_none());
    let (_, _, _, _, guard) = held.into_parts();
    assert!(replacement.reserve(Class::Payload, 200).is_none());
    drop(guard);
    assert!(replacement.reserve(Class::Payload, 200).is_some());
}

#[test]
fn canonical_record_rejects_substitution_replay_and_extra_inner_frame() {
    let cipher = crypto();
    let header = Header::request([8; 32], Class::Control, 1, 3)
        .unwrap()
        .with_kind(Kind::Data);
    let (encoded, mut encrypted) = record::seal(&cipher, &header, b"abc").unwrap();
    assert_eq!(Header::decode(&encoded).unwrap(), header);
    let altered = Header::request([8; 32], Class::Payload, 1, 3)
        .unwrap()
        .with_kind(Kind::Data)
        .bytes()
        .unwrap();
    assert!(record::open(&cipher, &altered, &mut encrypted.clone()).is_err());
    assert_eq!(
        record::open(&cipher, &encoded, &mut encrypted).unwrap(),
        b"abc"
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(Header::decode(&trailing).is_err());
    assert!(Header::decode(&vec![0; record::HEADER_CAP + 1]).is_err());
    let p = pool(3);
    let sender = peer(5);
    let mut ledger = Ledger::new(p.bind(sender.id()).unwrap());
    let original = request([8; 32], Class::Control, 1);
    ledger.request(original).unwrap();
    assert!(ledger.request(original).is_err());
    let grant = ledger.next_grant().unwrap().unwrap();
    assert!(
        ledger
            .consume(&request([9; 32], Class::Control, 1).with_kind(Kind::Data))
            .is_err()
    );
    assert!(
        ledger
            .consume(&request([8; 32], Class::Control, 2).with_kind(Kind::Data))
            .is_err()
    );
    drop(ledger.consume(&grant.with_kind(Kind::Data)).unwrap());
    assert!(ledger.request(original).is_err());
    let value = Fixture::Control(7);
    let mut wire = Vec::new();
    run::receive_credit_encode(&value, &mut wire).unwrap();
    let caps = crate::network::TopicFrameCaps::uniform(1024);
    assert!(run::receive_credit_decode::<Fixture>(&wire, Class::Control, caps).is_ok());
    assert!(run::receive_credit_decode::<Fixture>(&wire, Class::Payload, caps).is_err());
    let original = wire.clone();
    wire.extend_from_slice(&original);
    assert!(run::receive_credit_decode::<Fixture>(&wire, Class::Control, caps).is_err());
}

#[test]
fn full_session_binding_is_directional_and_rejects_foreign_transport_or_geometry() {
    let local = peer(6);
    let remote = peer(7);
    let network = test_network_id("credit binding");
    let left = record::Binding::verified(
        &network,
        local.id(),
        remote.id(),
        [3; 32],
        [4; 32],
        [5; 32],
        [6; 32],
    )
    .unwrap();
    let right = record::Binding::verified(
        &network,
        remote.id(),
        local.id(),
        [3; 32],
        [4; 32],
        [6; 32],
        [5; 32],
    )
    .unwrap();
    assert_eq!(left.outgoing, right.incoming);
    assert_ne!(left.outgoing, left.incoming);
    let changed = record::Binding::verified(
        &network,
        local.id(),
        remote.id(),
        [3; 32],
        [9; 32],
        [5; 32],
        [6; 32],
    )
    .unwrap();
    let header = request(left.outgoing, Class::Lane, 1);
    assert!(header.check(&changed.outgoing).is_err());
    let changed = record::Binding::verified(
        &network,
        local.id(),
        remote.id(),
        [3; 32],
        [4; 32],
        [5; 32],
        [7; 32],
    )
    .unwrap();
    assert!(header.check(&changed.outgoing).is_err());
    assert!(
        record::Binding::verified(
            &network,
            local.id(),
            local.id(),
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32]
        )
        .is_err()
    );
}

pub(super) fn post(value: Fixture) -> (RetainedPost<Fixture>, oneshot::Receiver<()>) {
    let budget = SharedByteBudget::new(4096, 0).unwrap();
    let (sender, receiver) = oneshot::channel();
    (
        RetainedPost::new(
            value,
            OutboundPostOwnership::new(budget.try_reserve(2048, false).unwrap(), Some(sender)),
        ),
        receiver,
    )
}
fn enqueue(stream: &mut CreditStream<Cipher, Fixture>, value: Fixture) -> oneshot::Receiver<()> {
    let (post, receiver) = post(value);
    assert!(stream.enqueue(post).is_ok());
    receiver
}

#[tokio::test(start_paused = true)]
async fn real_partial_duplex_grants_other_classes_past_blocked_body_then_services_body() {
    let a = peer(10);
    let b = peer(11);
    let pa = pool(3);
    let pb = pool(3);
    let cipher = crypto();
    let network = test_network_id("partial duplex credits");
    let ba = record::Binding::verified(
        &network,
        a.id(),
        b.id(),
        cipher.session_binding,
        [12; 32],
        pa.geometry,
        pb.geometry,
    )
    .unwrap();
    let bb = record::Binding::verified(
        &network,
        b.id(),
        a.id(),
        cipher.session_binding,
        [12; 32],
        pb.geometry,
        pa.geometry,
    )
    .unwrap();
    let (io_a, io_b) = tokio::io::duplex(7); // force prefix/header/payload partial writes
    let (ra, wa) = tokio::io::split(io_a);
    let (rb, wb) = tokio::io::split(io_b);
    let limits = OutboundFrameQueueLimits::new_with_progress_reserve(
        256 * 1024,
        128 * 1024,
        256 * 1024,
        32,
        32,
    );
    let caps = crate::network::TopicFrameCaps::uniform(1024);
    let mut sa = CreditStream::<Cipher, Fixture>::new(
        negotiation::OwnedTransport {
            read: Box::new(ra),
            write: Box::new(wa),
            source: pa.bind(b.id()).unwrap(),
        },
        ba,
        cipher.clone(),
        b,
        100,
        stream::CreditStreamConfig {
            caps,
            maximum: [1024; CLASS_COUNT],
            limits,
            idle_timeout: Duration::from_secs(20),
        },
    )
    .unwrap();
    let mut sb = CreditStream::<Cipher, Fixture>::new(
        negotiation::OwnedTransport {
            read: Box::new(rb),
            write: Box::new(wb),
            source: pb.bind(a.id()).unwrap(),
        },
        bb,
        cipher,
        a,
        101,
        stream::CreditStreamConfig {
            caps,
            maximum: [1024; CLASS_COUNT],
            limits,
            idle_timeout: Duration::from_secs(20),
        },
    )
    .unwrap();
    let mut first_ack = enqueue(&mut sa, Fixture::Payload(1));
    let first = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                a = sa.step() => { assert!(a.unwrap().is_none()); },
                b = sb.step() => { if let Some(value) = b.unwrap() { break value; } }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(first.payload.admission_class(), Class::Payload);
    // Flush ownership may complete after the receiver sees the final bytes.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match first_ack.try_recv() {
                Ok(()) => break,
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    panic!("post owner closed without flush")
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
            }
            tokio::select! { a = sa.step() => { a.unwrap(); }, b = sb.step() => { b.unwrap(); } }
        }
    })
    .await
    .unwrap();
    let _bulk_ack = enqueue(&mut sa, Fixture::Payload(2));
    let _lane_ack = enqueue(&mut sa, Fixture::Lane(3));
    let _control_ack = enqueue(&mut sa, Fixture::Control(4));
    let _safety_ack = enqueue(&mut sa, Fixture::Safety(5));
    let _block_sync_ack = enqueue(&mut sa, Fixture::BlockSync(6));
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while received.len() < 4 {
            tokio::select! {
                a = sa.step() => { a.unwrap(); },
                b = sb.step() => { if let Some(value) = b.unwrap() { received.push(value); } }
            }
        }
    })
    .await
    .unwrap();
    assert!(
        received
            .iter()
            .any(|p| p.payload.admission_class() == Class::Lane)
    );
    assert!(
        received
            .iter()
            .any(|p| p.payload.admission_class() == Class::Control)
    );
    assert!(
        received
            .iter()
            .all(|p| p.payload.admission_class() != Class::Payload)
    );
    assert!(
        received
            .iter()
            .any(|p| p.payload.admission_class() == Class::Safety)
    );
    assert!(
        received
            .iter()
            .any(|p| p.payload.admission_class() == Class::BlockSync)
    );
    assert!(
        used(&pb.frames.low) > 0,
        "BlockSync remains charged to low bytes"
    );
    // Probes use fixed authenticated transport cells while application Bulk
    // remains blocked. Neither local writes nor partial reads count as liveness.
    // Both production endpoints probe every idle_timeout / 2. Repeating past
    // the initial burst must not charge solicited Pongs to remote Ping credit.
    for _ in 0..4 {
        tokio::time::advance(Duration::from_secs(10)).await;
        sa.request_ping().unwrap();
        sb.request_ping().unwrap();
        let before_a = sa.authenticated_records();
        let before_b = sb.authenticated_records();
        tokio::time::timeout(Duration::from_secs(5), async {
            while sa.probe_pending() || sb.probe_pending() {
                tokio::select! {
                    a = sa.step() => { assert!(a.unwrap().is_none()); },
                    b = sb.step() => { assert!(b.unwrap().is_none()); }
                }
            }
        })
        .await
        .unwrap();
        assert!(sa.authenticated_records() >= before_a + 2);
        assert!(sb.authenticated_records() >= before_b + 2);
    }
    assert_eq!(
        used(&pb.frames.high_decode_scratch),
        0,
        "no scratch granted to blocked second Bulk"
    );
    drop(first); // real retained source/count/dispatch ownership, not a fake flag
    let next = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                a = sa.step() => { a.unwrap(); },
                b = sb.step() => { if let Some(value) = b.unwrap() { break value; } }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(next.payload.admission_class(), Class::Payload);
    assert!(used(&pb.frames.high) <= pb.frames.high.max_bytes);
    assert!(used(&pb.dispatch.high) <= pb.dispatch.high.max_bytes);
    drop((received, next, sa, sb));
    assert_eq!(used(&pb.frames.high), 0);
    assert_eq!(used(&pb.dispatch.high), 0);
}

#[test]
fn mandatory_writer_geometry_rejects_unfunded_bytes_counts_and_overflow() {
    let limits = OutboundFrameQueueLimits::new_with_progress_reserve(
        256 * 1024,
        128 * 1024,
        256 * 1024,
        32,
        32,
    );
    let bytes = writer_partitions([1024; CLASS_COUNT], limits).unwrap();
    assert_eq!(bytes, [2 * 1024 + ENVELOPE_BYTES; CLASS_COUNT]);
    let mut bad = limits;
    bad.high_max_bytes = CONTROL_BYTES;
    assert!(writer_partitions([1024; CLASS_COUNT], bad).is_err());
    let mut bad = limits;
    bad.low_max_bytes = bytes[Class::BlockSync.index()] - 1;
    assert!(writer_partitions([1024; CLASS_COUNT], bad).is_err());
    let mut bad = limits;
    bad.high_max_frames = Class::HIGH.len() - 1;
    assert!(writer_partitions([1024; CLASS_COUNT], bad).is_err());
    let mut bad = limits;
    bad.low_max_frames = Class::LOW.len() - 1;
    assert!(writer_partitions([1024; CLASS_COUNT], bad).is_err());
    assert!(writer_partitions([usize::MAX; CLASS_COUNT], limits).is_err());
    assert!(writer_partitions([0; CLASS_COUNT], limits).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn grant_release_wakes_streams_only_while_one_waits_for_capacity() {
    use std::future::Future as _;
    use std::task::{Context, Poll};
    let p = pool(3);
    let source = p.bind(peer(91).id()).unwrap();
    let poll_once = |notified: &mut std::pin::Pin<&mut tokio::sync::futures::Notified<'_>>| {
        let mut context = Context::from_waker(std::task::Waker::noop());
        notified.as_mut().poll(&mut context)
    };
    // Nobody waits: a release must not wake the registered notification.
    let idle = p.changed.notified();
    tokio::pin!(idle);
    idle.as_mut().enable();
    drop(source.reserve(Class::Lane, 200).expect("free capacity"));
    assert_eq!(p.blocked.load(Ordering::SeqCst), 0);
    assert!(
        matches!(poll_once(&mut idle), Poll::Pending),
        "an idle pool release must not wake every peer task"
    );
    // A registered waiter is woken by the next release.
    let waiting = p.changed.notified();
    tokio::pin!(waiting);
    let registration = BlockedOnRelease::register(&p);
    waiting.as_mut().enable();
    drop(source.reserve(Class::Lane, 200).expect("free capacity"));
    assert!(
        matches!(poll_once(&mut waiting), Poll::Ready(())),
        "released capacity must wake a stream waiting for a grant"
    );
    drop(registration);
    assert_eq!(p.blocked.load(Ordering::SeqCst), 0);
}

#[test]
fn sealed_record_is_one_buffer_with_the_canonical_wire_layout() {
    let cipher = crypto();
    let header = Header::request([7; 32], Class::Lane, 1, 3)
        .unwrap()
        .with_kind(Kind::Data);
    let record = record::seal_record(&cipher, &header, b"abc").unwrap();
    let header_bytes = header.bytes().unwrap();
    assert_eq!(
        record[..4],
        u32::try_from(header_bytes.len()).unwrap().to_be_bytes()
    );
    assert_eq!(&record[4..4 + header_bytes.len()], header_bytes.as_slice());
    let mut sealed = record[4 + header_bytes.len()..].to_vec();
    assert_eq!(
        sealed.len(),
        record::encrypted_len::<Cipher>(3).unwrap(),
        "nothing but the sealed body follows the header"
    );
    assert_eq!(
        record::open(&cipher, &header_bytes, &mut sealed).unwrap(),
        b"abc"
    );
    let mut tampered = record[4 + header_bytes.len()..].to_vec();
    let altered = header.with_kind(Kind::Grant).bytes().unwrap();
    assert!(
        record::open(&cipher, &altered, &mut tampered).is_err(),
        "the header remains authenticated as AAD"
    );
    assert!(
        record::seal_record(&cipher, &header.with_kind(Kind::Request), b"x").is_err(),
        "control records carry only an authenticated empty body"
    );
    assert!(record::seal_record(&cipher, &header, b"ab").is_err());
}

#[test]
fn reader_places_every_sealed_body_for_aligned_in_place_decoding() {
    let buffer = vec![0_u8; 512];
    for align in [1_usize, 2, 4, 8, 16, 32, 64] {
        for nonce in [0_usize, 12, 24] {
            for skew in 0..8 {
                let slice = &buffer[skew..];
                let start = stream::aligned_body_start(slice, nonce, align);
                assert!(start < align);
                assert_eq!(
                    (slice.as_ptr() as usize + start + nonce) % align,
                    0,
                    "the decrypted payload starts at an aligned address"
                );
            }
        }
    }
}
