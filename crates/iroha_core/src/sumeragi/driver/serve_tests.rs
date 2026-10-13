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
        &Served {
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
    s.done(0, &Served::default());
    assert_eq!(s.next(0), Some(blocks(2, 4)));
    s.done(0, &Served::default());
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
        &Served {
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
    s.done(0, &Served::default());
    assert!(s.push(blocks(2, 1), 0));
}
#[test]
fn ready_rows_are_immediate_resource_refusal_has_backoff_and_remote_wait_has_none() {
    let mut s = ServeSched::new(ServeLimits::default());
    s.done(
        5,
        &Served {
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
        &Served {
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
        &Served {
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
        &Served {
            payload: true,
            retry: true,
            refused: true,
            ..Served::default()
        },
    );
    s.done(0, &Served::default());
    assert_eq!(s.wakeup(), 10);
    s.done(
        0,
        &Served {
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
    scheduler.done(0, &Served::default());
    assert_eq!(scheduler.next(0), Some(author));
    scheduler.done(0, &Served::default());
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
        &Served {
            retry_request: Some(original.clone()),
            deferred: Some(owner.clone()),
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
        &Served {
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
    assert_eq!(scheduler.in_flight_refusal, Some(owner));
    scheduler.done(10, &Served::default());
    assert!(scheduler.in_flight_refusal.is_none());
    assert_eq!(scheduler.next(10), Some(other));
}
