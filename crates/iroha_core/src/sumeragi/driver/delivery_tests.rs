//! Exact-row and transport-occurrence retention under deterministic rank-one pressure.
use super::*;
use crate::sumeragi::driver::payload_worker_tests::Fixture;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct State {
    credit: BTreeMap<PublicKey, bool>,
    accepted: Vec<(PublicKey, Frame)>,
    attempts: usize,
    retries: usize,
    dropped_pending: usize,
}
#[derive(Clone, Default)]
struct RankOne(Arc<Mutex<State>>);
struct Pending {
    state: Arc<Mutex<State>>,
    peer: PublicKey,
    frame: Frame,
    active: bool,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if self.active {
            self.state.lock().unwrap().dropped_pending += 1;
        }
    }
}
impl PendingSend for Pending {
    fn retry(mut self: Box<Self>) -> SendOutcome {
        let admitted = {
            let mut s = self.state.lock().unwrap();
            s.retries += 1;
            if s.credit.get(&self.peer).copied().unwrap_or(false) {
                s.credit.insert(self.peer.clone(), false);
                s.accepted.push((self.peer.clone(), self.frame.clone()));
                true
            } else {
                false
            }
        };
        if admitted {
            self.active = false;
            SendOutcome::Admitted
        } else {
            SendOutcome::Backpressured(self)
        }
    }
}
impl Net for RankOne {
    fn send(&self, to: &PublicKey, frame: &Frame) -> SendOutcome {
        let mut s = self.0.lock().unwrap();
        s.attempts += 1;
        if s.credit.get(to).copied().unwrap_or(false) {
            s.credit.insert(to.clone(), false);
            s.accepted.push((to.clone(), frame.clone()));
            SendOutcome::Admitted
        } else {
            SendOutcome::Backpressured(Box::new(Pending {
                state: self.0.clone(),
                peer: to.clone(),
                frame: frame.clone(),
                active: true,
            }))
        }
    }
}
impl RankOne {
    fn release(&self, peer: &PublicKey) {
        self.0.lock().unwrap().credit.insert(peer.clone(), true);
    }
}
fn poll(f: &Fixture, worker: &mut PayloadWorker, net: &dyn Net, work: PayloadWork) -> Served {
    serve(
        ServeRequest::Payload(Box::new(work)),
        f.source.instance(),
        &f.bodies,
        &f.blocks,
        net,
        worker,
    )
    .unwrap()
}

#[test]
fn rank_one_admission_retains_all_six_actual_rows_and_reconstructs() {
    let f = Fixture::new();
    let to = f.signers[1].public_key().clone();
    let net = RankOne::default();
    net.release(&to);
    let mut sender = f.worker();
    let mut p = poll(&f, &mut sender, &net, f.disseminate());
    assert!(p.retry);
    p = poll(&f, &mut sender, &net, PayloadWork::Poll);
    for _ in 0..32 {
        if !p.retry {
            break;
        }
        net.release(&to);
        p = poll(&f, &mut sender, &net, PayloadWork::Poll);
    }
    assert!(
        !p.retry,
        "all rows eventually admit after individual ticket releases"
    );
    let state = net.0.lock().unwrap();
    let decoded: Vec<_> = state
        .accepted
        .iter()
        .map(|(_, frame)| WireMessage::decode(&frame.bytes, usize::MAX).unwrap())
        .collect();
    let indices: Vec<_> = decoded
        .iter()
        .filter_map(|m| {
            if let WireMessage::PayloadChunk(c) = m {
                Some(c.index)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        indices,
        vec![0, 1, 2, 3, 4, 5],
        "backpressure cannot consume the outgoing stream"
    );
    assert_eq!(
        state.attempts, 7,
        "one original post per manifest/row; retries use their original receipt"
    );
    assert!(state.retries > 0);
    assert_eq!(state.dropped_pending, 0);
    drop(state);
    let mut receiver = f.worker();
    let mut events = Vec::new();
    for mut message in decoded {
        message.admit_owned_bytes(&f.budget).unwrap();
        let work = match message {
            WireMessage::PayloadManifest(manifest) => PayloadWork::Acquire {
                source: f.source.clone(),
                manifest,
            },
            WireMessage::PayloadChunk(chunk) => PayloadWork::Chunk {
                from: f.signers[0].public_key().clone(),
                chunk,
            },
            _ => panic!("unexpected availability output"),
        };
        events.extend(f.poll(&mut receiver, work).events);
    }
    assert!(matches!(events.as_slice(), [Event::BodyAvailable { block }] if block == &f.body));
}

#[test]
fn blocked_peer_preserves_exact_frame_and_does_not_block_other_recipient() {
    let f = Fixture::new();
    let a = f.signers[1].public_key().clone();
    let b = f.signers[2].public_key().clone();
    let net = RankOne::default();
    net.release(&b);
    let msg = WireMessage::PayloadRequest(iroha_sumeragi::message::PayloadRequest {
        instance: f.source.instance(),
        height: 1,
        block_hash: f.source.block_hash(),
    });
    let frame = frame(&msg).unwrap();
    let pointer = frame.bytes.as_ptr();
    let bytes = frame.bytes.len() as u64;
    let mut batch = DeliveryBatch::new(
        vec![(vec![a.clone(), b.clone()], frame)],
        &[a.clone(), b.clone()],
    )
    .unwrap();
    assert_eq!(batch.poll(&net).unwrap(), vec![(b.clone(), bytes)]);
    assert!(!batch.complete());
    assert_eq!(batch.poll(&net).unwrap(), vec![]);
    net.release(&a);
    assert_eq!(batch.poll(&net).unwrap(), vec![(a, bytes)]);
    assert!(batch.complete());
    let s = net.0.lock().unwrap();
    assert_eq!(s.attempts, 2);
    assert_eq!(s.dropped_pending, 0);
    assert!(s.accepted.iter().all(|(_, f)| f.bytes.as_ptr() == pointer));
}

#[test]
fn metadata_retry_charges_once_only_after_original_receipt_admits() {
    let f = Fixture::new();
    let to = f.signers[1].public_key().clone();
    let net = RankOne::default();
    let mut worker = f.worker();
    let request = ServeRequest::Blocks {
        to: to.clone(),
        from_height: 1,
        max_count: 1,
        max_bytes: 4096,
    };
    let first = serve(
        request,
        f.source.instance(),
        &f.bodies,
        &f.blocks,
        &net,
        &mut worker,
    )
    .unwrap();
    assert!(first.retry && first.refused && first.charges.is_empty());
    let again = poll(&f, &mut worker, &net, PayloadWork::Poll);
    assert!(again.charges.is_empty());
    net.release(&to);
    let done = poll(&f, &mut worker, &net, PayloadWork::Poll);
    let s = net.0.lock().unwrap();
    assert_eq!(s.accepted.len(), 1);
    assert_eq!(s.attempts, 1);
    assert_eq!(s.dropped_pending, 0);
    assert_eq!(done.charges, vec![(to, s.accepted[0].1.bytes.len() as u64)]);
    assert!(!done.retry);
}

#[test]
fn blocked_output_still_allows_original_author_completion() {
    let f = Fixture::new();
    let net = RankOne::default();
    let mut worker = f.worker();
    let first = poll(&f, &mut worker, &net, f.disseminate());
    assert!(first.retry && first.refused);
    let mut header = f.body.header().clone();
    header.availability_digest = Hash32::ZERO;
    let done = poll(
        &f,
        &mut worker,
        &net,
        PayloadWork::Author {
            req: 999,
            config: f.source.config().clone(),
            header,
            payload: f.body.payload().clone(),
        },
    );
    assert!(
        matches!(done.events.as_slice(),[Event::PayloadAuthored { req:999,body }] if body == &f.body)
    );
    assert_eq!(
        net.0.lock().unwrap().attempts,
        1,
        "pending manifest remains the only original post"
    );
}

#[test]
fn terminal_transport_outcomes_fail_without_fabricated_admission() {
    struct Terminal(bool);
    impl Net for Terminal {
        fn send(&self, _: &PublicKey, _: &Frame) -> SendOutcome {
            if self.0 {
                SendOutcome::Closed
            } else {
                SendOutcome::Rejected
            }
        }
    }
    for closed in [true, false] {
        let f = Fixture::new();
        let mut worker = f.worker();
        let error = serve(
            ServeRequest::Payload(Box::new(f.disseminate())),
            f.source.instance(),
            &f.bodies,
            &f.blocks,
            &Terminal(closed),
            &mut worker,
        )
        .expect_err("terminal send error");
        assert_eq!(
            error.kind(),
            if closed {
                io::ErrorKind::BrokenPipe
            } else {
                io::ErrorKind::InvalidData
            }
        );
    }
}

#[test]
fn metadata_turn_preserves_the_active_stream_poll() {
    struct Admit;
    impl Net for Admit {
        fn send(&self, _: &PublicKey, _: &Frame) -> SendOutcome {
            SendOutcome::Admitted
        }
    }
    let f = Fixture::new();
    let mut worker = f.worker();
    let first = poll(&f, &mut worker, &Admit, f.disseminate());
    assert!(first.retry);
    let metadata = serve(
        ServeRequest::Blocks {
            to: f.signers[1].public_key().clone(),
            from_height: 1,
            max_count: 1,
            max_bytes: 4096,
        },
        f.source.instance(),
        &f.bodies,
        &f.blocks,
        &Admit,
        &mut worker,
    )
    .unwrap();
    assert!(
        metadata.retry,
        "metadata response must not erase the pending stream wakeup"
    );
    let mut scheduler = ServeSched::new(ServeLimits::default());
    scheduler.done(12, metadata);
    assert_eq!(scheduler.wakeup(), 12);
}

#[test]
fn forever_blocked_recipient_cannot_stop_all_six_rows_to_healthy_peer() {
    let f = Fixture::new();
    let blocked = f.signers[1].public_key().clone();
    let healthy = f.signers[2].public_key().clone();
    let net = RankOne::default();
    let mut worker = f.worker();
    net.release(&healthy);
    poll(
        &f,
        &mut worker,
        &net,
        PayloadWork::Disseminate {
            peers: vec![blocked.clone(), healthy.clone()],
            body: f.body.clone(),
        },
    );
    for _ in 0..40 {
        net.release(&healthy);
        poll(&f, &mut worker, &net, PayloadWork::Poll);
    }
    let s = net.0.lock().unwrap();
    assert!(s.accepted.iter().all(|(peer, _)| peer == &healthy));
    let rows: Vec<_> = s
        .accepted
        .iter()
        .filter_map(
            |(_, frame)| match WireMessage::decode(&frame.bytes, usize::MAX).unwrap() {
                WireMessage::PayloadChunk(row) => Some(row.index),
                _ => None,
            },
        )
        .collect();
    assert_eq!(rows, vec![0, 1, 2, 3, 4, 5]);
    assert_eq!(
        s.attempts, 8,
        "one blocked manifest plus seven healthy frames"
    );
    assert_eq!(
        s.dropped_pending, 0,
        "forever-pressured original receipt remains owned"
    );
}

#[test]
fn aligned_recipients_share_exact_encoded_rows() {
    let f = Fixture::new();
    let a = f.signers[1].public_key().clone();
    let b = f.signers[2].public_key().clone();
    let net = RankOne::default();
    let mut worker = f.worker();
    net.release(&a);
    net.release(&b);
    let mut result = poll(
        &f,
        &mut worker,
        &net,
        PayloadWork::Disseminate {
            peers: vec![a.clone(), b.clone()],
            body: f.body.clone(),
        },
    );
    for _ in 0..40 {
        if !result.retry {
            break;
        }
        net.release(&a);
        net.release(&b);
        result = poll(&f, &mut worker, &net, PayloadWork::Poll);
    }
    assert!(!result.retry);
    let s = net.0.lock().unwrap();
    let left: Vec<_> = s
        .accepted
        .iter()
        .filter(|(peer, _)| peer == &a)
        .map(|(_, f)| f)
        .collect();
    let right: Vec<_> = s
        .accepted
        .iter()
        .filter(|(peer, _)| peer == &b)
        .map(|(_, f)| f)
        .collect();
    assert_eq!(left.len(), 7);
    assert_eq!(right.len(), 7);
    for (l, r) in left.iter().zip(right) {
        assert!(Arc::ptr_eq(&l.bytes, &r.bytes));
    }
}

fn authored(f: &Fixture, height: u64, view: u64) -> iroha_sumeragi::availability::AvailableBody {
    let mut header = f.body.header().clone();
    header.height = height;
    header.origin_view = view;
    header.availability_digest = Hash32::ZERO;
    iroha_sumeragi::availability::PayloadAuthoring::new(header, f.body.payload().clone())
        .complete(
            f.source.instance(),
            f.source.config(),
            &f.budget,
            &crate::sumeragi::crypto::BlsCrypto::new(),
            &*f.signers[0],
        )
        .unwrap_or_else(|_| panic!("real signed available fixture"))
        .body
}
fn six_rows_for(net: &RankOne, peer: &PublicKey, hash: Hash32) -> bool {
    let state = net.0.lock().unwrap();
    let rows: Vec<_> = state
        .accepted
        .iter()
        .filter(|(to, _)| to == peer)
        .filter_map(
            |(_, frame)| match WireMessage::decode(&frame.bytes, usize::MAX).unwrap() {
                WireMessage::PayloadChunk(row) if row.block_hash == hash => Some(row.index),
                _ => None,
            },
        )
        .collect();
    rows == [0, 1, 2, 3, 4, 5]
}
#[test]
fn applied_rounds_retire_blocked_proactive_receipts() {
    let f = Fixture::new();
    let blocked = f.signers[1].public_key().clone();
    let healthy = f.signers[2].public_key().clone();
    let net = RankOne::default();
    let mut worker = f.worker();
    for height in 1..=8 {
        let body = authored(&f, height, 0);
        let hash = body.source().block_hash();
        net.release(&healthy);
        poll(
            &f,
            &mut worker,
            &net,
            PayloadWork::Disseminate {
                peers: vec![blocked.clone(), healthy.clone()],
                body: body.clone(),
            },
        );
        for _ in 0..40 {
            net.release(&healthy);
            poll(&f, &mut worker, &net, PayloadWork::Poll);
        }
        assert!(six_rows_for(&net, &healthy, hash));
        let applied = poll(&f, &mut worker, &net, PayloadWork::Applied(height));
        assert!(
            !applied.retry,
            "applied proactive occurrence must release its blocked receipt"
        );
        let stale = poll(
            &f,
            &mut worker,
            &net,
            PayloadWork::Disseminate {
                peers: vec![blocked.clone(), healthy.clone()],
                body,
            },
        );
        assert!(
            !stale.retry,
            "a delayed old proactive command cannot revive an applied stream"
        );
    }
    assert_eq!(net.0.lock().unwrap().dropped_pending, 8);
}
#[test]
fn bounded_failed_view_cache_keeps_new_authorized_streams_live() {
    let f = Fixture::new();
    let blocked = f.signers[1].public_key().clone();
    let healthy = f.signers[2].public_key().clone();
    let net = RankOne::default();
    let mut worker = f.worker();
    for view in 0..8 {
        let body = authored(&f, 1, view);
        let hash = body.source().block_hash();
        net.release(&healthy);
        poll(
            &f,
            &mut worker,
            &net,
            PayloadWork::Disseminate {
                peers: vec![blocked.clone(), healthy.clone()],
                body,
            },
        );
        for _ in 0..100 {
            net.release(&healthy);
            poll(&f, &mut worker, &net, PayloadWork::Poll);
        }
        assert!(
            six_rows_for(&net, &healthy, hash),
            "old blocked views cannot reject every newer stream"
        );
    }
    assert_eq!(
        net.0.lock().unwrap().dropped_pending,
        4,
        "only oldest bounded occurrences were cancelled"
    );
}
#[test]
fn historical_pressure_is_deduplicated_and_cannot_take_proactive_capacity() {
    let f = Fixture::new();
    f.bodies.put(&f.source.block_hash(), &f.body).unwrap();
    let blocked = f.signers[1].public_key().clone();
    let healthy = f.signers[2].public_key().clone();
    let net = RankOne::default();
    let mut worker = PayloadWorker::new(
        f.source.instance(),
        f.budget.clone(),
        Arc::new(crate::sumeragi::crypto::BlsCrypto::new()),
        vec![f.signers[0].clone()],
        1,
        0,
    );
    for _ in 0..12 {
        poll(
            &f,
            &mut worker,
            &net,
            PayloadWork::Serve {
                to: blocked.clone(),
                height: 1,
                block_hash: f.source.block_hash(),
            },
        );
    }
    assert_eq!(
        net.0.lock().unwrap().attempts,
        1,
        "same historical request retains its original receipt"
    );
    net.release(&healthy);
    poll(
        &f,
        &mut worker,
        &net,
        PayloadWork::Disseminate {
            peers: vec![healthy.clone()],
            body: f.body.clone(),
        },
    );
    for _ in 0..20 {
        net.release(&healthy);
        poll(&f, &mut worker, &net, PayloadWork::Poll);
    }
    assert!(six_rows_for(&net, &healthy, f.source.block_hash()));
    assert_eq!(
        net.0.lock().unwrap().dropped_pending,
        0,
        "historical receipt keeps its independent bounded slot"
    );
}
#[test]
fn blocked_metadata_and_fetch_do_not_gate_an_independent_healthy_fetch() {
    let f = Fixture::new();
    let blocked = f.signers[1].public_key().clone();
    let healthy = f.signers[2].public_key().clone();
    let net = RankOne::default();
    let mut worker = f.worker();
    serve(
        ServeRequest::Blocks {
            to: blocked.clone(),
            from_height: 1,
            max_count: 1,
            max_bytes: 4096,
        },
        f.source.instance(),
        &f.bodies,
        &f.blocks,
        &net,
        &mut worker,
    )
    .unwrap();
    poll(
        &f,
        &mut worker,
        &net,
        PayloadWork::Fetch {
            source: f.source.clone(),
            peers: vec![blocked.clone()],
        },
    );
    for _ in 0..8 {
        poll(&f, &mut worker, &net, PayloadWork::Poll);
    }
    let source = iroha_sumeragi::availability::AvailabilitySource::new(
        f.source.instance(),
        2,
        Hash32([77; 32]),
        f.source.config().clone(),
    )
    .unwrap();
    net.release(&healthy);
    poll(
        &f,
        &mut worker,
        &net,
        PayloadWork::Fetch {
            source: source.clone(),
            peers: vec![healthy.clone()],
        },
    );
    for _ in 0..20 {
        net.release(&healthy);
        poll(&f, &mut worker, &net, PayloadWork::Poll);
    }
    let state = net.0.lock().unwrap();
    assert!(state.accepted.iter().any(|(peer,frame)|peer==&healthy && matches!(WireMessage::decode(&frame.bytes,usize::MAX).unwrap(),WireMessage::PayloadRequest(r) if r.block_hash==source.block_hash())));
    assert_eq!(
        state.attempts, 3,
        "metadata, first source and second source retain separate original occurrences"
    );
    drop(state);
    poll(&f, &mut worker, &net, PayloadWork::Applied(1));
    assert_eq!(
        net.0.lock().unwrap().dropped_pending,
        1,
        "obsolete fetch cancels; independent historical metadata remains bounded"
    );
}

#[test]
fn completed_historical_stream_can_be_requested_again_with_original_signatures() {
    let f = Fixture::new();
    f.bodies.put(&f.source.block_hash(), &f.body).unwrap();
    let to = f.signers[1].public_key().clone();
    let net = RankOne::default();
    let mut worker = f.worker();
    for _ in 0..2 {
        net.release(&to);
        let mut result = poll(
            &f,
            &mut worker,
            &net,
            PayloadWork::Serve {
                to: to.clone(),
                height: 1,
                block_hash: f.source.block_hash(),
            },
        );
        for _ in 0..32 {
            if !result.retry {
                break;
            }
            net.release(&to);
            result = poll(&f, &mut worker, &net, PayloadWork::Poll);
        }
        assert!(!result.retry);
    }
    let s = net.0.lock().unwrap();
    assert_eq!(s.accepted.len(), 14);
    for (first, second) in s.accepted[..7].iter().zip(&s.accepted[7..]) {
        assert_eq!(first, second);
    }
}

#[test]
fn blocked_proactive_stream_cannot_take_historical_capacity() {
    let f = Fixture::new();
    f.bodies.put(&f.source.block_hash(), &f.body).unwrap();
    let blocked = f.signers[1].public_key().clone();
    let healthy = f.signers[2].public_key().clone();
    let net = RankOne::default();
    let mut worker = PayloadWorker::new(
        f.source.instance(),
        f.budget.clone(),
        Arc::new(crate::sumeragi::crypto::BlsCrypto::new()),
        vec![f.signers[0].clone()],
        1,
        0,
    );
    poll(
        &f,
        &mut worker,
        &net,
        PayloadWork::Disseminate {
            peers: vec![blocked.clone()],
            body: f.body.clone(),
        },
    );
    net.release(&healthy);
    poll(
        &f,
        &mut worker,
        &net,
        PayloadWork::Serve {
            to: healthy.clone(),
            height: 1,
            block_hash: f.source.block_hash(),
        },
    );
    for _ in 0..40 {
        net.release(&healthy);
        poll(&f, &mut worker, &net, PayloadWork::Poll);
    }
    assert!(six_rows_for(&net, &healthy, f.source.block_hash()));
    assert_eq!(
        net.0.lock().unwrap().dropped_pending,
        0,
        "blocked proactive receipt stays in its independent quota"
    );
}

#[test]
fn source_bound_fetch_rotation_keeps_intersection_receipts_and_reaches_new_peer() {
    let f = Fixture::new();
    let blocked = f.signers[1].public_key().clone();
    let healthy = f.signers[2].public_key().clone();
    let net = RankOne::default();
    let mut worker = f.worker();
    poll(
        &f,
        &mut worker,
        &net,
        PayloadWork::Fetch {
            source: f.source.clone(),
            peers: vec![blocked.clone()],
        },
    );
    for _ in 0..8 {
        poll(&f, &mut worker, &net, PayloadWork::Poll);
    }
    assert_eq!(net.0.lock().unwrap().attempts, 1);
    net.release(&healthy);
    poll(
        &f,
        &mut worker,
        &net,
        PayloadWork::Fetch {
            source: f.source.clone(),
            peers: vec![blocked.clone(), healthy.clone()],
        },
    );
    for _ in 0..8 {
        poll(&f, &mut worker, &net, PayloadWork::Poll);
    }
    {
        let state = net.0.lock().unwrap();
        assert_eq!(state.attempts, 2);
        assert_eq!(state.accepted.len(), 1);
        assert_eq!(state.accepted[0].0, healthy);
        assert_eq!(state.dropped_pending, 0);
    }
    let done = poll(
        &f,
        &mut worker,
        &net,
        PayloadWork::Fetch {
            source: f.source.clone(),
            peers: vec![healthy],
        },
    );
    assert!(!done.retry);
    let state = net.0.lock().unwrap();
    assert_eq!(state.attempts, 2);
    assert_eq!(state.accepted.len(), 1);
    assert_eq!(state.dropped_pending, 1);
}
#[test]
fn retained_core_cache_releases_codewords_before_small_pool_authoring() {
    let f = Fixture::new();
    let budget = iroha_allocation::AllocationBudget::new(32 * 1024);
    let net = RankOne::default();
    let crypto = Arc::new(crate::sumeragi::crypto::BlsCrypto::new());
    let mut worker = PayloadWorker::new(
        f.source.instance(),
        budget.clone(),
        crypto.clone(),
        vec![f.signers[0].clone()],
        1024,
        0,
    );
    let peer = f.signers[1].public_key().clone();
    for view in 0..24 {
        poll(
            &f,
            &mut worker,
            &net,
            PayloadWork::Retain {
                height: 1,
                keep: vec![],
            },
        );
        assert_eq!(
            budget.reserved_bytes(),
            0,
            "Core retirement must release original codeword and body owners before next authoring"
        );
        let mut payload = iroha_sumeragi::availability::PayloadBytes::from_untrusted(vec![
                u8::try_from(view)
                    .expect(
                        "fixture value fits u8"
                    );
                2049
            ])
        .unwrap();
        payload.admit(&budget).unwrap();
        let mut header = f.body.header().clone();
        header.origin_view = view;
        header.availability_digest = Hash32::ZERO;
        header.payload_hash = iroha_sumeragi::preimage::payload_hash(&*crypto, payload.as_slice());
        let body = iroha_sumeragi::availability::PayloadAuthoring::new(header, payload)
            .complete(
                f.source.instance(),
                f.source.config(),
                &budget,
                &*crypto,
                &*f.signers[0],
            )
            .unwrap_or_else(|_| panic!("same bounded pool must fund each next view"))
            .body;
        let hash = body.source().block_hash();
        net.release(&peer);
        poll(
            &f,
            &mut worker,
            &net,
            PayloadWork::Disseminate {
                peers: vec![peer.clone()],
                body,
            },
        );
        poll(&f, &mut worker, &net, PayloadWork::Poll); // Manifest admitted; actual coded row now awaits admission.
        let held = budget.reserved_bytes();
        assert!(held > 0);
        poll(
            &f,
            &mut worker,
            &net,
            PayloadWork::Retain {
                height: 1,
                keep: vec![hash],
            },
        );
        assert_eq!(
            budget.reserved_bytes(),
            held,
            "keep identity preserves its exact original owner"
        );
    }
    poll(
        &f,
        &mut worker,
        &net,
        PayloadWork::Retain {
            height: 1,
            keep: vec![],
        },
    );
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(net.0.lock().unwrap().dropped_pending, 24);
}
#[test]
fn cache_retirement_is_not_lost_to_queue_pressure() {
    let mut scheduler = ServeSched::new(ServeLimits {
        max_peers: 1,
        ..ServeLimits::default()
    });
    scheduler.push(
        ServeRequest::Payload(Box::new(PayloadWork::Disseminate {
            body: Fixture::new().body,
            peers: vec![],
        })),
        0,
    );
    scheduler.push(
        ServeRequest::Payload(Box::new(PayloadWork::Retain {
            height: 1,
            keep: vec![Hash32([3; 32])],
        })),
        0,
    );
    scheduler.push(
        ServeRequest::Payload(Box::new(PayloadWork::Retain {
            height: 1,
            keep: vec![Hash32([4; 32])],
        })),
        0,
    );
    assert_eq!(
        scheduler.len(),
        1,
        "retired queued streams cannot be recreated after the priority retirement turn"
    );
    assert!(
        matches!(scheduler.next(0),Some(ServeRequest::Payload(work)) if matches!(*work,PayloadWork::Retain {height:1,ref keep} if keep==&vec![Hash32([4;32])]))
    );
}

/// One unresponsive metadata requester cannot retain the reply slot of another requester.
#[test]
fn blocked_metadata_response_does_not_block_another_requester() {
    let f = Fixture::new();
    let blocked = f.signers[1].public_key().clone();
    let healthy = f.signers[2].public_key().clone();
    let net = RankOne::default();
    let mut worker = f.worker();
    net.release(&healthy);
    let request = |to| ServeRequest::Blocks {
        to,
        from_height: 1,
        max_count: 1,
        max_bytes: 4096,
    };
    let first = serve(
        request(blocked),
        f.source.instance(),
        &f.bodies,
        &f.blocks,
        &net,
        &mut worker,
    )
    .unwrap();
    assert!(first.retry && first.refused && first.charges.is_empty());
    let second = serve(
        request(healthy.clone()),
        f.source.instance(),
        &f.bodies,
        &f.blocks,
        &net,
        &mut worker,
    )
    .unwrap();
    let mut charges = second.charges;
    for _ in 0..64 {
        if !net.0.lock().unwrap().accepted.is_empty() {
            break;
        }
        charges.extend(poll(&f, &mut worker, &net, PayloadWork::Poll).charges);
    }
    let state = net.0.lock().unwrap();
    assert_eq!(
        state.accepted.len(),
        1,
        "the healthy metadata response must admit independently"
    );
    let (peer, frame) = &state.accepted[0];
    assert_eq!(peer, &healthy);
    assert!(
        matches!(WireMessage::decode(&frame.bytes, usize::MAX).unwrap(), WireMessage::SyncResponse(response) if response.instance == f.source.instance())
    );
    assert_eq!(
        state.attempts, 2,
        "each recipient keeps one original occurrence"
    );
    assert_eq!(
        state.dropped_pending, 0,
        "the unresponsive recipient retains its own receipt"
    );
    assert_eq!(charges, vec![(healthy, frame.bytes.len() as u64)]);
}
