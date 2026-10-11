//! The kernel with a real core: O1/O2 routing through the barrier and the ordered persistence
//! queue, O5 input priority (a due `Tick` first, whatever is queued), O7.

use std::sync::Arc;

use iroha_sumeragi::{
    api::{Action, CommittedTip, Event, Init, LocalFault, LocalParams},
    message::{PayloadRequest, Status, SyncRequest, TrafficClass, VoteKind, WireMessage},
    safety::{RecordState, SafetyRecord},
    testing::FakeValidators,
    types::{ChainParams, Hash32, HeightConfig, Millis},
};
use parking_lot::Mutex;

use super::{
    super::{
        Backlog, Completion, DriverConfig, Kernel, KernelStart, MAX_OPS_PER_POLL, Op, Report,
        barrier::HeldLimits,
        exec::{ExecDone, ExecOp},
        ingress::{Ingress, IngressLimits},
        persist::Write,
        serve::{ServeRequest, Served},
    },
    block, commit_qc, hash,
};

const INSTANCE: Hash32 = Hash32([5; 32]);

/// A kernel of member 0 of a four-member committee at genesis, and the committee's keys.
pub(super) fn start_kernel(now: Millis) -> (Kernel, FakeValidators) {
    let (start, validators) = kernel_start(now, super::test_budget());
    let (kernel, _) = Kernel::start(start).unwrap();
    (kernel, validators)
}

fn kernel_start(
    now: Millis,
    allocation_budget: iroha_allocation::AllocationBudget,
) -> (KernelStart, FakeValidators) {
    let vals = FakeValidators::new(4, 7, None);
    let me = vals.key(0);
    let crypto = vals.crypto.clone();
    let record = SafetyRecord::fresh(
        INSTANCE,
        iroha_sumeragi::testing::TEST_EPOCH.id,
        me.clone(),
        0,
        None,
    )
    .encode(&crypto)
    .unwrap();
    let config = HeightConfig {
        epoch: Box::new(iroha_sumeragi::testing::TEST_EPOCH),
        committee: vals.committee.clone(),
        params: ChainParams::default(),
    };
    let init = Init {
        instance: INSTANCE,
        records: vec![(me, RecordState::Present(record), false)],
        genesis_height: 0,
        demotion_window: 128,
        nonce: 1,
        tip: CommittedTip {
            height: 0,
            block_hash: Hash32([0xa0; 32]),
            result: Hash32([0xa1; 32]),
            header: None,
            commit_qc: None,
        },
        configs: vec![
            (1, iroha_sumeragi::types::ConfigSlot::Ready(config.clone())),
            (2, iroha_sumeragi::types::ConfigSlot::Ready(config)),
        ],
        recent_headers: Vec::new(),
    };
    let start = KernelStart {
        allocation_budget,
        local: LocalParams::default(),
        init,
        signers: vec![Arc::new(vals.signer(0).clone())],
        crypto: Box::new(crypto.clone()),
        hasher: Box::new(crypto),
        now,
        ingress: Arc::new(Mutex::new(Ingress::new(IngressLimits::default()))),
        config: DriverConfig::default(),
    };
    (start, vals)
}

#[test]
fn kernel_refuses_unfunded_waiter_before_constructing_consensus() {
    let budget = iroha_allocation::AllocationBudget::new(0);
    let (start, _) = kernel_start(0, budget.clone());
    assert!(matches!(
        Kernel::start(start),
        Err(super::super::KernelStartError::Admission(
            iroha_allocation::AllocationRefusal::ExceedsLimit { .. }
        ))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

fn request(height: u64) -> WireMessage {
    WireMessage::PayloadRequest(PayloadRequest {
        instance: INSTANCE,
        height,
        block_hash: Hash32::ZERO,
    })
}

/// O5: a due `Tick` comes before any queued input however many are queued (Tick lateness is
/// bounded by one event), then local events, then messages; the Tick consumes its deadline.
#[test]
fn tick_first_then_local_then_messages() {
    let (mut kernel, vals) = start_kernel(1_000);
    for h in 0..1_000 {
        kernel.receive(vals.key(1), request(h), TrafficClass::Control);
    }
    kernel.deliver(Event::PayloadReady { req: 99 });
    let due = kernel.core().next_wakeup();
    assert!(due < Millis::MAX);
    assert_eq!(kernel.next_input(due), Some(Event::Tick));
    kernel.handle(due, Event::Tick);
    assert!(
        kernel.core().next_wakeup() > due,
        "the Tick consumed its deadline"
    );
    assert_eq!(
        kernel.next_input(due),
        Some(Event::PayloadReady { req: 99 })
    );
    assert!(matches!(
        kernel.next_input(due),
        Some(Event::Message { .. })
    ));
    // Under the flood, the next deadline is again served first.
    let next = kernel.core().next_wakeup();
    assert_eq!(kernel.next_input(next), Some(Event::Tick));
    assert!(kernel.has_input());
    // The earlier Tick also queued original application-control work. Dispatch it
    // before comparing the kernel deadline with the still-unconsumed Core Tick.
    assert_eq!(kernel.next_wakeup(), 0, "queued control work is ready now");
    assert!(
        kernel.poll(next).iter().any(|op| matches!(op, Op::Exec(_))),
        "the immediate deadline must dispatch actual executor work"
    );
    assert_eq!(kernel.next_wakeup(), next);
}

/// O7 and routing by instance: the node's own messages and other instances' are dropped.
#[test]
fn own_and_foreign_messages_are_dropped() {
    let (mut kernel, vals) = start_kernel(0);
    kernel.receive(vals.key(0), request(1), TrafficClass::Control);
    let foreign = WireMessage::PayloadRequest(PayloadRequest {
        instance: Hash32([6; 32]),
        height: 1,
        block_hash: Hash32::ZERO,
    });
    kernel.receive(vals.key(1), foreign, TrafficClass::Control);
    assert!(!kernel.has_input());
    kernel.receive(vals.key(1), request(1), TrafficClass::Control);
    assert!(kernel.has_input());
    assert_eq!(kernel.ingress_drops(), 0);
}

fn record(height: u64, vals: &FakeValidators) -> Box<SafetyRecord> {
    Box::new(SafetyRecord::fresh(
        INSTANCE,
        iroha_sumeragi::testing::TEST_EPOCH.id,
        vals.key(0),
        height,
        None,
    ))
}

/// Complete an executor operation the way an executor without post-states would (builds are
/// `EMPTY`, executions lack their parent).
fn complete_exec(kernel: &mut Kernel, now: Millis, op: &ExecOp) {
    let done = match op {
        ExecOp::BuildControlWitness { .. } => {
            ExecDone::ControlWitnessBuilt(Ok(iroha_sumeragi::types::ControlWitness::empty()))
        }
        ExecOp::DriveApplicationControl(_) => ExecDone::ApplicationControlDriven(Ok(None)),
        ExecOp::ReceiveApplicationControl {
            occurrence,
            from,
            message,
        } => ExecDone::ApplicationControlReceived {
            occurrence: *occurrence,
            from: from.clone(),
            message: message.clone(),
            result: Ok(()),
        },
        ExecOp::Build { .. } => ExecDone::Built(Ok(None)),
        ExecOp::Execute { .. } => ExecDone::Executed(None),
        ExecOp::Discard { .. } => ExecDone::Discarded,
        ExecOp::Reject { .. } => ExecDone::Rejected,
        op => panic!("no commit here: {op:?}"),
    };
    kernel.complete(now, Completion::Exec(done));
}

/// Complete every start-up operation (writes durable, builds `EMPTY`) until none is left.
fn settle(kernel: &mut Kernel) {
    loop {
        let ops = kernel.poll(0);
        if ops.is_empty() {
            return;
        }
        for op in ops {
            match op {
                Op::Persist { seq, .. } => {
                    kernel.complete(
                        0,
                        Completion::Persisted {
                            seq,
                            result: Ok(()),
                        },
                    );
                }
                Op::Exec(op) => complete_exec(kernel, 0, &op),
                Op::Send { .. } | Op::Serve(_) | Op::Report(_) => {}
            }
        }
    }
}

/// Run the kernel at `now` until it is idle: handle every input, make every write durable and
/// complete executor operations; the other operations are returned (serving is not completed).
fn run(kernel: &mut Kernel, now: Millis) -> Vec<Op> {
    let mut out = Vec::new();
    loop {
        while let Some(event) = kernel.next_input(now) {
            kernel.handle(now, event);
        }
        let ops = kernel.poll(now);
        if ops.is_empty() {
            return out;
        }
        for op in ops {
            match op {
                Op::Persist { seq, .. } => kernel.complete(
                    now,
                    Completion::Persisted {
                        seq,
                        result: Ok(()),
                    },
                ),
                Op::Exec(op) => complete_exec(kernel, now, &op),
                other => out.push(other),
            }
        }
    }
}

fn sync_request(from_height: u64) -> WireMessage {
    WireMessage::SyncRequest(SyncRequest {
        instance: INSTANCE,
        from_height,
        max_count: u16::MAX,
        max_bytes: u32::MAX,
    })
}

/// O1/O2: after a `PersistSafety`, gated effects wait for its durability and leave in order;
/// exempt actions (execution, faults, bodies) go at once; one write at a time, in order, so
/// the record is durable only after the body stored before it; a failed write is retried, not
/// skipped; the node never addresses itself (O7).
#[test]
fn barrier_and_ordered_persistence() {
    let (mut kernel, vals) = start_kernel(0);
    settle(&mut kernel);
    let b1 = block(
        1,
        Hash32([0xa0; 32]),
        Hash32([0xa1; 32]),
        iroha_sumeragi::sim::driver::encode_tx(0, false, 0),
    );
    let send = |h: u64| Action::Broadcast {
        to: vec![vals.key(0), vals.key(1)],
        msg: request(h),
    };
    kernel.route(vec![
        Action::StoreBody { block: b1.clone() },
        Action::PersistSafety(record(1, &vals)),
        send(1),
        Action::Execute {
            block: b1.clone(),
            req: 1,
            certified: false,
        },
        Action::LocalFault(LocalFault::RecordMissing),
        Action::CommitBlock {
            block: b1.clone(),
            commit_qc: commit_qc(&b1, Hash32([3; 32])),
        },
    ]);
    let ops = kernel.poll(0);
    assert!(ops.contains(&Op::Report(Report::Fault(LocalFault::RecordMissing))));
    let body = ops
        .iter()
        .find_map(|op| match op {
            Op::Persist {
                seq,
                write: Write::Body(_),
            } => Some(*seq),
            _ => None,
        })
        .expect("the body is written first");
    assert!(ops.iter().any(|op| matches!(
        op,
        Op::Exec(ExecOp::Execute {
            certified: false,
            ..
        })
    )));
    assert!(!ops.iter().any(|op| matches!(
        op,
        Op::Send { .. }
            | Op::Persist {
                write: Write::Record(_),
                ..
            }
    )));
    assert_eq!(kernel.held().len(), 2, "the broadcast and the commit wait");
    // The body is durable: the record is written next; the effects still wait.
    kernel.complete(
        0,
        Completion::Persisted {
            seq: body,
            result: Ok(()),
        },
    );
    let ops = kernel.poll(0);
    let [Op::Persist { seq, write }] = &ops[..] else {
        panic!("{ops:?}")
    };
    let (seq, write) = (*seq, write.clone());
    assert_eq!(seq, body + 1);
    assert!(matches!(write, Write::Record(_)));
    // The record write fails: retried after the backoff, nothing released meanwhile.
    kernel.complete(
        0,
        Completion::Persisted {
            seq,
            result: Err(write),
        },
    );
    assert!(kernel.poll(5).is_empty());
    let ops = kernel.poll(10);
    assert!(
        matches!(&ops[..], [Op::Persist { seq: s, .. }] if *s == seq),
        "retried, not skipped"
    );
    kernel.complete(
        10,
        Completion::Persisted {
            seq,
            result: Ok(()),
        },
    );
    let ops = kernel.poll(10);
    assert_eq!(
        ops,
        vec![Op::Send {
            to: vec![vals.key(1)],
            msg: request(1)
        }],
        "released in order, without the node's own key; the commit waits for the executor"
    );
    assert!(kernel.held().is_empty());
    assert!(kernel.exec().busy());
}

/// A local event from serving reaches the core like any local event.
#[test]
fn served_bodies_become_local_events() {
    let (mut kernel, _) = start_kernel(0);
    let b1 = block(
        1,
        Hash32([0xa0; 32]),
        Hash32([0xa1; 32]),
        iroha_sumeragi::sim::driver::encode_tx(0, false, 0),
    );
    kernel.complete(
        0,
        Completion::Served(Served {
            events: vec![Event::BodyAvailable { block: b1.clone() }],
            ..Served::default()
        }),
    );
    kernel.transactions_available();
    let mut now = 0;
    loop {
        match kernel.next_input(now) {
            Some(Event::Tick) => {
                kernel.handle(now, Event::Tick);
                now += 1;
            }
            other => {
                assert_eq!(other, Some(Event::BodyAvailable { block: b1 }));
                break;
            }
        }
    }
}

/// §12.2 serving limits: a flood of `SyncRequest`s from three peers leaves one pending
/// `ServeBlocks` per peer (one in flight), and the node's own `FetchBody` — a body it lacks
/// for a `CommitQC` — runs after the in-flight request and its mandatory lifetime cleanup,
/// before any queued peer response.
#[test]
fn serving_is_bounded_and_the_nodes_fetch_goes_first() {
    let (mut kernel, vals) = start_kernel(0);
    settle(&mut kernel);
    for i in 0..3_000u64 {
        let peer = vals.key([1, 2, 3][usize::try_from(i % 3).unwrap()]);
        kernel.receive(peer, sync_request(i), TrafficClass::Control);
    }
    let ops = run(&mut kernel, 0);
    let serving = ops.iter().filter(|op| matches!(op, Op::Serve(_))).count();
    assert_eq!(serving, 1, "one request in flight");
    let backlog = kernel.backlog();
    assert!(
        backlog.serve <= 3,
        "one pending request per peer: {backlog:?}"
    );
    assert!(backlog.serve_dropped >= 700, "{backlog:?}");
    // A CommitQC of height 1 whose body the node lacks.
    let b1 = block(1, Hash32([0xa0; 32]), Hash32([0xa1; 32]), vec![1, 2, 3]);
    let qc = vals.qc(
        VoteKind::Commit,
        &INSTANCE,
        1,
        0,
        &hash(&b1),
        &Hash32([3; 32]),
        &[1, 2, 3],
    );
    let status = Status {
        instance: INSTANCE,
        height: 2,
        view: 0,
        committed_qc: Some(qc),
        high_pqc: None,
        high_tc: None,
        proposal_hash: None,
        want_proposal: false,
        probe: None,
        echo: None,
    };
    kernel.receive(
        vals.key(1),
        WireMessage::Status(Box::new(status)),
        TrafficClass::Control,
    );
    let ops = run(&mut kernel, 0);
    assert!(
        !ops.iter().any(|op| matches!(op, Op::Serve(_))),
        "the serve thread is busy: {ops:?}"
    );
    kernel.complete(0, Completion::Served(Served::default()));
    let ops = kernel.poll(0);
    assert!(
        matches!(
            &ops[..],
            [Op::Serve(ServeRequest::Payload(work))] if matches!(&**work,
                super::super::payload_worker::PayloadWork::Retain { height: 1, keep }
                if keep.as_slice() == [hash(&b1)])
        ),
        "authorized cleanup precedes local recovery: {ops:?}"
    );
    kernel.complete(
        0,
        Completion::Served(Served {
            payload: true,
            ..Served::default()
        }),
    );
    let ops = kernel.poll(0);
    assert!(
        matches!(
            &ops[..],
            [Op::Serve(ServeRequest::Payload(work))] if matches!(&**work, super::super::payload_worker::PayloadWork::Fetch { source, .. } if source.block_hash() == hash(&b1))
        ),
        "{ops:?}"
    );
}

/// A disk that keeps failing: the core keeps running (timeouts, rebroadcasts, serving requests
/// behind its pending record), yet the queues stay bounded — one queued record per key, held
/// effects within their limits. Once the disk recovers the held effects leave in batches of at
/// most `MAX_OPS_PER_POLL`, with a due `Tick` handled between batches (O5).
#[test]
fn failing_disk_bounds_the_queues_and_releases_in_batches() {
    let (mut kernel, vals) = start_kernel(0);
    settle(&mut kernel);
    let limits = HeldLimits::default();
    let mut max = Backlog::default();
    let mut now = 0;
    for step in 0..6_000u64 {
        now += 25;
        if step < 2_000 {
            for peer in 1..=3 {
                kernel.receive(vals.key(peer), sync_request(step), TrafficClass::Control);
            }
        }
        while let Some(event) = kernel.next_input(now) {
            kernel.handle(now, event);
        }
        for op in kernel.poll(now) {
            match op {
                Op::Persist { seq, write } => kernel.complete(
                    now,
                    Completion::Persisted {
                        seq,
                        result: Err(write),
                    },
                ),
                Op::Exec(op) => complete_exec(&mut kernel, now, &op),
                Op::Serve(_) => kernel.complete(now, Completion::Served(Served::default())),
                Op::Send { .. } | Op::Report(_) => {}
            }
        }
        let backlog = kernel.backlog();
        max.held = max.held.max(backlog.held);
        max.records = max.records.max(backlog.records);
        max.writes = max.writes.max(backlog.writes);
        max.serve = max.serve.max(backlog.serve);
        max.held_dropped = backlog.held_dropped;
    }
    assert!(max.held <= limits.effects, "{max:?}");
    assert!(
        max.held >= 100,
        "the core kept emitting behind its record: {max:?}"
    );
    assert!(max.held_dropped > 0, "the bound was reached: {max:?}");
    assert!(max.records <= 1, "one queued record per key: {max:?}");
    assert!(max.writes <= 3, "{max:?}");
    assert!(max.serve <= 3, "{max:?}");
    // The disk recovers: the record becomes durable and the held effects are released.
    let held = kernel
        .held()
        .iter()
        .filter(|a| matches!(a, Action::Send { .. } | Action::Broadcast { .. }))
        .count();
    assert!(held > MAX_OPS_PER_POLL, "{held} held messages");
    let mut batches = 0;
    let mut released = 0;
    let mut ticks_between = 0;
    for round in 0.. {
        assert!(round < 100_000, "the release never finished");
        let ops = kernel.poll(now);
        let idle = ops.is_empty();
        let sends = ops
            .iter()
            .filter(|op| matches!(op, Op::Send { .. }))
            .count();
        assert!(sends <= MAX_OPS_PER_POLL, "{sends}");
        released += sends;
        batches += usize::from(sends > 0);
        for op in ops {
            match op {
                Op::Persist { seq, .. } => kernel.complete(
                    now,
                    Completion::Persisted {
                        seq,
                        result: Ok(()),
                    },
                ),
                Op::Exec(op) => complete_exec(&mut kernel, now, &op),
                Op::Serve(_) => kernel.complete(now, Completion::Served(Served::default())),
                Op::Send { .. } | Op::Report(_) => {}
            }
        }
        if kernel.has_output() {
            // A deadline that falls due between two batches is served first.
            now = now.max(kernel.core().next_wakeup());
            assert_eq!(kernel.next_input(now), Some(Event::Tick));
            kernel.handle(now, Event::Tick);
            ticks_between += 1;
        } else if kernel.backlog().writes == 0 && kernel.backlog().held == 0 {
            break;
        } else if idle {
            // The record's retry is due later.
            now = now.max(kernel.next_wakeup());
            while let Some(event) = kernel.next_input(now) {
                kernel.handle(now, event);
            }
        }
    }
    assert!(released >= held, "released {released} of {held}");
    assert!(batches > 1 && ticks_between > 0, "{batches} batches");
}

/// Recovery is synchronous: queued consensus effects never escape, but O2 writes and serving do.
#[test]
fn publication_recovery_halts_before_poll_and_preserves_safety_persistence() {
    use super::super::traits::PublicationError;
    use iroha_sumeragi::api::HaltReason;

    let (mut kernel, vals) = start_kernel(0);
    settle(&mut kernel);
    let block = block(
        1,
        Hash32([0xa0; 32]),
        Hash32([0xa1; 32]),
        iroha_sumeragi::sim::driver::encode_tx(0, false, 0),
    );
    let result = Hash32([0x31; 32]);
    kernel.route(vec![Action::CommitBlock {
        commit_qc: commit_qc(&block, result),
        block: block.clone(),
    }]);
    assert!(
        kernel
            .poll(0)
            .iter()
            .any(|op| matches!(op, Op::Exec(ExecOp::Prepare(_))))
    );
    kernel.complete(0, Completion::Exec(ExecDone::Prepared(Ok(Some(result)))));
    assert!(
        kernel
            .poll(0)
            .iter()
            .any(|op| matches!(op, Op::Exec(ExecOp::Append(_))))
    );
    kernel.complete(
        0,
        Completion::Exec(ExecDone::Appended {
            durable: true,
            deferred: None,
        }),
    );
    assert!(
        kernel
            .poll(0)
            .iter()
            .any(|op| matches!(op, Op::Exec(ExecOp::Commit(_))))
    );
    kernel.route(vec![
        Action::Broadcast {
            to: vec![vals.key(1)],
            msg: request(1),
        },
        Action::PersistSafety(record(2, &vals)),
        Action::Broadcast {
            to: vec![vals.key(1)],
            msg: request(2),
        },
        Action::Execute {
            block,
            req: 444,
            certified: true,
        },
        Action::BuildPayload {
            req: 445,
            height: 1,
            view: 0,
            max_bytes: 1024,
            exec_budget_ms: 10,
        },
    ]);
    kernel.complete(
        0,
        Completion::Exec(ExecDone::Committed(Err(
            PublicationError::RecoveryRequired("consuming state failure".into()),
        ))),
    );
    let halt = HaltReason::PublicationRecoveryRequired { height: 1 };
    assert_eq!(
        kernel.core().status().halted,
        Some(halt),
        "no Tick or poll precedes the halt"
    );
    assert_eq!(kernel.exec().applied(), 0);
    let ops = kernel.poll(0);
    assert!(
        !ops.iter()
            .any(|op| matches!(op, Op::Send { .. } | Op::Exec(_)))
    );
    let seq = ops
        .iter()
        .find_map(|op| match op {
            Op::Persist {
                seq,
                write: Write::Record(_),
            } => Some(*seq),
            _ => None,
        })
        .expect("pending safety record remains ordered");
    assert!(
        !ops.iter()
            .any(|op| matches!(op, Op::Report(Report::Halt(_)))),
        "halt report preserves O2"
    );
    kernel.complete(
        0,
        Completion::Persisted {
            seq,
            result: Ok(()),
        },
    );
    let ops = kernel.poll(0);
    assert_eq!(
        ops.iter()
            .filter(|op| matches!(op, Op::Report(Report::Halt(reason)) if *reason == halt))
            .count(),
        1
    );
    assert!(
        !ops.iter()
            .any(|op| matches!(op, Op::Send { .. } | Op::Exec(_))),
        "durability cannot release stale signing or apply work"
    );
    kernel.handle(10_000, Event::Tick);
    kernel.transactions_available();
    kernel.handle(
        10_000,
        Event::Message {
            from: vals.key(1),
            msg: sync_request(1),
        },
    );
    let ops = kernel.poll(10_000);
    assert!(
        ops.iter()
            .any(|op| matches!(op, Op::Serve(ServeRequest::Blocks { .. })))
    );
    assert!(
        !ops.iter()
            .any(|op| matches!(op, Op::Send { .. } | Op::Exec(_)))
    );
    assert_eq!(kernel.core().status().halted, Some(halt));
}

#[test]
fn frame_limits_cover_both_atomic_boundary_configs_without_pending_fallback() {
    use iroha_sumeragi::types::{AppliedConfig, ConfigSlot};
    let (_, vals) = start_kernel(0);
    let mut next = HeightConfig {
        epoch: Box::new(iroha_sumeragi::testing::TEST_EPOCH),
        committee: vals.committee,
        params: ChainParams::default(),
    };
    next.params.max_block_bytes = 1_000;
    let mut after_next = next.clone();
    after_next.params.max_block_bytes = 2_000;
    let output = AppliedConfig::Boundary { next, after_next };
    let found = super::super::applied_frame_limits(1, 3, &output);
    assert_eq!(found[0].as_ref().unwrap().height, 4);
    assert_eq!(found[1].as_ref().unwrap().height, 5);
    assert_eq!(
        found[1].as_ref().unwrap().needed - found[0].as_ref().unwrap().needed,
        1_000
    );
    let pending = AppliedConfig::Continuation {
        after_next: ConfigSlot::PendingBoundary {
            boundary_height: 4,
            predecessor: iroha_sumeragi::testing::TEST_EPOCH.id,
        },
    };
    assert_eq!(
        super::super::applied_frame_limits(1, 3, &pending),
        [None, None]
    );
}

#[test]
fn core_discard_routes_the_same_authorized_keep_set_to_payload_lifetime() {
    let (mut kernel, _) = start_kernel(0);
    let keep = vec![Hash32([0x73; 32])];
    kernel.route(vec![Action::DiscardExecution {
        height: 1,
        keep: keep.clone(),
    }]);
    let operations = kernel.poll(0);
    assert!(operations.iter().any(|operation| matches!(operation,
        Op::Serve(ServeRequest::Payload(work))
            if matches!(&**work, super::super::payload_worker::PayloadWork::Retain { height: 1, keep: retained } if retained == &keep)
    )), "the exact Core lifetime reaches the payload worker before another author job");
}
