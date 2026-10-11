//! Transactions-only admission on the actual charged-wake loop and original pool.

use std::{
    sync::{Arc, mpsc},
    time::Duration,
};

use iroha_sumeragi::{
    api::{CoreStatus, Event},
    message::{Status, TrafficClass, WireMessage},
    types::{Millis, PublicKey},
};
use parking_lot::Mutex;

use super::super::{
    super::{
        Backlog, Backoff, DriverHandle, DriverInputs, Input, LoopGuard, NodeGate, Op,
        PendingAdmission, Shared, Worker, Workers,
        exec::ExecOp,
        persist::Write,
        run_loop,
        serve::ServeRequest,
        traits::{Clock, NoObserver},
        wake::ThreadWake,
    },
    fakes::FakeNet,
    kernel::start_kernel,
};

/// Send-safe inspection handles; the actual non-Send Kernel stays on its owning thread.
struct LoopFixture {
    handle: DriverHandle,
    shared: Arc<Shared>,
    persisted: mpsc::Receiver<(u64, Write)>,
    executed: mpsc::Receiver<ExecOp>,
    served: mpsc::Receiver<ServeRequest>,
    net: Arc<FakeNet>,
    due: Millis,
    peer: PublicKey,
    initial_status: CoreStatus,
    budget: iroha_allocation::AllocationBudget,
    original_bytes: usize,
    loop_inputs: DriverInputs,
}

/// One genuine Kernel constructed on the same thread that runs the production loop.
struct LoopSession {
    fixture: LoopFixture,
    start: mpsc::Sender<()>,
    counts: mpsc::Receiver<usize>,
    event_loop: std::thread::JoinHandle<Result<(), Worker>>,
}

fn spawn_loop_fixture(reached: mpsc::Sender<()>, release: mpsc::Receiver<()>) -> LoopSession {
    let (ready, fixture_receiver) = mpsc::sync_channel(1);
    let (start, started) = mpsc::channel();
    let (counted, counts) = mpsc::channel();
    let event_loop = std::thread::spawn(move || {
        let budget = super::super::test_budget();
        let original_bytes = budget.reserved_bytes();
        let (mut kernel, validators) = start_kernel(1_000);
        let due = kernel.core().next_wakeup();
        let (sender, receiver) = mpsc::channel();
        let shared = Arc::new(Shared {
            node_gate: Arc::new(NodeGate::new()),
            allocation_budget: budget.clone(),
            pending_admission: Mutex::new(
                PendingAdmission::admit(&budget, Backoff::default()).unwrap(),
            ),
            instance: kernel.instance,
            own: vec![validators.key(0)],
            ingress: Arc::clone(&kernel.ingress),
            frame_limit: usize::try_from(kernel.frame_limit).unwrap(),
            status: Mutex::new(None),
            backlog: Mutex::new(Backlog::default()),
            wake: ThreadWake::admit(&budget).unwrap(),
            transactions_pending: std::sync::atomic::AtomicBool::new(false),
            empty_waiting: std::sync::atomic::AtomicBool::new(false),
            empty_epoch: std::sync::atomic::AtomicU64::new(0),
            alive: std::sync::atomic::AtomicBool::new(true),
            stopped: Mutex::new(None),
            metrics: None,
        });
        let inputs = DriverInputs {
            sender,
            wake: shared.wake.clone(),
        };
        let loop_inputs = inputs.clone();
        let handle = DriverHandle {
            shared: Arc::clone(&shared),
            inputs,
        };
        let (persist, persisted) = mpsc::channel();
        let (exec, executed) = mpsc::channel();
        let (serve, served) = mpsc::channel();
        let net = Arc::new(FakeNet::default());
        let workers = Workers {
            node_gate: Arc::clone(&shared.node_gate),
            net: net.clone(),
            observer: Arc::new(NoObserver),
            persist,
            exec,
            serve,
        };
        let clock = Arc::new(DispatchClock {
            due,
            reads: Mutex::new(0),
            reached,
            release: Mutex::new(release),
        });
        ready
            .send(LoopFixture {
                handle,
                shared: Arc::clone(&shared),
                persisted,
                executed,
                served,
                net,
                due,
                peer: validators.key(1),
                initial_status: kernel.core().status(),
                budget,
                original_bytes,
                loop_inputs: loop_inputs.clone(),
            })
            .unwrap_or_else(|_| panic!("original fixture inspection receiver"));
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        let admitted: Vec<_> = receiver.try_iter().collect();
        counted
            .send(
                admitted
                    .iter()
                    .filter(|input| matches!(input, Input::Transactions))
                    .count(),
            )
            .unwrap();
        for input in admitted {
            loop_inputs.send(input).unwrap();
        }
        shared.wake.bind_current();
        kernel
            .exec
            .bind_release_waker(shared.wake.clone().into_waker());
        let _loop_guard = LoopGuard {
            shared: Arc::clone(&shared),
            observer: Arc::new(NoObserver),
        };
        run_loop(kernel, &receiver, &shared, &*clock, &workers)
    });
    LoopSession {
        fixture: fixture_receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap(),
        start,
        counts,
        event_loop,
    }
}

/// Stops at the second scheduling turn, after the first due Tick reached dispatch.
struct DispatchClock {
    due: Millis,
    reads: Mutex<usize>,
    reached: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl Clock for DispatchClock {
    fn now(&self) -> Millis {
        let count = {
            let mut reads = self.reads.lock();
            *reads += 1;
            *reads
        };
        if count == 5 {
            self.reached.send(()).unwrap();
            self.release
                .lock()
                .recv_timeout(Duration::from_secs(5))
                .expect("the test releases the actual event loop after inspecting dispatch");
        }
        self.due
    }
}

/// Transaction notification admission cannot grow an arbitrary prefix before the
/// due Tick reaches the actual worker/transport dispatch. The original network owner stays
/// in ingress until that Tick, and shutdown naturally joins the same event-loop thread.
#[test]
fn actual_run_loop_bounds_transactions_before_due_tick_dispatch() {
    let (reached, probe) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let session = spawn_loop_fixture(reached, released);
    let fixture = &session.fixture;
    let budget = fixture.budget.clone();
    let original_bytes = fixture.original_bytes;
    let due = fixture.due;
    assert!(due < Millis::MAX);
    let queue_wake = fixture.handle.queue_wake();
    assert!(queue_wake.is_live());
    assert!(queue_wake.same_original(&fixture.handle.queue_wake()));
    let original_wake_charge = budget.reserved_bytes();
    for _ in 0..4_096 {
        queue_wake.notify();
    }
    assert_eq!(
        budget.reserved_bytes(),
        original_wake_charge,
        "coalesced notifications preserve the original wake charge"
    );
    let message = WireMessage::Status(Box::new(Status {
        instance: fixture.initial_status.instance,
        height: fixture.initial_status.height,
        view: fixture.initial_status.view,
        committed_qc: None,
        high_pqc: None,
        high_tc: None,
        proposal_hash: None,
        want_proposal: false,
        probe: None,
        echo: None,
    }));
    assert!(
        fixture
            .handle
            .deliver_message(fixture.peer.clone(), message.clone())
    );
    assert_eq!(fixture.shared.ingress.lock().len(), 1);

    // All admissions finish before a consumer starts: no startup or producer timing race.
    // Move exact admitted notifications while retaining the original shared message owner.
    let (mut oracle, _) = start_kernel(1_000);
    assert_eq!(oracle.core().next_wakeup(), due);
    oracle.receive(fixture.peer.clone(), message, TrafficClass::Control);
    oracle.transactions_available();
    let mut expected = oracle.poll(due);
    assert_eq!(oracle.next_input(due), Some(Event::Tick));
    oracle.handle(due, Event::Tick);
    let tick_operations = oracle.poll(due);
    assert!(!tick_operations.is_empty(), "this Tick must reach dispatch");
    expected.extend(tick_operations);
    assert!(oracle.core().next_wakeup() > due);

    session.start.send(()).unwrap();
    let transaction_notifications = session.counts.recv_timeout(Duration::from_secs(5)).unwrap();
    let rendezvous = probe.recv_timeout(Duration::from_secs(5));
    let observed_persist: Vec<_> = fixture.persisted.try_iter().collect();
    let observed_exec: Vec<_> = fixture.executed.try_iter().collect();
    let observed_serve: Vec<_> = fixture.served.try_iter().collect();
    let observed_net = fixture.net.sent();
    let observed_status = fixture.shared.status.lock().clone();
    let original_message_still_retained = fixture.shared.ingress.lock().len();

    fixture.loop_inputs.send(Input::Stop).unwrap();
    release.send(()).unwrap();
    let ended = session.event_loop.join();
    assert!(rendezvous.is_ok(), "actual Tick dispatch rendezvous");
    assert_eq!(ended.unwrap(), Ok(()), "natural ordered shutdown");

    assert_eq!(observed_status, Some(oracle.core().status()));
    assert_eq!(original_message_still_retained, 1, "Tick precedes ingress");
    assert_eq!(
        observed_persist,
        expected
            .iter()
            .filter_map(|op| match op {
                Op::Persist { seq, write } => Some((*seq, write.clone())),
                _ => None,
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(
        observed_exec,
        expected
            .iter()
            .filter_map(|op| match op {
                Op::Exec(op) => Some(op.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(
        observed_serve,
        expected
            .iter()
            .filter_map(|op| match op {
                Op::Serve(request) => Some(request.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(
        observed_net,
        expected
            .iter()
            .flat_map(|op| match op {
                Op::Send { to, msg } => to
                    .iter()
                    .map(|peer| (peer.clone(), msg.clone()))
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            })
            .collect::<Vec<_>>()
    );
    assert!(
        !queue_wake.is_live(),
        "the stopped original driver cannot notify again"
    );
    queue_wake.notify();
    drop(queue_wake);
    drop(session.fixture);
    drop((oracle, expected));
    drop((
        observed_persist,
        observed_exec,
        observed_serve,
        observed_net,
    ));
    assert_eq!(budget.reserved_bytes(), original_bytes);
    assert_eq!(
        transaction_notifications, 1,
        "one original pending transaction notification before actual Tick dispatch"
    );
}

/// A fixed logical time; these boundary tests do not depend on wall-clock deadlines.
struct FrozenClock(Millis);

impl Clock for FrozenClock {
    fn now(&self) -> Millis {
        self.0
    }
}

/// A genuine four-member Kernel whose sole local signer is the height-one leader.
fn start_leader_kernel() -> (
    super::super::super::Kernel,
    iroha_sumeragi::testing::FakeValidators,
) {
    use super::super::super::{
        DriverConfig, Kernel, KernelStart,
        ingress::{Ingress, IngressLimits},
    };
    use iroha_sumeragi::{
        api::{CommittedTip, Init, LocalParams},
        safety::{RecordState, SafetyRecord},
        testing::{FakeValidators, TEST_EPOCH},
        types::{ChainParams, ConfigSlot, Hash32, HeightConfig},
    };

    let validators = FakeValidators::new(4, 7, None);
    let instance = Hash32([5; 32]);
    let topology = iroha_sumeragi::topology::Topology::compute(
        &validators.crypto,
        &instance,
        &TEST_EPOCH,
        &validators.committee,
        1,
        0,
        128,
        &[],
    );
    let leader = topology.leader(0);
    let key = validators.key(leader);
    let record = SafetyRecord::fresh(instance, TEST_EPOCH.id, key.clone(), 0, None)
        .encode(&validators.crypto)
        .unwrap();
    let config = HeightConfig {
        epoch: Box::new(TEST_EPOCH),
        committee: validators.committee.clone(),
        params: ChainParams::default(),
    };
    let (kernel, _) = Kernel::start(KernelStart {
        allocation_budget: super::super::test_budget(),
        local: LocalParams::default(),
        init: Init {
            instance,
            records: vec![(key.clone(), RecordState::Present(record), false)],
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
                (1, ConfigSlot::Ready(config.clone())),
                (2, ConfigSlot::Ready(config)),
            ],
            recent_headers: Vec::new(),
        },
        signers: vec![Arc::new(validators.signer(leader).clone())],
        crypto: Box::new(validators.crypto.clone()),
        hasher: Box::new(validators.crypto.clone()),
        now: 0,
        ingress: Arc::new(Mutex::new(Ingress::new(IngressLimits::default()))),
        config: DriverConfig::default(),
    })
    .unwrap();
    assert_eq!(kernel.core().status().leader, Some(key));
    (kernel, validators)
}

/// Original workers are inspected through their real dispatch channels.
struct LeaderLoop {
    handle: DriverHandle,
    shared: Arc<Shared>,
    executed: mpsc::Receiver<ExecOp>,
    persisted: mpsc::Receiver<(u64, Write)>,
    served: mpsc::Receiver<ServeRequest>,
    net: Arc<FakeNet>,
    start: mpsc::Sender<()>,
    event_loop: std::thread::JoinHandle<Result<(), Worker>>,
}

fn spawn_leader_loop(recovery_in_flight: bool) -> LeaderLoop {
    let (ready, received) = mpsc::sync_channel(1);
    let (start, started) = mpsc::channel();
    let event_loop = std::thread::spawn(move || {
        let (mut kernel, validators) = start_leader_kernel();
        if recovery_in_flight {
            assert!(matches!(
                kernel.exec.next(0),
                Some(ExecOp::DriveApplicationControl(_))
            ));
            let peer = (0..4)
                .map(|index| validators.key(index))
                .find(|key| Some(key) != kernel.core().status().signer.as_ref())
                .unwrap();
            kernel.route(vec![iroha_sumeragi::api::Action::PersistSafety(Box::new(
                iroha_sumeragi::safety::SafetyRecord::fresh(
                    kernel.instance,
                    iroha_sumeragi::testing::TEST_EPOCH.id,
                    kernel.core().status().signer.clone().unwrap(),
                    1,
                    None,
                ),
            ))]);
            kernel.send(
                vec![peer],
                WireMessage::PayloadRequest(iroha_sumeragi::message::PayloadRequest {
                    instance: kernel.instance,
                    height: 1,
                    block_hash: iroha_sumeragi::types::Hash32::ZERO,
                }),
            );
        }
        // At genesis, pace equals the committed target block time. Earlier rebroadcast
        // deadlines remain enabled; the fixed logical clock reaches the original Build.
        let clock = FrozenClock(if recovery_in_flight {
            kernel.core().next_wakeup()
        } else {
            iroha_sumeragi::types::ChainParams::default().block_time
        });
        let shared = Arc::new(Shared {
            node_gate: Arc::new(NodeGate::new()),
            allocation_budget: super::super::test_budget(),
            pending_admission: Mutex::new(
                PendingAdmission::admit(&super::super::test_budget(), Backoff::default()).unwrap(),
            ),
            instance: kernel.instance,
            own: vec![kernel.core().status().signer.clone().unwrap()],
            ingress: Arc::clone(&kernel.ingress),
            frame_limit: usize::try_from(kernel.frame_limit).unwrap(),
            status: Mutex::new(None),
            backlog: Mutex::new(Backlog::default()),
            wake: ThreadWake::admit(&super::super::test_budget()).unwrap(),
            transactions_pending: std::sync::atomic::AtomicBool::new(false),
            empty_waiting: std::sync::atomic::AtomicBool::new(false),
            empty_epoch: std::sync::atomic::AtomicU64::new(0),
            alive: std::sync::atomic::AtomicBool::new(true),
            stopped: Mutex::new(None),
            metrics: None,
        });
        let (sender, receiver) = mpsc::channel();
        let inputs = DriverInputs {
            sender,
            wake: shared.wake.clone(),
        };
        let handle = DriverHandle {
            shared: Arc::clone(&shared),
            inputs,
        };
        let (persist, persisted) = mpsc::channel();
        let (exec, executed) = mpsc::channel();
        let (serve, served) = mpsc::channel();
        let net = Arc::new(FakeNet::default());
        let workers = Workers {
            node_gate: Arc::clone(&shared.node_gate),
            net: net.clone(),
            observer: Arc::new(NoObserver),
            persist,
            exec,
            serve,
        };
        ready
            .send((
                handle,
                Arc::clone(&shared),
                executed,
                persisted,
                served,
                net,
            ))
            .unwrap_or_else(|_| panic!("leader loop inspection receiver"));
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        shared.wake.bind_current();
        kernel
            .exec
            .bind_release_waker(shared.wake.clone().into_waker());
        run_loop(kernel, &receiver, &shared, &clock, &workers)
    });
    let (handle, shared, executed, persisted, served, net) =
        received.recv_timeout(Duration::from_secs(5)).unwrap();
    LeaderLoop {
        handle,
        shared,
        executed,
        persisted,
        served,
        net,
        start,
        event_loop,
    }
}

/// A notification consumed before the first Build cannot swallow a later arrival while
/// that original operation is running: its EMPTY result must cause a fresh Build at once.
#[test]
fn actual_run_loop_reopens_transactions_before_build_and_preserves_empty_arrival() {
    use super::super::super::{Completion, exec::ExecDone};

    let fixture = spawn_leader_loop(false);
    for _ in 0..4_096 {
        fixture.handle.transactions_available();
    }
    fixture.start.send(()).unwrap();
    let first = fixture.executed.recv_timeout(Duration::from_secs(5));
    if matches!(first, Ok(ExecOp::DriveApplicationControl(_))) {
        fixture
            .handle
            .inputs
            .send(Input::Done(Completion::Exec(
                ExecDone::ApplicationControlDriven(Ok(None)),
            )))
            .unwrap();
    }
    let build = fixture.executed.recv_timeout(Duration::from_secs(5));
    let mut second = Err(mpsc::RecvTimeoutError::Timeout);
    if matches!(build, Ok(ExecOp::Build { .. })) {
        // The worker already holds the exact operation and can have read an empty queue.
        for _ in 0..4_096 {
            fixture.handle.transactions_available();
        }
        fixture
            .handle
            .inputs
            .send(Input::Done(Completion::Exec(ExecDone::Built(Ok(None)))))
            .unwrap();
        second = fixture.executed.recv_timeout(Duration::from_secs(5));
        if matches!(second, Ok(ExecOp::DriveApplicationControl(_))) {
            // The Tick also queued its normal application drive. Complete that original
            // operation so the fair scheduler can dispatch the renewed payload request.
            fixture
                .handle
                .inputs
                .send(Input::Done(Completion::Exec(
                    ExecDone::ApplicationControlDriven(Ok(None)),
                )))
                .unwrap();
            second = fixture.executed.recv_timeout(Duration::from_secs(5));
        }
    }
    let sent = fixture.net.sent();
    fixture.handle.inputs.send(Input::Stop).unwrap();
    let ended = fixture.event_loop.join();
    assert_eq!(ended.unwrap(), Ok(()), "natural ordered shutdown");
    assert!(matches!(first, Ok(ExecOp::DriveApplicationControl(_))));
    let Ok(ExecOp::Build {
        req: first_req,
        height: first_height,
        view: first_view,
        ..
    }) = build
    else {
        panic!("first actual Build: {build:?}");
    };
    let Ok(ExecOp::Build {
        req: next_req,
        height: next_height,
        view: next_view,
        ..
    }) = second
    else {
        panic!("EMPTY followed by an arrival must dispatch a new Build: {second:?}");
    };
    assert_ne!(first_req, next_req);
    assert_eq!((first_height, first_view), (1, 0));
    assert_eq!((next_height, next_view), (first_height, first_view));
    assert!(
        sent.iter().all(|(_, message)| !matches!(
            message,
            WireMessage::Proposal(_) | WireMessage::Vote(_)
        )),
        "an EMPTY answer cannot publish a proposal or vote"
    );
}

/// All finite FIFO completions precede the due Tick, including recovery behind a large
/// notification/completion prefix. Terminal recovery must still suppress sends and Build.
#[test]
fn actual_run_loop_drains_terminal_recovery_before_due_tick_dispatch() {
    use super::super::super::{
        Completion, exec::ExecDone, serve::Served, traits::PublicationError,
    };
    use iroha_sumeragi::api::HaltReason;

    let fixture = spawn_leader_loop(true);
    for _ in 0..4_096 {
        fixture.handle.transactions_available();
        fixture
            .handle
            .inputs
            .send(Input::Done(Completion::Served(Served::default())))
            .unwrap();
    }
    fixture
        .handle
        .inputs
        .send(Input::Done(Completion::Exec(
            ExecDone::ApplicationControlDriven(Err(PublicationError::RecoveryRequired(
                "exact worker owner consumed".into(),
            ))),
        )))
        .unwrap();
    fixture.start.send(()).unwrap();
    let began = std::time::Instant::now();
    let halt = Some(HaltReason::PublicationRecoveryRequired { height: 1 });
    while fixture
        .shared
        .status
        .lock()
        .as_ref()
        .is_none_or(|status| status.halted != halt)
        && began.elapsed() < Duration::from_secs(5)
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    let status = fixture.shared.status.lock().clone();
    let persisted: Vec<_> = fixture.persisted.try_iter().collect();
    let executed: Vec<_> = fixture.executed.try_iter().collect();
    let sent = fixture.net.sent();
    let _serving: Vec<_> = fixture.served.try_iter().collect();
    fixture.handle.inputs.send(Input::Stop).unwrap();
    let ended = fixture.event_loop.join();
    assert_eq!(ended.unwrap(), Ok(()), "natural ordered shutdown");
    let status = status.expect("actual loop published the recovery status");
    assert_eq!(status.halted, halt);
    assert_eq!(
        (status.height, status.view, status.applied_height),
        (1, 0, 0)
    );
    assert!(
        !persisted.is_empty(),
        "original safety persistence survives recovery"
    );
    assert!(
        executed.is_empty(),
        "no worker operation starts after recovery"
    );
    assert!(
        sent.is_empty(),
        "no consensus output escapes the queued terminal completion"
    );
}

/// Observes original worker dispatch at the next clock read, without moving any Kernel
/// across threads. One arrival is injected in the completion drain preceding the Build.
struct BuildDispatchClock {
    handle: DriverHandle,
    executed: Mutex<mpsc::Receiver<ExecOp>>,
    first_drive: std::sync::atomic::AtomicBool,
    inject_after_reads: std::sync::atomic::AtomicUsize,
    paused_build: std::sync::atomic::AtomicBool,
    builds: mpsc::Sender<ExecOp>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl Clock for BuildDispatchClock {
    fn now(&self) -> Millis {
        use super::super::super::{Completion, exec::ExecDone};
        use std::sync::atomic::Ordering;

        if self.inject_after_reads.load(Ordering::Acquire) > 0
            && self.inject_after_reads.fetch_sub(1, Ordering::AcqRel) == 1
        {
            // The first post-Tick read timestamps its original worker completion.
            // This notification enters the same finite FIFO drain before Build dispatch.
            self.handle.transactions_available();
        }
        loop {
            let operation = self.executed.lock().try_recv();
            match operation {
                Ok(ExecOp::DriveApplicationControl(_)) => {
                    if self.first_drive.swap(false, Ordering::AcqRel) {
                        // One read remains in the first Tick turn; the next is completion.
                        self.inject_after_reads.store(2, Ordering::Release);
                    }
                    self.handle
                        .inputs
                        .send(Input::Done(Completion::Exec(
                            ExecDone::ApplicationControlDriven(Ok(None)),
                        )))
                        .unwrap();
                }
                Ok(op @ ExecOp::Build { .. }) => {
                    self.builds.send(op).unwrap();
                    if !self.paused_build.swap(true, Ordering::AcqRel) {
                        self.release
                            .lock()
                            .recv_timeout(Duration::from_secs(5))
                            .expect("the test releases the first actual Build dispatch turn");
                    }
                }
                Ok(other) => panic!("unexpected original worker operation: {other:?}"),
                Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => break,
            }
        }
        iroha_sumeragi::types::ChainParams::default().block_time
    }
}

/// Reopening after dispatch is too late: the real worker may have read EMPTY before
/// a new transaction arrives while the loop is still finishing that scheduling turn.
#[test]
fn actual_run_loop_retains_build_arrival_before_dispatch_turn_finishes() {
    use super::super::super::{Completion, exec::ExecDone};

    let (ready, received) = mpsc::sync_channel(1);
    let (release, released) = mpsc::channel();
    let (built, builds) = mpsc::channel();
    let event_loop = std::thread::spawn(move || {
        let budget = super::super::test_budget();
        let original_bytes = budget.reserved_bytes();
        let (mut kernel, _) = start_leader_kernel();
        let shared = Arc::new(Shared {
            node_gate: Arc::new(NodeGate::new()),
            allocation_budget: budget.clone(),
            pending_admission: Mutex::new(
                PendingAdmission::admit(&budget, Backoff::default()).unwrap(),
            ),
            instance: kernel.instance,
            own: vec![kernel.core().status().signer.clone().unwrap()],
            ingress: Arc::clone(&kernel.ingress),
            frame_limit: usize::try_from(kernel.frame_limit).unwrap(),
            status: Mutex::new(None),
            backlog: Mutex::new(Backlog::default()),
            wake: ThreadWake::admit(&budget).unwrap(),
            transactions_pending: std::sync::atomic::AtomicBool::new(false),
            empty_waiting: std::sync::atomic::AtomicBool::new(false),
            empty_epoch: std::sync::atomic::AtomicU64::new(0),
            alive: std::sync::atomic::AtomicBool::new(true),
            stopped: Mutex::new(None),
            metrics: None,
        });
        let (sender, receiver) = mpsc::channel();
        let handle = DriverHandle {
            shared: Arc::clone(&shared),
            inputs: DriverInputs {
                sender,
                wake: shared.wake.clone(),
            },
        };
        let (exec, executed) = mpsc::channel();
        let (persist, persisted) = mpsc::channel();
        let (serve, served) = mpsc::channel();
        let net = Arc::new(FakeNet::default());
        let workers = Workers {
            node_gate: Arc::clone(&shared.node_gate),
            net: net.clone(),
            observer: Arc::new(NoObserver),
            persist,
            exec,
            serve,
        };
        let clock = BuildDispatchClock {
            handle: handle.clone(),
            executed: Mutex::new(executed),
            first_drive: std::sync::atomic::AtomicBool::new(true),
            inject_after_reads: std::sync::atomic::AtomicUsize::new(0),
            paused_build: std::sync::atomic::AtomicBool::new(false),
            builds: built,
            release: Mutex::new(released),
        };
        // An earlier availability signal must not swallow the later in-Build signal.
        handle.transactions_available();
        ready
            .send((
                handle,
                shared.clone(),
                budget,
                original_bytes,
                persisted,
                served,
                net,
            ))
            .unwrap_or_else(|_| panic!("Build dispatch inspection receiver"));
        shared.wake.bind_current();
        kernel
            .exec
            .bind_release_waker(shared.wake.clone().into_waker());
        run_loop(kernel, &receiver, &shared, &clock, &workers)
    });
    let (handle, shared, budget, original_bytes, persisted, served, net) =
        received.recv_timeout(Duration::from_secs(5)).unwrap();
    let first = builds.recv_timeout(Duration::from_secs(5));
    if first.is_ok() {
        // Clock rendezvous holds the actual loop after dispatch, before its turn finishes.
        for _ in 0..4_096 {
            handle.transactions_available();
        }
        handle
            .inputs
            .send(Input::Done(Completion::Exec(ExecDone::Built(Ok(None)))))
            .unwrap();
    }
    let released = release.send(());
    let next = builds.recv_timeout(Duration::from_secs(5));
    handle.inputs.send(Input::Stop).unwrap();
    let ended = event_loop.join();
    let sent = net.sent();
    drop((handle, shared, persisted, served, net));
    assert_eq!(ended.unwrap(), Ok(()), "natural ordered shutdown");
    assert!(released.is_ok(), "actual dispatch rendezvous was released");
    let Ok(ExecOp::Build {
        req: first_req,
        height: first_height,
        view: first_view,
        ..
    }) = first
    else {
        panic!("first original dispatch: {first:?}");
    };
    let Ok(ExecOp::Build {
        req: next_req,
        height: next_height,
        view: next_view,
        ..
    }) = next
    else {
        panic!("in-Build arrival must follow EMPTY with a fresh dispatch: {next:?}");
    };
    assert_ne!(first_req, next_req);
    assert_eq!((first_height, first_view), (1, 0));
    assert_eq!((next_height, next_view), (first_height, first_view));
    assert!(
        sent.iter().all(|(_, message)| !matches!(
            message,
            WireMessage::Proposal(_) | WireMessage::Vote(_)
        )),
        "EMPTY cannot become a block"
    );
    drop(sent);
    assert_eq!(
        budget.reserved_bytes(),
        original_bytes,
        "original pool and wake ownership refund"
    );
}
