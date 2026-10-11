//! The full driver on its threads over the fake backends: a single validator's chain commits
//! with failing and panicking writes and apply steps retried; a stopped worker stops the
//! instance; O9 — two instances in one process, one stalled (its executor never returns) and
//! flooded, the other committing on time; §12.2 serving under a `SyncRequest` flood with the
//! node's own body fetch served on time; O10 frame limits at start and after a committed
//! parameter change; raw-frame delivery; `Init` assembly from the block store.

use std::{
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use iroha_sumeragi::{
    api::{ExecOutcome, HaltReason, LocalParams},
    crypto::Signer,
    message::{PayloadRequest, Status, SyncRequest, VoteKind, WireMessage},
    safety::RecordState,
    sim::driver::block_exec,
    testing::{FakeCrypto, FakeSigner, FakeValidators},
    types::{ChainParams, Committee, Hash32, HeightConfig, PublicKey},
};

use super::{
    super::{
        Driver, DriverConfig, DriverError, DriverHandle, DriverStart, ExitGuard, Input, NodeGate,
        Op, RunningDriver, SharedCrypto, Worker, Workers, assemble_init,
        exec::ExecOp,
        persist::install_records,
        traits::{BlockStore, Clock, NoObserver, Observer, SystemClock},
    },
    block, commit_qc,
    fakes::{
        FakeBlocks, FakeBodies, FakeClock, FakeExecutor, FakeNet, FakeRecords, RecordingObserver,
        WorkPump,
    },
    hash,
};

fn params() -> ChainParams {
    ChainParams {
        block_time: 10,
        payload_retry_interval: 30,
        ..ChainParams::default()
    }
}

/// The fakes of one instance, shared with its test.
#[derive(Clone)]
struct Fakes {
    exec: FakeExecutor,
    net: Arc<FakeNet>,
    records: Arc<FakeRecords>,
    bodies: Arc<FakeBodies>,
    blocks: Arc<FakeBlocks>,
    observer: Arc<RecordingObserver>,
}

/// One single-validator instance on its threads.
struct Instance {
    running: RunningDriver,
    key: PublicKey,
    instance: Hash32,
    fakes: Fakes,
}

impl Instance {
    fn handle(&self) -> DriverHandle {
        self.running.handle()
    }

    fn committed(&self) -> u64 {
        self.handle().status().map_or(0, |s| s.committed_height)
    }

    /// Keep work queued until the pump is dropped (blocks are work-driven, §6.10).
    fn pump(&self) -> WorkPump {
        self.fakes.exec.pump(self.handle())
    }
}

/// A fresh instance `tag` whose key was generated on the node; `prepare` may set up failures
/// or a closed executor gate before it starts.
fn spawn_instance<C: Clock + 'static>(
    tag: u8,
    clock: Arc<C>,
    prepare: impl FnOnce(&Fakes),
) -> Instance {
    let signer = FakeSigner::from_seed(&[tag], None);
    let key = signer.public_key().clone();
    let crypto: SharedCrypto = Arc::new(FakeCrypto::new());
    let instance = Hash32([tag; 32]);
    let config = HeightConfig {
        epoch: Box::new(iroha_sumeragi::testing::TEST_EPOCH),
        committee: Committee::new(vec![key.clone()]).unwrap(),
        params: params(),
    };
    let records = Arc::new(FakeRecords::default());
    records.install_key(&key, true, 1);
    let mut next = 1u128;
    let mut fresh = || {
        next += 1;
        next
    };
    let found = install_records(
        &*records,
        &*crypto,
        &instance,
        iroha_sumeragi::testing::TEST_EPOCH.id,
        &[(key.clone(), false)],
        0,
        false,
        &mut fresh,
    )
    .unwrap();
    assert!(matches!(found[0].1, RecordState::Present(_)));
    let blocks = Arc::new(FakeBlocks::default());
    let genesis = (Hash32([tag ^ 0x11; 32]), Hash32([tag ^ 0x22; 32]));
    let init = assemble_init(
        &*blocks,
        instance,
        0,
        genesis,
        128,
        found,
        vec![
            (1, iroha_sumeragi::types::ConfigSlot::Ready(config.clone())),
            (2, iroha_sumeragi::types::ConfigSlot::Ready(config.clone())),
        ],
        u64::from(tag),
    )
    .unwrap();
    let fakes = Fakes {
        exec: FakeExecutor::new(genesis.0, genesis.1, config),
        net: Arc::new(FakeNet::default()),
        records,
        bodies: Arc::new(FakeBodies::default()),
        blocks,
        observer: Arc::new(RecordingObserver::default()),
    };
    prepare(&fakes);
    let observer: Arc<dyn Observer> = fakes.observer.clone();
    let driver = Driver::new(
        Arc::clone(&fakes.net),
        Arc::clone(&fakes.records),
        Arc::clone(&fakes.bodies),
        Arc::clone(&fakes.blocks),
        clock,
        fakes.exec.clone(),
        observer,
    );
    let running = driver
        .spawn(
            DriverConfig::default(),
            DriverStart {
                node_gate: Arc::new(NodeGate::new()),
                allocation_budget: super::test_budget(),
                local: LocalParams::default(),
                init,
                signers: vec![Arc::new(signer)],
                crypto,
            },
        )
        .unwrap();
    Instance {
        running,
        key,
        instance,
        fakes,
    }
}

fn wait_until(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < limit, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn backend_owners_released(fakes: &Fakes) -> bool {
    Arc::strong_count(&fakes.records) == 1
        && Arc::strong_count(&fakes.bodies) == 1
        && Arc::strong_count(&fakes.blocks) == 1
        && Arc::strong_count(&fakes.net) == 1
        && Arc::strong_count(&fakes.exec.state) == 1
        && Arc::strong_count(&fakes.observer) == 1
}

fn assert_driver_retired(handle: &DriverHandle, fakes: &Fakes) {
    assert!(
        !handle.ready(),
        "retained delivery handles cannot keep the driver running"
    );
    assert!(
        backend_owners_released(fakes),
        "all physical worker backend owners were released"
    );
    assert_eq!(handle.stopped(), None);
    assert!(fakes.observer.stopped.lock().is_empty());
    assert_eq!(
        *fakes.observer.finished.lock(),
        1,
        "exactly one orderly completion"
    );
}

/// The final running owner joins every physical worker before returning, even
/// when a public delivery handle keeps the input channel connected.
#[test]
fn dropping_running_owner_stops_and_joins_with_retained_handle() {
    let Instance { running, fakes, .. } = spawn_instance(231, Arc::new(SystemClock::new()), |_| {});
    let handle = running.handle();
    assert!(handle.ready());
    drop(running);
    assert_driver_retired(&handle, &fakes);
}

/// Caller panic retires the same real worker owner without an explicit shutdown
/// and without converting orderly completion into a worker-failure report.
#[test]
fn caller_unwind_stops_and_joins_running_owner_with_retained_handle() {
    let Instance { running, fakes, .. } = spawn_instance(232, Arc::new(SystemClock::new()), |_| {});
    let handle = running.handle();
    assert!(handle.ready());
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _running = running;
        panic!("caller unwinds with the original running driver owner");
    }));
    assert!(unwind.is_err());
    assert_driver_retired(&handle, &fakes);
}

/// A real backend callback can own the running instance. It must return before
/// its own worker and the loop's remaining channel owners can be joined.
#[test]
fn worker_callback_drop_transfers_all_original_joins_without_self_deadlock() {
    struct DropOwnerClock {
        clock: SystemClock,
        running: parking_lot::Mutex<Option<RunningDriver>>,
        retired: mpsc::SyncSender<std::thread::ThreadId>,
    }
    impl Clock for DropOwnerClock {
        fn now(&self) -> iroha_sumeragi::types::Millis {
            let running = self.running.lock().take();
            if let Some(running) = running {
                drop(running);
                let _ = self.retired.send(std::thread::current().id());
            }
            self.clock.now()
        }
    }
    let (retired, receive) = mpsc::sync_channel(1);
    let clock = Arc::new(DropOwnerClock {
        clock: SystemClock::new(),
        running: parking_lot::Mutex::new(None),
        retired,
    });
    let Instance { running, fakes, .. } = spawn_instance(233, Arc::clone(&clock), |_| {});
    let handle = running.handle();
    assert!(handle.ready());
    let loop_thread = running.threads.last().unwrap().thread().id();
    *clock.running.lock() = Some(running);
    handle.transactions_available();
    assert_eq!(
        receive
            .recv_timeout(Duration::from_secs(5))
            .expect("the real loop callback returns"),
        loop_thread,
    );
    wait_until(
        "all reentrant worker owners retired",
        Duration::from_secs(5),
        || !handle.ready() && backend_owners_released(&fakes),
    );
    assert_driver_retired(&handle, &fakes);
}

/// A single validator commits through the whole driver — persistence, executor and serve
/// threads, the loop and the barrier — while record, body and block-store writes and apply
/// steps fail and are retried (never skipped); transactions reach blocks.
#[test]
fn single_validator_commits_through_failures() {
    let node = spawn_instance(1, Arc::new(SystemClock::new()), |fakes| {
        fakes.records.fail_next(3);
        fakes.bodies.fail_next(2);
        fakes.blocks.fail_next(2);
        fakes.exec.state.lock().fail_apply = 2;
    });
    assert!(node.handle().ready());
    for id in 0..20 {
        node.fakes.exec.add_tx(id);
    }
    node.handle().transactions_available();
    wait_until("the transactions applied", Duration::from_secs(20), || {
        node.fakes.exec.state.lock().txs.is_empty()
    });
    let work = node.pump();
    wait_until("20 heights", Duration::from_secs(20), || {
        node.committed() >= 20
    });
    drop(work);
    let status = node.handle().status().unwrap();
    assert!(status.halted.is_none() && node.handle().halted().is_none());
    assert!(
        node.fakes.blocks.height() >= 19,
        "applied heights are in the block store"
    );
    assert!(node.fakes.records.writes() > 0);
    let payloads = (1..=node.fakes.blocks.height())
        .filter_map(|h| node.fakes.blocks.entry(h).unwrap())
        .filter(|e| e.manifest.header.payload_len > 0)
        .count();
    assert!(payloads > 0, "transactions were included");
    assert!(
        (1..=node.fakes.blocks.height())
            .filter_map(|h| node.fakes.blocks.entry(h).unwrap())
            .all(|e| e.manifest.header.payload_len > 0),
        "blocks are never empty"
    );
    assert!(node.fakes.bodies.len() <= 4, "applied bodies are pruned");
    node.running.shutdown();
}

/// O9: instance A's executor never returns and its ingress is flooded; instance B, in the same
/// process, commits on time, and delivering to A never blocks (the flood is bounded, O6).
#[test]
fn stalled_and_flooded_instance_does_not_delay_another() {
    let a = spawn_instance(3, Arc::new(SystemClock::new()), |fakes| {
        fakes.exec.set_open(false)
    });
    let b = spawn_instance(4, Arc::new(SystemClock::new()), |_| {});
    let flood = {
        let handle = a.handle();
        let instance = a.instance;
        std::thread::spawn(move || {
            let start = Instant::now();
            let mut longest = 0;
            for i in 0..20_000u64 {
                let peer = PublicKey::new(vec![u8::try_from(i % 50).unwrap(); 32]).unwrap();
                let msg = if i % 2 == 0 {
                    WireMessage::PayloadRequest(PayloadRequest {
                        instance,
                        height: i,
                        block_hash: Hash32::ZERO,
                    })
                } else {
                    WireMessage::Status(Box::new(Status {
                        instance,
                        height: i,
                        view: 0,
                        committed_qc: None,
                        high_pqc: None,
                        high_tc: None,
                        proposal_hash: None,
                        want_proposal: false,
                        probe: None,
                        echo: None,
                    }))
                };
                handle.deliver_message(peer, msg);
                longest = longest.max(handle.shared.ingress.lock().len());
            }
            (start.elapsed(), longest)
        })
    };
    let _a_work = a.pump();
    let _b_work = b.pump();
    let start = Instant::now();
    wait_until("B commits 20 heights", Duration::from_secs(20), || {
        b.committed() >= 20
    });
    let b_time = start.elapsed();
    let (flood_time, longest) = flood.join().unwrap();
    assert!(
        flood_time < Duration::from_secs(10),
        "delivery never blocks: {flood_time:?}"
    );
    assert_eq!(a.committed(), 0, "A is stalled");
    // Whether A's loop fell behind the flood is a matter of timing; its queues are bounded
    // either way (256 control messages per peer; the drops themselves: `ingress` tests).
    assert!(longest <= 50 * 256, "A's ingress is bounded: {longest}");
    assert!(b_time < Duration::from_secs(20));
    // A recovers once its executor returns.
    a.fakes.exec.set_open(true);
    wait_until("A commits", Duration::from_secs(20), || a.committed() >= 3);
    a.running.shutdown();
    b.running.shutdown();
}

/// Every timer of the driver follows its `Clock` backend: with the local clock stopped a chain
/// with pending work makes no block, and once it runs heights commit.
#[test]
fn timers_follow_the_clock_backend() {
    let clock = Arc::new(FakeClock::default());
    let node = spawn_instance(7, Arc::clone(&clock), |_| {});
    let _work = node.pump();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(node.committed(), 0, "no local time passed");
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let runner = {
        let (clock, stop) = (Arc::clone(&clock), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                clock.advance(10);
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    };
    wait_until("heights", Duration::from_secs(30), || node.committed() >= 3);
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    runner.join().unwrap();
    assert!(clock.now() > 0);
    node.running.shutdown();
}

/// Raw frames: decoded by the driver within the class limit; garbage, the node's own frames
/// and other instances' are refused.
#[test]
fn raw_frames_are_decoded_and_filtered() {
    let node = spawn_instance(5, Arc::new(SystemClock::new()), |fakes| {
        fakes.exec.set_open(false)
    });
    let handle = node.handle();
    let request = |instance| {
        WireMessage::PayloadRequest(PayloadRequest {
            instance,
            height: 1,
            block_hash: Hash32::ZERO,
        })
        .encode()
        .unwrap()
    };
    let peer = PublicKey::new(vec![9; 32]).unwrap();
    assert!(handle.deliver(&peer, &request(node.instance)));
    assert!(!handle.deliver(&peer, b"garbage"));
    assert!(!handle.deliver(&node.key, &request(node.instance)), "O7");
    assert!(!handle.deliver(&peer, &request(Hash32([0xee; 32]))));
    node.fakes.exec.set_open(true);
    node.running.shutdown();
}

/// O10: a transport limit below the chain parameters' needs refuses the start.
#[test]
fn frame_limit_below_parameters_is_refused() {
    let signer = FakeSigner::from_seed(&[6], None);
    let key = signer.public_key().clone();
    let config = HeightConfig {
        epoch: Box::new(iroha_sumeragi::testing::TEST_EPOCH),
        committee: Committee::new(vec![key.clone()]).unwrap(),
        params: params(),
    };
    let blocks = Arc::new(FakeBlocks::default());
    let init = assemble_init(
        &*blocks,
        Hash32([6; 32]),
        0,
        (Hash32([1; 32]), Hash32([2; 32])),
        128,
        vec![(key, RecordState::Absent, false)],
        vec![
            (1, iroha_sumeragi::types::ConfigSlot::Ready(config.clone())),
            (2, iroha_sumeragi::types::ConfigSlot::Ready(config.clone())),
        ],
        1,
    )
    .unwrap();
    let exec = FakeExecutor::new(Hash32([1; 32]), Hash32([2; 32]), config);
    let driver = Driver::new(
        Arc::new(FakeNet::default()),
        Arc::new(FakeRecords::default()),
        Arc::new(FakeBodies::default()),
        blocks,
        Arc::new(SystemClock::new()),
        exec,
        Arc::new(NoObserver),
    );
    let config = DriverConfig {
        frame_limit: 1024,
        ..DriverConfig::default()
    };
    let refused = driver.spawn(
        config,
        DriverStart {
            node_gate: Arc::new(NodeGate::new()),
            allocation_budget: super::test_budget(),
            local: LocalParams::default(),
            init,
            signers: vec![Arc::new(signer)],
            crypto: Arc::new(FakeCrypto::new()),
        },
    );
    assert!(matches!(refused, Err(DriverError::FrameLimit { .. })));
}

/// Startup checks the mandatory signed epoch layout, with no detached driver layout.
#[test]
fn a_signed_epoch_layout_below_the_block_bound_is_refused() {
    use iroha_sumeragi::{
        api::ConfigError,
        availability::{LayoutError, recommended_data_availability_layout},
    };
    let signer = FakeSigner::from_seed(&[7], None);
    let key = signer.public_key().clone();
    let recommended = recommended_data_availability_layout();
    let mut small = recommended;
    small.max_payload_size_bytes = u64::from(params().max_block_bytes) - 1;
    let mut invalid = recommended;
    invalid.parity_shards = 0;
    for (layout, expected) in [
        (small, ConfigError::PayloadAboveAvailabilityLimit),
        (
            invalid,
            ConfigError::AvailabilityLayout(LayoutError::InvalidLayout),
        ),
    ] {
        let mut epoch = iroha_sumeragi::testing::TEST_EPOCH;
        epoch.da_layout = layout;
        let config = HeightConfig {
            epoch: Box::new(epoch),
            committee: Committee::new(vec![key.clone()]).unwrap(),
            params: params(),
        };
        let blocks = Arc::new(FakeBlocks::default());
        let init = assemble_init(
            &*blocks,
            Hash32([7; 32]),
            0,
            (Hash32([1; 32]), Hash32([2; 32])),
            128,
            vec![(key.clone(), RecordState::Absent, false)],
            vec![
                (1, iroha_sumeragi::types::ConfigSlot::Ready(config.clone())),
                (2, iroha_sumeragi::types::ConfigSlot::Ready(config.clone())),
            ],
            1,
        )
        .unwrap();
        let driver = Driver::new(
            Arc::new(FakeNet::default()),
            Arc::new(FakeRecords::default()),
            Arc::new(FakeBodies::default()),
            blocks,
            Arc::new(SystemClock::new()),
            FakeExecutor::new(Hash32([1; 32]), Hash32([2; 32]), config),
            Arc::new(NoObserver),
        );
        let refused = driver.spawn(
            DriverConfig::default(),
            DriverStart {
                node_gate: Arc::new(NodeGate::new()),
                allocation_budget: super::test_budget(),
                local: LocalParams::default(),
                init,
                signers: vec![Arc::new(signer.clone())],
                crypto: Arc::new(FakeCrypto::new()),
            },
        );
        assert!(
            matches!(refused, Err(DriverError::Config(error)) if error == expected),
            "{layout:?}"
        );
    }
}

/// `Init` from the block store: the tip with its header and `CommitQC`, the last `W + 2`
/// headers, and an error when an entry is missing.
#[test]
fn init_from_the_block_store() {
    let blocks = FakeBlocks::default();
    let (mut parent, mut parent_result) = (Hash32([1; 32]), Hash32([2; 32]));
    let mut headers = Vec::new();
    for h in 1..=5 {
        let b = block(
            h,
            parent,
            parent_result,
            iroha_sumeragi::sim::driver::encode_tx(0, false, 0),
        );
        let r = Hash32([u8::try_from(h).unwrap(); 32]);
        blocks.append(&b, &commit_qc(&b, r)).unwrap();
        headers.push(b.header().clone());
        (parent, parent_result) = (hash(&b), r);
    }
    let init = assemble_init(
        &blocks,
        Hash32([5; 32]),
        0,
        (Hash32([1; 32]), Hash32([2; 32])),
        1,
        Vec::new(),
        Vec::new(),
        9,
    )
    .unwrap();
    assert_eq!(init.tip.height, 5);
    assert_eq!(init.tip.block_hash, parent);
    assert_eq!(init.tip.result, parent_result);
    assert!(init.tip.commit_qc.is_some() && init.tip.header.is_some());
    assert_eq!(
        init.recent_headers,
        headers[2..].to_vec(),
        "W + 2 = 3 headers"
    );
    assert_eq!(init.nonce, 9);
    let empty = assemble_init(
        &FakeBlocks::default(),
        Hash32([5; 32]),
        0,
        (Hash32([1; 32]), Hash32([2; 32])),
        1,
        Vec::new(),
        Vec::new(),
        9,
    )
    .unwrap();
    assert_eq!(
        (empty.tip.height, empty.tip.block_hash),
        (0, Hash32([1; 32]))
    );
    assert!(empty.recent_headers.is_empty());
    assert!(
        matches!(
            super::super::startup_entry(&FakeBlocks::default(), 1),
            Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                super::super::StartupHistoryError::Missing { height: 1 }
            ))
        ),
        "a completed absent read remains distinct from local read refusal"
    );
}

/// §12.5: backends that panic — a record write, a block-store append and read — fail like I/O
/// errors and are retried; the instance keeps committing, nothing stops and nothing is
/// reported stopped.
#[test]
fn panicking_backends_are_retried() {
    let node = spawn_instance(8, Arc::new(SystemClock::new()), |fakes| {
        fakes.records.panic_next(2);
        fakes.blocks.panic_appends(2);
        fakes.blocks.panic_reads(1);
    });
    let work = node.pump();
    wait_until("10 heights", Duration::from_secs(20), || {
        node.committed() >= 10
    });
    let handle = node.handle();
    assert!(handle.ready(), "{:?}", handle.stopped());
    assert_eq!(handle.stopped(), None);
    assert!(node.fakes.observer.stopped.lock().is_empty());
    assert!(node.fakes.blocks.height() >= 9);
    drop(work);
    node.running.shutdown();
    assert!(!handle.ready(), "a shut-down instance is not ready");
    assert_eq!(*node.fakes.observer.finished.lock(), 1);
}

/// A worker thread that ends stops the instance: the loop stops, the observer is told, the
/// handle is no longer ready and reports the halt as a driver anomaly.
#[test]
fn a_stopped_worker_stops_the_instance() {
    let node = spawn_instance(9, Arc::new(SystemClock::new()), |_| {});
    let handle = node.handle();
    let _work = node.pump();
    wait_until("a height", Duration::from_secs(20), || {
        node.committed() >= 1
    });
    assert!(handle.ready());
    handle.inputs.send(Input::Exited(Worker::Exec)).unwrap();
    wait_until("the stop", Duration::from_secs(5), || !handle.ready());
    assert_eq!(handle.stopped(), Some(Worker::Exec));
    assert_eq!(handle.halted(), Some(HaltReason::DriverAnomaly));
    assert_eq!(*node.fakes.observer.stopped.lock(), vec![Worker::Exec]);
    let height = node.committed();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(node.committed(), height, "the instance no longer runs");
    node.running.shutdown();
    assert_eq!(
        *node.fakes.observer.finished.lock(),
        0,
        "worker failure is not orderly completion"
    );
}

/// A worker thread that ends announces it (however it ends), and a worker that cannot be
/// reached is reported by the dispatch rather than dropping the operation silently.
#[test]
fn worker_exits_and_unreachable_workers_are_detected() {
    let budget = iroha_allocation::AllocationBudget::new(
        iroha_allocation::ChargedShared::<super::super::ThreadWake>::allocation_layout().size(),
    );
    let wake = super::super::ThreadWake::admit(&budget).unwrap();
    let (tx, rx) = mpsc::channel();
    drop(ExitGuard {
        worker: Worker::Persist,
        tx: super::super::DriverInputs { sender: tx, wake },
    });
    assert!(matches!(rx.try_recv(), Ok(Input::Exited(Worker::Persist))));
    assert_eq!(budget.reserved_bytes(), 0);
    let (persist, _) = mpsc::channel();
    let (exec, exec_rx) = mpsc::channel();
    let (serve, serve_rx) = mpsc::channel();
    drop(serve_rx);
    let workers = Workers {
        node_gate: Arc::new(NodeGate::new()),
        net: Arc::new(FakeNet::default()),
        observer: Arc::new(NoObserver),
        persist,
        exec,
        serve,
    };
    let discard = || ExecOp::Discard {
        height: 1,
        keep: Vec::new(),
    };
    assert_eq!(workers.dispatch(vec![Op::Exec(discard())]), Ok(()));
    drop(exec_rx);
    assert_eq!(
        workers.dispatch(vec![Op::Exec(discard())]),
        Err(Worker::Exec)
    );
    let fetch = super::super::serve::ServeRequest::Payload(Box::new(
        super::super::payload_worker::PayloadWork::Fetch {
            source: super::source(1, Hash32::ZERO),
            peers: Vec::new(),
        },
    ));
    assert_eq!(workers.dispatch(vec![Op::Serve(fetch)]), Err(Worker::Serve));
}

/// §12.2 serving limits on the real threads: member 0 of a four-member committee, on a slow
/// disk (every block-store read takes 20 ms), is flooded with 10 000 `SyncRequest`s from 50
/// peers. Its own `FetchPayload` for a body it lacks under a `CommitQC` still asks the peer at
/// once, it applies the block once the peer answers, and its serving queue stays bounded (a
/// FIFO would have queued 200 s of reads ahead of the fetch).
#[test]
fn serving_flood_does_not_delay_the_nodes_fetch() {
    let vals = FakeValidators::new(4, 11, None);
    let key = vals.key(0);
    let instance = Hash32([5; 32]);
    let crypto: SharedCrypto = Arc::new(vals.crypto.clone());
    let config = HeightConfig {
        epoch: Box::new(iroha_sumeragi::testing::TEST_EPOCH),
        committee: vals.committee.clone(),
        params: params(),
    };
    let records = Arc::new(FakeRecords::default());
    records.install_key(&key, true, 1);
    let mut next = 1u128;
    let mut fresh = || {
        next += 1;
        next
    };
    let found = install_records(
        &*records,
        &*crypto,
        &instance,
        iroha_sumeragi::testing::TEST_EPOCH.id,
        &[(key.clone(), false)],
        0,
        false,
        &mut fresh,
    )
    .unwrap();
    let blocks = Arc::new(FakeBlocks::default());
    let genesis = (Hash32([0xa0; 32]), Hash32([0xa1; 32]));
    let init = assemble_init(
        &*blocks,
        instance,
        0,
        genesis,
        128,
        found,
        vec![
            (1, iroha_sumeragi::types::ConfigSlot::Ready(config.clone())),
            (2, iroha_sumeragi::types::ConfigSlot::Ready(config.clone())),
        ],
        3,
    )
    .unwrap();
    blocks.set_read_delay(20);
    let net = Arc::new(FakeNet::default());
    let exec = FakeExecutor::new(genesis.0, genesis.1, config.clone());
    let driver = Driver::new(
        Arc::clone(&net),
        records,
        Arc::new(FakeBodies::default()),
        Arc::clone(&blocks),
        Arc::new(SystemClock::new()),
        exec,
        Arc::new(NoObserver),
    );
    let running = driver
        .spawn(
            DriverConfig::default(),
            DriverStart {
                node_gate: Arc::new(NodeGate::new()),
                allocation_budget: super::test_budget(),
                local: LocalParams::default(),
                init,
                signers: vec![Arc::new(vals.signer(0).clone())],
                crypto,
            },
        )
        .unwrap();
    let handle = running.handle();
    for round in 0..200u64 {
        for peer in 0..50u8 {
            let from = PublicKey::new(vec![peer; 32]).unwrap();
            let request = WireMessage::SyncRequest(SyncRequest {
                instance,
                from_height: round,
                max_count: u16::MAX,
                max_bytes: u32::MAX,
            });
            handle.deliver_message(from, request);
        }
    }
    std::thread::sleep(Duration::from_millis(100));
    let application_bytes = vec![4; 64];
    let header = iroha_sumeragi::message::BlockHeader {
        instance,
        epoch: config.epoch.id,
        height: 1,
        origin_view: 0,
        parent_hash: genesis.0,
        parent_result: genesis.1,
        payload_hash: iroha_sumeragi::preimage::payload_hash(&vals.crypto, &application_bytes),
        availability_digest: Hash32::ZERO,
        payload_len: application_bytes.len() as u32,
        proposer: 0,
        skipped_leaders: Vec::new(),
        control_witness: iroha_sumeragi::types::ControlWitness::empty(),
    };
    let b1 = iroha_sumeragi::testing::author_body(
        header,
        &application_bytes,
        &config,
        &super::test_budget(),
        &vals.crypto,
        vals.signer(0),
    );
    let ExecOutcome::Valid(r1) = block_exec(&genesis.1, &b1, &iroha_sumeragi::testing::TEST_EPOCH)
    else {
        panic!("the block executes")
    };
    let qc = vals.qc(
        VoteKind::Commit,
        &instance,
        1,
        0,
        &hash(&b1),
        &r1,
        &[1, 2, 3],
    );
    let status = Status {
        instance,
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
    let asked = Instant::now();
    handle.deliver_message(vals.key(1), WireMessage::Status(Box::new(status)));
    wait_until("the body request", Duration::from_secs(3), || {
        net.sent().iter().any(|(to, msg)| {
            *to == vals.key(1)
                && matches!(msg, WireMessage::PayloadRequest(r) if r.block_hash == hash(&b1))
        })
    });
    assert!(asked.elapsed() < Duration::from_secs(3));
    let backlog = handle.backlog();
    assert!(backlog.serve <= 2 * 50, "{backlog:?}");
    let response = super::row_messages(&b1);
    let matching_requests = || {
        net.sent()
            .iter()
            .filter(|(to, message)| {
                *to == vals.key(1)
                    && matches!(message, WireMessage::PayloadRequest(request)
                        if request.instance == instance
                            && request.height == 1
                            && request.block_hash == hash(&b1))
            })
            .count()
    };
    let mut answered_requests = matching_requests();
    assert!(
        answered_requests > 0,
        "the peer answers an actual body request"
    );
    // Preserve the original burst as a real transport-pressure probe. Local ingress
    // refusal is not a promise of delivery; the peer must answer later exact fetches.
    let initial_admission: Vec<_> = response
        .iter()
        .map(|message| handle.deliver_message(vals.key(1), message.clone()))
        .collect();
    let applied_start = Instant::now();
    let mut next_response_frame = None;
    let mut retry_attempts = 0;
    let mut retry_admitted = 0;
    while !handle
        .status()
        .is_some_and(|status| status.applied_height >= 1)
    {
        let requests = matching_requests();
        assert!(
            applied_start.elapsed() < Duration::from_secs(5),
            "timed out waiting for height 1 applied; initial admission={initial_admission:?}, \
             requests={requests}, answered={answered_requests}, retry attempts={retry_attempts}, \
             retry admitted={retry_admitted}, status={:?}, halt={:?}, stopped={:?}, backlog={:?}",
            handle.status(),
            handle.halted(),
            handle.stopped(),
            handle.backlog(),
        );
        if next_response_frame.is_none() && requests > answered_requests {
            answered_requests = requests;
            next_response_frame = Some(0);
        }
        // Stream one unchanged signed manifest/actual row per turn. A rejected local
        // delivery retains that exact response frame; no new fetch or body is invented.
        if let Some(index) = next_response_frame {
            retry_attempts += 1;
            if handle.deliver_message(vals.key(1), response[index].clone()) {
                retry_admitted += 1;
                next_response_frame = (index + 1 < response.len()).then_some(index + 1);
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    eprintln!(
        "serving-flood response: initial admission={initial_admission:?}, \
         answered requests={answered_requests}, retry attempts={retry_attempts}, \
         retry admitted={retry_admitted}, apply elapsed={:?}",
        applied_start.elapsed(),
    );
    assert!(blocks.reads() < 10_000, "most requests were never read");
    let dropped = handle.backlog().serve_dropped;
    assert!(dropped > 0, "the flood was dropped, not queued");
    running.shutdown();
}

/// O10 at run time: every frame is decoded within the transport limit, so a committed rise of
/// `max_block_bytes` (4 MiB to 8 MiB) is followed without a restart; a configuration above the
/// transport limit is reported to the observer.
#[test]
fn frame_limit_follows_committed_configurations() {
    let node = spawn_instance(10, Arc::new(SystemClock::new()), |_| {});
    let handle = node.handle();
    let _work = node.pump();
    wait_until("a height", Duration::from_secs(20), || {
        node.committed() >= 1
    });
    let raise = |bytes: u32| {
        let mut state = node.fakes.exec.state.lock();
        state.config.params.max_block_bytes = bytes;
    };
    raise(8 << 20);
    let from = node.committed();
    wait_until("the new size in force", Duration::from_secs(20), || {
        node.committed() >= from + 3
    });
    let peer = PublicKey::new(vec![9; 32]).unwrap();
    let response = |bytes: usize| {
        WireMessage::PayloadChunk(iroha_sumeragi::message::PayloadChunk {
            instance: node.instance,
            height: 1,
            block_hash: Hash32::ZERO,
            index: 0,
            bytes: iroha_sumeragi::availability::RowBytes::from_untrusted(vec![0; bytes]).unwrap(),
        })
        .encode()
        .unwrap()
    };
    assert!(
        handle.deliver(&peer, &response(256 << 10)),
        "a maximum legal RS16 row decodes under the committed block limit"
    );
    assert!(
        !handle.deliver(&peer, &vec![0; 17 << 20]),
        "above the transport limit"
    );
    assert!(node.fakes.observer.frame_limits.lock().is_empty());
    raise(32 << 20);
    wait_until("the report", Duration::from_secs(20), || {
        !node.fakes.observer.frame_limits.lock().is_empty()
    });
    let exceeded = node.fakes.observer.frame_limits.lock()[0];
    assert_eq!(
        exceeded.needed,
        (32 << 20) + u64::from(iroha_sumeragi::pacemaker::FRAME_OVERHEAD)
    );
    assert_eq!(exceeded.limit, DriverConfig::default().frame_limit);
    node.running.shutdown();
}

/// A closed storage owner immediately closes the real handle and stops its loop.
#[test]
fn storage_closure_stops_native_driver_without_accepting_further_work() {
    let node = spawn_instance(29, Arc::new(SystemClock::new()), |fakes| {
        fakes.exec.set_open(false);
        fakes.exec.add_tx(17);
    });
    let handle = node.handle();
    handle.transactions_available();
    wait_until(
        "original worker operation is held",
        Duration::from_secs(5),
        || node.fakes.exec.waiting() == 1,
    );
    handle.shared.node_gate.close();
    assert!(!handle.ready());
    assert_eq!(handle.halted(), Some(HaltReason::DriverAnomaly));
    handle.transactions_available();
    assert!(!handle.deliver(&node.key, &[0; 32]));
    wait_until(
        "storage closure stops the event loop",
        Duration::from_secs(5),
        || {
            !handle
                .shared
                .alive
                .load(std::sync::atomic::Ordering::Acquire)
        },
    );
    assert_eq!(
        node.fakes.exec.waiting(),
        1,
        "closure never interrupts or replaces the original operation"
    );
    node.fakes.exec.set_open(true);
    node.running.shutdown();
    assert_eq!(
        node.fakes.exec.waiting(),
        0,
        "shutdown joins the original operation"
    );
    let height = node.fakes.blocks.height();
    let sent = node.fakes.net.sent().len();
    handle.transactions_available();
    assert!(!handle.ready());
    assert_eq!(node.fakes.blocks.height(), height);
    assert_eq!(node.fakes.net.sent().len(), sent);
    assert!(
        node.fakes.exec.state.lock().executions.is_empty(),
        "a buffered build result cannot start a successor execution after closure"
    );
}

/// Buffered operations cannot enter workers after closure, and the physical send wrapper
/// independently gates serving output that was prepared earlier.
#[test]
fn storage_closure_refuses_buffered_dispatch_and_each_physical_send() {
    let gate = Arc::new(NodeGate::new());
    let net = Arc::new(FakeNet::default());
    let (persist, persist_rx) = mpsc::channel();
    let (exec, exec_rx) = mpsc::channel();
    let (serve, serve_rx) = mpsc::channel();
    let workers = Workers {
        node_gate: Arc::clone(&gate),
        net: net.clone(),
        observer: Arc::new(NoObserver),
        persist,
        exec,
        serve,
    };
    let block = block(
        2,
        Hash32([1; 32]),
        Hash32([2; 32]),
        iroha_sumeragi::sim::driver::encode_tx(0, false, 0),
    );
    let message = WireMessage::Qc(commit_qc(&block, Hash32([3; 32])));
    let frame = super::super::serve::frame(&message).unwrap();
    let peer = FakeSigner::from_seed(&[3], None).public_key().clone();
    let physical = super::super::NodeNet {
        net: Arc::clone(&net),
        gate: Arc::clone(&gate),
    };
    assert!(matches!(
        super::super::traits::Net::send(&physical, &peer, &frame),
        super::super::traits::SendOutcome::Admitted
    ));
    assert_eq!(
        net.sent().len(),
        1,
        "open native sends reach the original transport"
    );
    gate.close();
    assert!(matches!(
        super::super::traits::Net::send(&physical, &peer, &frame),
        super::super::traits::SendOutcome::Closed
    ));
    assert_eq!(
        net.sent().len(),
        1,
        "closed serving cannot emit another frame"
    );
    assert_eq!(
        workers.dispatch(vec![Op::Exec(ExecOp::Discard {
            height: 2,
            keep: Vec::new()
        })]),
        Err(Worker::Loop)
    );
    assert_eq!(
        workers.dispatch(vec![Op::Send {
            to: vec![peer],
            msg: message
        }]),
        Err(Worker::Loop)
    );
    assert!(exec_rx.try_recv().is_err());
    assert!(persist_rx.try_recv().is_err());
    assert!(serve_rx.try_recv().is_err());
    assert_eq!(net.sent().len(), 1);
}

#[path = "threaded_transactions.rs"]
mod transactions;
