//! Real lane reconciliation retains blocked driver joins without stopping another lane's wake.

use super::*;
use crate::sumeragi::{
    crypto::BlsCrypto,
    lanes::{
        global::AppliedWatch,
        registry::{LaneStoreAuthorities, LaneStoreAuthority, LaneStores},
        runner::{LaneRunner, LaneRunnerInputs},
    },
    records::FileRecordStore,
    test_chain::CertifiedTestChain,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_model_base::topology::LaneId;
use std::{
    io,
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};

struct StartupAttempts(AtomicUsize);
impl LaneStoreAuthorities for StartupAttempts {
    fn authority(
        &self,
        _: LaneId,
        _: &[u8; 32],
        _: Hash32,
    ) -> Result<
        Option<LaneStoreAuthority>,
        crate::execution_attempt::ExecutionAttemptError<io::Error>,
    > {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("observed original lane startup authority boundary").into())
    }
}

fn runner(
    chain: &CertifiedTestChain,
    directory: &Path,
    attempts: Arc<StartupAttempts>,
) -> LaneRunner {
    let state = Arc::clone(chain.state());
    let crypto = Arc::new(BlsCrypto::new());
    let (_, time) = iroha_primitives::time::TimeSource::new_mock(Duration::ZERO);
    let stores = Arc::new(LaneStores::new(
        directory.join("lanes"),
        chain.network_id(),
        state.chain_id_ref().to_string(),
        crypto.clone(),
        state.ivm_execution_budget(),
        attempts,
    ));
    LaneRunner::for_retirement_test(LaneRunnerInputs {
        state: Arc::clone(&state),
        queue: Arc::new(crate::queue::Queue::test(
            iroha_config::parameters::actual::Queue::default(),
            &time,
        )),
        watch: Arc::new(AppliedWatch::new(
            chain.height(),
            state.view().latest_block_hash(),
        )),
        stores,
        crypto,
        net: Arc::new(FakeNet::default()),
        ingress: None,
        records: Arc::new(
            FileRecordStore::open(
                directory.join("records"),
                directory.join("keys/installation.log"),
            )
            .unwrap(),
        ),
        global_instance: chain.instance(),
        bodies_dir: directory.join("bodies"),
        key_pair: KeyPair::from_seed(vec![1; 32], Algorithm::BlsNormal),
        local: iroha_config::parameters::actual::SumeragiLocalOverrides::default(),
        driver: DriverConfig::default(),
        network: chain.network_id(),
        chain_id: state.chain_id_ref().to_string(),
    })
}

// A setup assertion or test unwind must release the real executor before any
// RunningDriver/LaneRunner owner tries to join it. Declare this after those owners.
struct OpenExecutorOnDrop(FakeExecutor);
impl Drop for OpenExecutorOnDrop {
    fn drop(&mut self) {
        self.0.set_open(true);
    }
}

fn observed_within(limit: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while !ready() {
        if start.elapsed() >= limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

#[test]
fn retiring_executor_does_not_block_other_lane_transaction_delivery() {
    let (chain, record, _epoch) =
        crate::sumeragi::runtime_availability::tests::npos_fixed_lane_chain_at(4);
    let directory = tempfile::tempdir().unwrap();
    let attempts = Arc::new(StartupAttempts(AtomicUsize::new(0)));
    let runner = runner(&chain, directory.path(), Arc::clone(&attempts));
    let a = spawn_instance(234, Arc::new(SystemClock::new()), |fakes| {
        fakes.exec.set_open(false)
    });
    let b = spawn_instance(235, Arc::new(SystemClock::new()), |_| {});
    let release = OpenExecutorOnDrop(a.fakes.exec.clone());
    let a_handle = a.handle();
    let b_handle = b.handle();
    a.fakes.exec.add_tx(1);
    a_handle.transactions_available();
    assert!(observed_within(Duration::from_secs(5), || a
        .fakes
        .exec
        .waiting()
        == 1));
    assert!(observed_within(Duration::from_secs(5), || b_handle
        .waiting_after_empty_for_test()));
    let retired_key = (LaneId::new(8), [0xe4; 32]);
    assert_ne!(retired_key.0, record.lane);
    runner.install_retirement_driver_for_test(retired_key, a.instance, a.running);
    runner.install_retirement_driver_for_test(
        (record.lane, record.incarnation),
        b.instance,
        b.running,
    );
    b.fakes.exec.add_tx(2);
    runner.handle().transactions_available();
    let (finished, observed) = mpsc::sync_channel(1);
    let (turn_completed, progressed, retained, hidden, joined) = std::thread::scope(|scope| {
        // This inner guard drops before scope joins on an unexpected unwind.
        let _scope_release = OpenExecutorOnDrop(release.0.clone());
        let lifecycle = scope.spawn(|| {
            runner.drive_retirement_for_test();
            let _ = finished.send(());
        });
        let completed = observed.recv_timeout(Duration::from_secs(1));
        let progressed = completed.is_ok()
            && observed_within(Duration::from_secs(5), || {
                b_handle
                    .status()
                    .is_some_and(|status| status.committed_height >= 1)
                    && b.fakes.exec.state.lock().txs.is_empty()
            });
        let retained = a.fakes.exec.waiting() == 1 && runner.retirement_owner_count_for_test() == 2;
        let instances = runner.instances();
        let hidden = instances.len() == 1 && instances[0].instance == b.instance;
        release.0.set_open(true);
        let joined = lifecycle.join();
        (completed, progressed, retained, hidden, joined)
    });
    joined.unwrap();
    let retired = observed_within(Duration::from_secs(5), || {
        runner.drive_retirement_for_test();
        runner.retirement_owner_count_for_test() == 1
    });
    runner.shutdown();
    drop(release);
    assert_driver_retired(&a_handle, &a.fakes);
    assert_driver_retired(&b_handle, &b.fakes);
    assert_eq!(
        turn_completed,
        Ok(()),
        "retired worker joins must not block the actual lane lifecycle turn"
    );
    assert!(
        progressed,
        "another lane's original queued transaction must commit while the retired executor remains blocked"
    );
    assert!(
        retained,
        "the exact retiring driver owner must remain retained until its workers finish"
    );
    assert!(
        hidden,
        "retiring instances must be absent from live instance observers"
    );
    assert!(
        retired,
        "completed original joins must be reaped on a later lifecycle turn"
    );
    assert_eq!(
        attempts.0.load(Ordering::SeqCst),
        0,
        "the already running independent lane is not restarted"
    );
}

#[test]
fn retiring_incarnation_blocks_same_lane_start_until_original_workers_finish() {
    let (chain, record, _epoch) =
        crate::sumeragi::runtime_availability::tests::npos_fixed_lane_chain_at(4);
    let directory = tempfile::tempdir().unwrap();
    let attempts = Arc::new(StartupAttempts(AtomicUsize::new(0)));
    let runner = runner(&chain, directory.path(), Arc::clone(&attempts));
    let a = spawn_instance(236, Arc::new(SystemClock::new()), |fakes| {
        fakes.exec.set_open(false)
    });
    let release = OpenExecutorOnDrop(a.fakes.exec.clone());
    let handle = a.handle();
    a.fakes.exec.add_tx(3);
    handle.transactions_available();
    assert!(observed_within(Duration::from_secs(5), || a
        .fakes
        .exec
        .waiting()
        == 1));
    let incarnation = [0xe5; 32];
    assert_ne!(incarnation, record.incarnation);
    runner.install_retirement_driver_for_test((record.lane, incarnation), a.instance, a.running);
    let (finished, observed) = mpsc::sync_channel(1);
    let (turn_completed, calls_while_held, retained, hidden, joined) =
        std::thread::scope(|scope| {
            // This inner guard drops before scope joins on an unexpected unwind.
            let _scope_release = OpenExecutorOnDrop(release.0.clone());
            let lifecycle = scope.spawn(|| {
                runner.drive_retirement_for_test();
                let _ = finished.send(());
            });
            let completed = observed.recv_timeout(Duration::from_secs(1));
            let calls = attempts.0.load(Ordering::SeqCst);
            let retained =
                a.fakes.exec.waiting() == 1 && runner.retirement_owner_count_for_test() == 1;
            let statuses = runner.handle().statuses();
            let hidden = runner.instances().is_empty()
                && statuses.len() == 1
                && statuses[0].instance.is_none();
            release.0.set_open(true);
            let joined = lifecycle.join();
            (completed, calls, retained, hidden, joined)
        });
    joined.unwrap();
    let startup_reached = observed_within(Duration::from_secs(5), || {
        runner.drive_retirement_for_test();
        attempts.0.load(Ordering::SeqCst) > 0
    });
    let remaining = runner.retirement_owner_count_for_test();
    runner.shutdown();
    drop(release);
    assert_driver_retired(&handle, &a.fakes);
    assert_eq!(
        turn_completed,
        Ok(()),
        "retired worker joins must not block the actual lane lifecycle turn"
    );
    assert_eq!(
        calls_while_held, 0,
        "a new incarnation must not acquire startup authority before its same-lane predecessor physically finishes"
    );
    assert!(
        retained,
        "same-lane retirement retains the original physical driver owner"
    );
    assert!(
        hidden,
        "retiring drivers must not appear as a live instance or current-incarnation status"
    );
    assert!(
        startup_reached,
        "the original current incarnation starts admission after physical retirement"
    );
    assert_eq!(
        remaining, 0,
        "refused startup must not install a replacement running driver"
    );
}

#[test]
fn failed_join_handoff_retains_every_original_handle_until_final_shutdown() {
    let Instance {
        mut running, fakes, ..
    } = spawn_instance(237, Arc::new(SystemClock::new()), |_| {});
    let handle = running.handle();
    running.request_shutdown();
    assert!(observed_within(Duration::from_secs(5), || running
        .threads
        .iter()
        .all(std::thread::JoinHandle::is_finished)));
    let original_workers = running
        .threads
        .iter()
        .map(|thread| thread.thread().id())
        .collect::<Vec<_>>();
    assert_eq!(
        original_workers.len(),
        4,
        "the original driver owns its four physical worker handles"
    );

    // A closed private receiver exercises the actual SendError ownership return.
    // The displaced idle joiner is joined too; no thread or worker handle is leaked.
    let (workers, receive) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || drop(receive));
    assert!(observed_within(Duration::from_secs(5), || thread.is_finished()));
    let failed_joiner_id = thread.thread().id();
    let failed_joiner = crate::sumeragi::driver::DriverJoiner { workers, thread };
    let original_joiner = running.joiner.replace(failed_joiner).unwrap();
    original_joiner.finish(Vec::new(), false);

    assert!(
        !running.poll_shutdown(),
        "failed handoff must not report physical retirement"
    );
    assert!(running.handoff_failed);
    assert!(running.joiner.is_none());
    assert_eq!(
        running.joining.as_ref().unwrap().thread().id(),
        failed_joiner_id
    );
    assert_eq!(
        running
            .threads
            .iter()
            .map(|thread| thread.thread().id())
            .collect::<Vec<_>>(),
        original_workers
    );
    assert!(
        !running.poll_shutdown(),
        "failed handoff stays owned instead of retrying or creating a replacement joiner"
    );
    assert_eq!(
        running.joining.as_ref().unwrap().thread().id(),
        failed_joiner_id
    );
    assert_eq!(
        running
            .threads
            .iter()
            .map(|thread| thread.thread().id())
            .collect::<Vec<_>>(),
        original_workers
    );
    running.shutdown();
    assert_driver_retired(&handle, &fakes);
}

struct PendingStoreClock {
    clock: SystemClock,
    armed: std::sync::atomic::AtomicBool,
    entered: mpsc::SyncSender<()>,
    resume: parking_lot::Mutex<mpsc::Receiver<()>>,
    release: parking_lot::Mutex<Option<mpsc::SyncSender<()>>>,
    _original_store: Arc<crate::sumeragi::lanes::store::FileLaneBlockStore>,
}
impl PendingStoreClock {
    fn release(&self) {
        if let Some(release) = self.release.lock().take() {
            let _ = release.send(());
        }
    }
}
impl Clock for PendingStoreClock {
    fn now(&self) -> iroha_sumeragi::types::Millis {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.entered
                .send(())
                .expect("observe original driver callback");
            self.resume
                .lock()
                .recv_timeout(Duration::from_secs(5))
                .expect("release original driver callback");
        }
        self.clock.now()
    }
}
struct ReleasePendingClockOnDrop(Arc<PendingStoreClock>);
impl Drop for ReleasePendingClockOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[test]
fn pending_publication_waits_for_its_original_retiring_driver() {
    crate::sumeragi::lanes::registry::observe_pending_lane_retirement_for_test(
        |runner, key, store| {
            let (entered, observed) = mpsc::sync_channel(1);
            let (release, resume) = mpsc::sync_channel(1);
            let clock = Arc::new(PendingStoreClock {
                clock: SystemClock::new(),
                armed: std::sync::atomic::AtomicBool::new(false),
                entered,
                resume: parking_lot::Mutex::new(resume),
                release: parking_lot::Mutex::new(Some(release)),
                _original_store: Arc::clone(store),
            });
            let Instance {
                running,
                instance,
                fakes,
                ..
            } = spawn_instance(238, Arc::clone(&clock), |_| {});
            let _setup_release = ReleasePendingClockOnDrop(Arc::clone(&clock));
            let handle = running.handle();
            clock.armed.store(true, Ordering::SeqCst);
            handle.transactions_available();
            observed
                .recv_timeout(Duration::from_secs(5))
                .expect("original callback holds the exact pending store owner");
            runner.install_retirement_driver_for_test(key, instance, running);
            let (finished, done) = mpsc::sync_channel(1);
            let (height_while_held, joined) = std::thread::scope(|scope| {
                let _scope_release = ReleasePendingClockOnDrop(Arc::clone(&clock));
                let lifecycle = scope.spawn(|| {
                    runner.drive_retirement_for_test();
                    let _ = finished.send(());
                });
                // Before the asynchronous shutdown fix the turn is blocked on join.
                // With it the turn completes, but it still cannot publish this store yet.
                let _completed = done.recv_timeout(Duration::from_secs(1));
                let height = store.height();
                clock.release();
                (height, lifecycle.join())
            });
            joined.unwrap();
            let retired = observed_within(Duration::from_secs(5), || {
                runner.drive_retirement_for_test();
                runner.retirement_owner_count_for_test() == 0 && store.height() == 1
            });
            assert_driver_retired(&handle, &fakes);
            assert_eq!(
                height_while_held, 0,
                "a still-owned retiring driver must exclude its original pending publication from lifecycle continuation"
            );
            assert!(
                retired,
                "after physical retirement the same admitted publication must finish without a replacement body or authority"
            );
        },
    );
}

// Unlike the ordinary fake-store fixture, this idle driver owns the actual retired
// FileLaneBlockStore, its independently derived instance, and its original State pool.
fn spawn_retiring_store_driver(
    instance: Hash32,
    store: Arc<crate::sumeragi::lanes::store::FileLaneBlockStore>,
    budget: iroha_allocation::AllocationBudget,
) -> Instance {
    let signer = FakeSigner::from_seed(&[239], None);
    let key = signer.public_key().clone();
    let crypto: SharedCrypto = Arc::new(FakeCrypto::new());
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
    let genesis = (Hash32([0x91; 32]), Hash32([0x92; 32]));
    let init = assemble_init(
        &*store,
        instance,
        0,
        genesis,
        128,
        found,
        vec![
            (1, iroha_sumeragi::types::ConfigSlot::Ready(config.clone())),
            (2, iroha_sumeragi::types::ConfigSlot::Ready(config.clone())),
        ],
        239,
    )
    .unwrap();
    let fakes = Fakes {
        exec: FakeExecutor::new(genesis.0, genesis.1, config),
        net: Arc::new(FakeNet::default()),
        records,
        bodies: Arc::new(FakeBodies::default()),
        blocks: Arc::new(FakeBlocks::default()),
        observer: Arc::new(RecordingObserver::default()),
    };
    let observer: Arc<dyn Observer> = fakes.observer.clone();
    let running = Driver::new(
        Arc::clone(&fakes.net),
        Arc::clone(&fakes.records),
        Arc::clone(&fakes.bodies),
        store,
        Arc::new(SystemClock::new()),
        fakes.exec.clone(),
        observer,
    )
    .spawn(
        DriverConfig::default(),
        DriverStart {
            node_gate: Arc::new(NodeGate::new()),
            allocation_budget: budget,
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

struct StopRetiredSyncOnDrop<'a> {
    stop: &'a std::sync::atomic::AtomicBool,
    gate: Arc<crate::sumeragi::lanes::registry::RetiredSyncGate>,
}
impl Drop for StopRetiredSyncOnDrop<'_> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.gate.release();
    }
}

#[test]
fn retired_directory_sync_does_not_block_other_lane_transaction_delivery() {
    let (a_handle, a_fakes, b_handle, b_fakes) =
        crate::sumeragi::lanes::registry::observe_retired_sync_for_test(|fixture| {
            let runner = fixture.runner;
            let a = spawn_retiring_store_driver(
                fixture.instance,
                Arc::clone(fixture.store),
                fixture.budget,
            );
            let b = spawn_instance(240, Arc::new(SystemClock::new()), |_| {});
            let a_handle = a.handle();
            let b_handle = b.handle();
            assert!(observed_within(Duration::from_secs(5), || a_handle
                .waiting_after_empty_for_test()));
            assert!(observed_within(Duration::from_secs(5), || b_handle
                .waiting_after_empty_for_test()));
            runner.install_retirement_driver_for_test(fixture.retired, a.instance, a.running);
            runner.install_retirement_driver_for_test(fixture.active, b.instance, b.running);
            let stop = std::sync::atomic::AtomicBool::new(false);
            let requested_turn = std::sync::atomic::AtomicBool::new(false);
            let (acknowledge_turn, observed_turn) = std::sync::mpsc::sync_channel(1);
            let _setup_release = StopRetiredSyncOnDrop {
                stop: &stop,
                gate: Arc::clone(fixture.gate),
            };
            let (entered, progressed, tip_while_held, joined) = std::thread::scope(|scope| {
                // This guard runs before scope joins during every assertion/unwind path.
                let _scope_release = StopRetiredSyncOnDrop {
                    stop: &stop,
                    gate: Arc::clone(fixture.gate),
                };
                let lifecycle = scope.spawn(|| {
                    while !stop.load(Ordering::Acquire) {
                        // Only acknowledge a whole turn begun after the explicit wake below.
                        let acknowledge = requested_turn.swap(false, Ordering::AcqRel);
                        runner.drive_retirement_for_test();
                        if acknowledge {
                            let _ = acknowledge_turn.send(());
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                });
                let entered = fixture.gate.wait_entered();
                b.fakes.exec.add_tx(2);
                runner.handle().transactions_available();
                requested_turn.store(true, Ordering::Release);
                let mut turn_observed = false;
                let progressed = entered.is_ok()
                    && observed_within(Duration::from_secs(1), || {
                        turn_observed |= observed_turn.try_recv().is_ok();
                        turn_observed
                            && b_handle
                                .status()
                                .is_some_and(|status| status.committed_height >= 1)
                            && b.fakes.exec.state.lock().txs.is_empty()
                    });
                let tip = fixture.store.height();
                stop.store(true, Ordering::Release);
                fixture.gate.release();
                (entered, progressed, tip, lifecycle.join())
            });
            // Cleanup precedes every causal assertion, including the unfixed blocked path.
            joined.unwrap();
            let retired = observed_within(Duration::from_secs(5), || {
                runner.drive_retirement_for_test();
                runner.retirement_owner_count_for_test() == 1 && fixture.store.height() == 1
            });
            entered.unwrap();
            assert!(
                progressed,
                "original retired SyncDir must not block another lane's actual transaction wake and commit"
            );
            assert_eq!(
                tip_while_held, 0,
                "materialized retired bytes are not a synchronized committed tip"
            );
            assert!(
                retired,
                "the same original publication must finish and retire after SyncDir resumes"
            );
            (a_handle, a.fakes, b_handle, b.fakes)
        });
    assert_driver_retired(&a_handle, &a_fakes);
    assert_driver_retired(&b_handle, &b_fakes);
}

#[test]
fn final_driver_shutdown_preserves_original_pending_store_for_existing_registry_continuation() {
    crate::sumeragi::lanes::registry::observe_retired_sync_for_test(|observation| {
        let Instance { running, fakes, .. } = spawn_retiring_store_driver(
            observation.instance,
            Arc::clone(observation.store),
            observation.budget.clone(),
        );
        let handle = running.handle();
        running.shutdown();
        let height_after_stop = observation.store.height();
        let remaining_owners = Arc::strong_count(observation.store);
        // Release before any assertion or synchronous orphan continuation.
        observation.gate.release();
        observation.runner.drive_retirement_for_test();
        assert_driver_retired(&handle, &fakes);
        assert_eq!(
            height_after_stop, 0,
            "final shutdown must not claim an unperformed publication"
        );
        assert_eq!(
            remaining_owners, 2,
            "the original registry and fixture retain the exact pending store after driver shutdown"
        );
        assert_eq!(
            observation.store.height(),
            1,
            "the original pending write survives final driver cancellation for registry continuation"
        );
        // The enclosing owner independently authenticates the original body/QC and
        // verifies sole backend ownership after the registry itself drops.
    });
}

#[test]
fn final_shutdown_recognizes_original_publication_joiner_and_finishes_inflight_sync() {
    crate::sumeragi::lanes::registry::observe_retired_sync_for_test(|observation| {
        let Instance {
            mut running, fakes, ..
        } = spawn_retiring_store_driver(
            observation.instance,
            Arc::clone(observation.store),
            observation.budget.clone(),
        );
        let handle = running.handle();
        let original = running.joiner.as_ref().unwrap().thread.thread().id();
        let original_is_owned = running.owns_thread(original);
        let caller_is_owned = running.owns_thread(std::thread::current().id());
        let handed_off = observed_within(Duration::from_secs(5), || {
            running.poll_shutdown();
            running.joining.is_some()
        });
        let entered = observation.gate.wait_entered();
        let joining_is_owned = running.joining.as_ref().is_some_and(|thread| {
            thread.thread().id() == original && running.owns_thread(thread.thread().id())
        });
        let height_while_held = observation.store.height();
        if let Some(owner) = &running.retirement {
            owner.stop();
        }
        observation.gate.release();
        // Final shutdown may wait for this original native syscall, but never self-joins
        // if invoked from its publication/refund callback. The exact helper is checked below.
        running.shutdown();
        assert_driver_retired(&handle, &fakes);
        assert!(handed_off);
        entered.unwrap();
        assert!(
            original_is_owned && joining_is_owned,
            "both ownership phases must recognize the original publication joiner as a self-worker"
        );
        assert!(!caller_is_owned);
        assert_eq!(height_while_held, 0);
        assert_eq!(observation.store.height(), 1);
    });
}

struct StopStartupSyncOnDrop<'a> {
    stop: &'a std::sync::atomic::AtomicBool,
    gate: Arc<crate::sumeragi::lanes::registry::StartupSyncGate>,
}
impl Drop for StopStartupSyncOnDrop<'_> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.gate.release();
    }
}

#[test]
fn native_lane_startup_sync_does_not_block_other_lane_transaction_delivery() {
    let (handle, fakes, entered, progressed, original_opening, joined) =
        crate::sumeragi::lanes::registry::observe_startup_sync_for_test(|fixture| {
            let runner = fixture.runner;
            let live = spawn_instance(241, Arc::new(SystemClock::new()), |_| {});
            let handle = live.handle();
            assert!(observed_within(Duration::from_secs(5), || handle
                .waiting_after_empty_for_test()));
            runner.install_retirement_driver_for_test(fixture.active, live.instance, live.running);
            let stop = std::sync::atomic::AtomicBool::new(false);
            let requested_turn = std::sync::atomic::AtomicBool::new(false);
            let (acknowledge_turn, observed_turn) = std::sync::mpsc::sync_channel(1);
            let _setup_release = StopStartupSyncOnDrop {
                stop: &stop,
                gate: Arc::clone(fixture.gate),
            };
            let observation = std::thread::scope(|scope| {
                // This releases the actual I/O before scope joins during every unwind.
                let _scope_release = StopStartupSyncOnDrop {
                    stop: &stop,
                    gate: Arc::clone(fixture.gate),
                };
                let lifecycle = scope.spawn(|| {
                    while !stop.load(Ordering::Acquire) {
                        let acknowledge = requested_turn.swap(false, Ordering::AcqRel);
                        runner.drive_retirement_for_test();
                        if acknowledge {
                            let _ = acknowledge_turn.send(());
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                });
                let entered = fixture.gate.wait_entered();
                let original_opening = entered.is_ok() && fixture.original_opening_is_busy();
                live.fakes.exec.add_tx(2);
                runner.handle().transactions_available();
                requested_turn.store(true, Ordering::Release);
                let mut turn_observed = false;
                let progressed = entered.is_ok()
                    && observed_within(Duration::from_secs(1), || {
                        turn_observed |= observed_turn.try_recv().is_ok();
                        turn_observed
                            && handle
                                .status()
                                .is_some_and(|status| status.committed_height >= 1)
                            && live.fakes.exec.state.lock().txs.is_empty()
                    });
                stop.store(true, Ordering::Release);
                fixture.gate.release();
                (entered, progressed, original_opening, lifecycle.join())
            });
            (
                handle,
                live.fakes,
                observation.0,
                observation.1,
                observation.2,
                observation.3,
            )
        });
    // The fixture released I/O, joined the lifecycle, dropped the real coordinator and
    // joined both original drivers before returning any causal observation.
    joined.unwrap();
    assert_driver_retired(&handle, &fakes);
    entered.unwrap();
    assert!(
        original_opening,
        "actual eligible startup must retain its authenticated in-flight native opening"
    );
    assert!(
        progressed,
        "original native startup SyncFile must not block another lane's actual lifecycle turn and transaction commit"
    );
}
