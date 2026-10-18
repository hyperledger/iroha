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

// The native registry fixtures release their State and original epoch guard before
// returning. Their old charged generations still belong to the shared EBR collector,
// whose existing protocol must run before final all-owner refund can be observed.
fn collect_retired_native_fixture_state(budget: &iroha_allocation::AllocationBudget) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while budget.reserved_bytes() != 0 {
        assert!(
            Instant::now() < deadline,
            "retired native fixture State generations were not reclaimed: {}",
            budget.reserved_bytes()
        );
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
}

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
            let deadline = Instant::now() + Duration::from_secs(1);
            let lifecycle = scope.spawn(|| {
                runner.drive_retirement_for_test();
                let _ = finished.send(());
            });
            let completed =
                observed.recv_timeout(deadline.saturating_duration_since(Instant::now()));
            // Async preparation can reach the real authority after the turn
            // returns. Observe that owner within the same original one-second
            // window, while the predecessor is still physically blocked.
            while completed.is_ok()
                && attempts.0.load(Ordering::SeqCst) == 0
                && Instant::now() < deadline
            {
                std::thread::sleep(
                    Duration::from_millis(5)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
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
    crate::sumeragi::lanes::registry::observe_retired_sync_for_test(|fixture| {
        let (runner, key, store) = (fixture.runner, fixture.retired, fixture.store);
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
        } = {
            let prepared = prepare_retiring_store_driver(
                fixture.instance,
                Arc::clone(store),
                fixture.budget.clone(),
                Arc::clone(&clock),
            );
            let running = prepared
                .driver
                .spawn(DriverConfig::default(), prepared.start)
                .unwrap();
            Instance {
                running,
                key: prepared.key,
                instance: prepared.instance,
                fakes: prepared.fakes,
            }
        };
        fixture.admit_pending();
        fixture.gate.release();
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
    });
}

// Unlike the ordinary fake-store fixture, this idle driver owns the actual retired
// FileLaneBlockStore, its independently derived instance, and its original State pool.
struct PreparedRetiringStore<C> {
    driver: Driver<
        FakeNet,
        FakeRecords,
        FakeBodies,
        crate::sumeragi::lanes::store::FileLaneBlockStore,
        C,
        FakeExecutor,
    >,
    start: DriverStart,
    key: PublicKey,
    instance: Hash32,
    fakes: Fakes,
}

fn prepare_retiring_store_driver<C: Clock + 'static>(
    instance: Hash32,
    store: Arc<crate::sumeragi::lanes::store::FileLaneBlockStore>,
    budget: iroha_allocation::AllocationBudget,
    clock: Arc<C>,
) -> PreparedRetiringStore<C> {
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
    let driver = Driver::new(
        Arc::clone(&fakes.net),
        Arc::clone(&fakes.records),
        Arc::clone(&fakes.bodies),
        store,
        clock,
        fakes.exec.clone(),
        observer,
    );
    PreparedRetiringStore {
        driver,
        start: DriverStart {
            node_gate: Arc::new(NodeGate::new()),
            allocation_budget: budget,
            local: LocalParams::default(),
            init,
            signers: vec![Arc::new(signer)],
            crypto,
        },
        key,
        instance,
        fakes,
    }
}

fn spawn_retiring_store_driver(
    instance: Hash32,
    store: Arc<crate::sumeragi::lanes::store::FileLaneBlockStore>,
    budget: iroha_allocation::AllocationBudget,
) -> Instance {
    let PreparedRetiringStore {
        driver,
        start,
        key,
        instance,
        fakes,
    } = prepare_retiring_store_driver(instance, store, budget, Arc::new(SystemClock::new()));
    let running = driver.spawn(DriverConfig::default(), start).unwrap();
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
                fixture.budget.clone(),
            );
            fixture.admit_pending();
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
fn final_driver_shutdown_preserves_original_pending_store_for_authenticated_restart() {
    crate::sumeragi::lanes::registry::observe_shutdown_sync_for_test(|observation| {
        let Instance { running, fakes, .. } = spawn_retiring_store_driver(
            observation.instance,
            Arc::clone(observation.store),
            observation.budget.clone(),
        );
        observation.admit_pending();
        let handle = running.handle();
        running.shutdown();
        let height_after_stop = observation.store.height();
        let remaining_owners = Arc::strong_count(observation.store);
        // Release before assertions and the notification-only reconciliation.
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
            0,
            "final cancellation preserves the original pending write without restarting an ended owner"
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
        observation.admit_pending();
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

#[test]
fn ready_transfer_reissues_consumed_transaction_wake_to_original_workers() {
    use crate::sumeragi::driver::{DriverPreparation, PendingDriver, StartupPoll};

    let (chain, record, _epoch) =
        crate::sumeragi::runtime_availability::tests::npos_fixed_lane_chain_at(4);
    let directory = tempfile::tempdir().unwrap();
    let attempts = Arc::new(StartupAttempts(AtomicUsize::new(0)));
    let runner = runner(&chain, directory.path(), Arc::clone(&attempts));
    let PreparedInstance {
        driver,
        start,
        key: _,
        instance,
        fakes,
    } = prepare_instance(245, Arc::new(SystemClock::new()), |_| {});
    let budget = start.allocation_budget.clone();
    let mut original = PendingDriver::spawn(
        instance,
        &budget,
        DriverConfig::default().backoff,
        move |_| {
            Ok(Some(DriverPreparation::new(
                driver,
                DriverConfig::default(),
                start,
            )))
        },
    )
    .unwrap();
    let awaiting = observed_within(Duration::from_secs(5), || {
        matches!(original.poll(), StartupPoll::AwaitingActivation)
    });
    let activated = original.activate();
    let ready = observed_within(Duration::from_secs(5), || {
        original.ready_handle_for_test().is_some()
    });
    let handle = original.ready_handle_for_test();
    let empty = handle.as_ref().is_some_and(|handle| {
        observed_within(Duration::from_secs(5), || {
            handle.waiting_after_empty_for_test()
        })
    });
    let before = handle
        .as_ref()
        .map(|handle| handle.shared.empty_epoch.load(Ordering::Acquire));
    let key = (record.lane, record.incarnation);
    runner.install_startup_for_test(key, instance, original);
    fakes.exec.add_tx(1);
    runner.handle().transactions_available();
    let consumed = runner.drain_startup_wake_for_test();
    let hidden = runner.instances().is_empty();
    runner.transfer_startup_for_test();
    let delivered_and_committed = handle.as_ref().is_some_and(|handle| {
        observed_within(Duration::from_secs(5), || {
            before.is_some_and(|before| handle.shared.empty_epoch.load(Ordering::Acquire) > before)
                && handle
                    .status()
                    .is_some_and(|status| status.committed_height >= 1)
                && fakes.exec.state.lock().txs.is_empty()
        })
    });
    let visible = runner
        .instances()
        .iter()
        .any(|status| status.instance == instance);
    drop(runner);
    if let Some(handle) = &handle {
        assert_driver_retired(handle, &fakes);
    }
    drop(handle);
    // FakeBlocks deliberately keeps the actually committed paid body after its
    // driver ends. Retain that same shared body across backend destruction, prove
    // its exact two byte allocations/control shells, then release the last owner.
    let original_body = fakes
        .blocks
        .committed_body(1)
        .unwrap()
        .map(|(body, _)| body);
    let retained_bytes = original_body.as_ref().map_or(0, |body| {
        assert!(body.admitted_to(&budget));
        body.payload().charged_source(&budget).unwrap().capacity()
            + body.availability().charged_source(&budget).unwrap().capacity()
            + 2 * iroha_allocation::ChargedShared::<
                iroha_allocation::ChargedBuffer<u8>,
            >::allocation_layout()
            .size()
    });
    let retained_with_backends = budget.reserved_bytes();
    let original_body_present = original_body.is_some();
    drop(fakes);
    assert_eq!(
        budget.reserved_bytes(),
        retained_bytes,
        "only the exact retained committed body may remain after the fake backends drop"
    );
    drop(original_body);
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        awaiting && activated && ready && empty,
        "original workers must reach unexposed Ready then Core EMPTY"
    );
    assert!(
        consumed && hidden,
        "the first real runner wake must be consumed before original Ready exposure"
    );
    assert!(
        visible && delivered_and_committed,
        "Ready transfer must redeliver the consumed transaction wake to the original workers"
    );
    assert_eq!(
        attempts.0.load(Ordering::SeqCst),
        0,
        "the original pending owner is transferred without another authority lookup"
    );
    assert!(original_body_present);
    assert_eq!(retained_with_backends, retained_bytes);
}

struct RefusedStartupClock {
    entered: mpsc::SyncSender<()>,
    resume: parking_lot::Mutex<mpsc::Receiver<()>>,
    release: parking_lot::Mutex<Option<mpsc::SyncSender<()>>>,
}
impl RefusedStartupClock {
    fn release(&self) {
        if let Some(release) = self.release.lock().take() {
            let _ = release.send(());
        }
    }
}
impl Clock for RefusedStartupClock {
    fn now(&self) -> iroha_sumeragi::types::Millis {
        let _ = self.entered.send(());
        self.resume
            .lock()
            .recv_timeout(Duration::from_secs(5))
            .expect("release the original startup worker before cleanup");
        0
    }
}
struct ReleaseRefusedStartupClock(Arc<RefusedStartupClock>);
impl Drop for ReleaseRefusedStartupClock {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[test]
fn stale_failed_startup_releases_same_lane_only_after_original_workers_join() {
    use crate::sumeragi::driver::{DriverPreparation, PendingDriver, StartupPoll};

    let (chain, record, _epoch) =
        crate::sumeragi::runtime_availability::tests::npos_fixed_lane_chain_at(4);
    let directory = tempfile::tempdir().unwrap();
    let attempts = Arc::new(StartupAttempts(AtomicUsize::new(0)));
    let runner = runner(&chain, directory.path(), Arc::clone(&attempts));
    let (entered, entry) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    let clock = Arc::new(RefusedStartupClock {
        entered,
        resume: parking_lot::Mutex::new(resume),
        release: parking_lot::Mutex::new(Some(release)),
    });
    let PreparedInstance {
        driver,
        mut start,
        key: _,
        instance,
        fakes,
    } = prepare_instance(246, Arc::clone(&clock), |_| {});
    start.signers.clear();
    let budget = start.allocation_budget.clone();
    let mut original = PendingDriver::spawn(
        instance,
        &budget,
        DriverConfig::default().backoff,
        move |_| {
            Ok(Some(DriverPreparation::new(
                driver,
                DriverConfig::default(),
                start,
            )))
        },
    )
    .unwrap();
    let release = ReleaseRefusedStartupClock(Arc::clone(&clock));
    let awaiting = observed_within(Duration::from_secs(5), || {
        matches!(original.poll(), StartupPoll::AwaitingActivation)
    });
    let activated = original.activate();
    let worker_held = entry.recv_timeout(Duration::from_secs(5));
    let stale = [0xe7; 32];
    assert_ne!(stale, record.incarnation);
    runner.install_startup_for_test((record.lane, stale), instance, original);
    let (done, turn) = mpsc::sync_channel(1);
    let (completed, while_held, original_retained, lifecycle_joined) =
        std::thread::scope(|scope| {
            let _release = ReleaseRefusedStartupClock(Arc::clone(&clock));
            let lifecycle = scope.spawn(|| {
                runner.drive_retirement_for_test();
                let _ = done.send(());
            });
            let deadline = Instant::now() + Duration::from_secs(1);
            let completed = turn.recv_timeout(deadline.saturating_duration_since(Instant::now()));
            while completed.is_ok()
                && attempts.0.load(Ordering::SeqCst) == 0
                && Instant::now() < deadline
            {
                std::thread::sleep(
                    Duration::from_millis(5)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            let while_held = attempts.0.load(Ordering::SeqCst);
            let original_retained =
                budget.reserved_bytes() > 0 && Arc::strong_count(&fakes.exec.state) > 1;
            clock.release();
            (completed, while_held, original_retained, lifecycle.join())
        });
    let replacement_reached = observed_within(Duration::from_secs(5), || {
        runner.drive_retirement_for_test();
        attempts.0.load(Ordering::SeqCst) > 0
    });
    let original_released = budget.reserved_bytes() == 0;
    let hidden = runner.instances().is_empty();
    drop(release);
    runner.shutdown();
    lifecycle_joined.unwrap();
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(Arc::strong_count(&fakes.net), 1);
    assert_eq!(Arc::strong_count(&fakes.records), 1);
    assert_eq!(Arc::strong_count(&fakes.bodies), 1);
    assert_eq!(Arc::strong_count(&fakes.blocks), 1);
    assert_eq!(Arc::strong_count(&fakes.exec.state), 1);
    assert_eq!(Arc::strong_count(&fakes.observer), 1);
    assert_eq!(*fakes.observer.finished.lock(), 1);
    assert!(awaiting && activated && worker_held.is_ok());
    assert_eq!(
        completed,
        Ok(()),
        "failed startup cleanup must not block the actual lifecycle turn"
    );
    assert_eq!(
        while_held, 0,
        "replacement authority must wait for every original startup worker and join"
    );
    assert!(original_retained);
    assert!(
        replacement_reached && original_released,
        "committed retirement must release the original failed startup after successful physical cleanup"
    );
    assert!(hidden, "a refused startup never exposes a live driver");
    assert_eq!(attempts.0.load(Ordering::SeqCst), 1);
}

#[test]
fn pending_publication_waits_for_original_startup_workers() {
    use crate::sumeragi::driver::{DriverPreparation, PendingDriver, StartupPoll};
    let (
        awaiting,
        activated,
        held,
        completed,
        height_while_held,
        retired,
        original_fakes,
        budget,
        live_handle,
        live_fakes,
    ) = crate::sumeragi::lanes::registry::observe_retired_sync_for_test(|fixture| {
        // This control observes ownership before continuation, not a slow syscall.
        // Release the fixture's later native synchronization before any assertion.
        fixture.gate.release();
        let (entered, observed) = mpsc::sync_channel(1);
        let (release, resume) = mpsc::sync_channel(1);
        let clock = Arc::new(RefusedStartupClock {
            entered,
            resume: parking_lot::Mutex::new(resume),
            release: parking_lot::Mutex::new(Some(release)),
        });
        let PreparedRetiringStore {
            driver,
            mut start,
            fakes,
            ..
        } = prepare_retiring_store_driver(
            fixture.instance,
            Arc::clone(fixture.store),
            fixture.budget.clone(),
            Arc::clone(&clock),
        );
        // KernelStart reads the held original clock before rejecting this missing signer.
        // All four genuine worker handles exist, but no RunningDriver has transferred.
        start.signers.clear();
        let mut original = PendingDriver::spawn(
            fixture.instance,
            &fixture.budget,
            DriverConfig::default().backoff,
            move |_| {
                Ok(Some(DriverPreparation::new(
                    driver,
                    DriverConfig::default(),
                    start,
                )))
            },
        )
        .unwrap();
        let release = ReleaseRefusedStartupClock(Arc::clone(&clock));
        let live = spawn_instance(248, Arc::new(SystemClock::new()), |_| {});
        let live_handle = live.handle();
        fixture.runner.install_retirement_driver_for_test(
            fixture.active,
            live.instance,
            live.running,
        );
        let awaiting = observed_within(Duration::from_secs(5), || {
            matches!(original.poll(), StartupPoll::AwaitingActivation)
        });
        fixture.admit_pending();
        let activated = original.activate();
        let held = observed.recv_timeout(Duration::from_secs(5));
        fixture
            .runner
            .install_startup_for_test(fixture.retired, fixture.instance, original);
        let (done, turn) = mpsc::sync_channel(1);
        let (completed, height, joined) = std::thread::scope(|scope| {
            let _release = ReleaseRefusedStartupClock(Arc::clone(&clock));
            let lifecycle = scope.spawn(|| {
                fixture.runner.drive_retirement_for_test();
                let _ = done.send(());
            });
            let completed = turn.recv_timeout(Duration::from_secs(1));
            let height = fixture.store.height();
            clock.release();
            (completed, height, lifecycle.join())
        });
        joined.unwrap();
        let retired = observed_within(Duration::from_secs(5), || {
            fixture.runner.drive_retirement_for_test();
            fixture.runner.startup_owner_count_for_test() == 0 && fixture.store.height() == 1
        });
        drop(release);
        (
            awaiting,
            activated,
            held,
            completed,
            height,
            retired,
            fakes,
            fixture.budget.clone(),
            live_handle,
            live.fakes,
        )
    });
    // The enclosing native fixture has joined both owners and authenticated the original
    // body/QC before returning. Clean all exact backend and allocation owners before cause.
    assert_driver_retired(&live_handle, &live_fakes);
    assert_eq!(Arc::strong_count(&original_fakes.net), 1);
    assert_eq!(Arc::strong_count(&original_fakes.records), 1);
    assert_eq!(Arc::strong_count(&original_fakes.bodies), 1);
    assert_eq!(Arc::strong_count(&original_fakes.exec.state), 1);
    assert_eq!(Arc::strong_count(&original_fakes.observer), 1);
    assert_eq!(*original_fakes.observer.finished.lock(), 1);
    assert_eq!(original_fakes.bodies.len(), 0);
    assert_eq!(original_fakes.blocks.height(), 0);
    collect_retired_native_fixture_state(&budget);
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(awaiting && activated && held.is_ok());
    assert_eq!(
        completed,
        Ok(()),
        "pending startup exclusion must not block the lifecycle turn"
    );
    assert!(
        retired,
        "the same admitted write must publish after successful original startup cleanup"
    );
    assert_eq!(
        height_while_held, 0,
        "an original pending startup must exclude its publication until every acquired worker is physically joined"
    );
}

#[test]
fn retired_startup_keeps_publication_on_its_original_joiner() {
    use crate::sumeragi::driver::{DriverPreparation, PendingDriver, StartupPoll};
    // Cover no acquired worker, abandoned Ready, real readiness refusal, partial
    // physical creation refusal, and Ready already transferred to RunningDriver.
    for phase in 0..5 {
        let (correct_owner, progressed, retired, live_handle, live_fakes, fakes, budget) =
            crate::sumeragi::lanes::registry::observe_retired_sync_with_restart_cleanup_for_test(
                |fixture| {
                    let PreparedRetiringStore {
                        driver,
                        mut start,
                        fakes,
                        ..
                    } = prepare_retiring_store_driver(
                        fixture.instance,
                        Arc::clone(fixture.store),
                        fixture.budget.clone(),
                        Arc::new(SystemClock::new()),
                    );
                    if phase == 2 {
                        start.signers.clear();
                    }
                    let mut original = PendingDriver::spawn(
                        fixture.instance,
                        &fixture.budget,
                        DriverConfig::default().backoff,
                        move |_| {
                            if phase == 3 {
                                crate::sumeragi::driver::startup::refuse_startup_thread_for_test(2);
                            }
                            Ok(Some(DriverPreparation::new(
                                driver,
                                DriverConfig::default(),
                                start,
                            )))
                        },
                    )
                    .unwrap();
                    let joiner = original.original_joiner_for_test();
                    let awaiting = observed_within(Duration::from_secs(5), || {
                        matches!(original.poll(), StartupPoll::AwaitingActivation)
                    });
                    assert!(awaiting);
                    fixture.admit_pending();
                    if phase != 0 {
                        assert!(original.activate());
                        assert!(observed_within(Duration::from_secs(5), || {
                            if phase == 2 || phase == 3 {
                                original.refusal_ready_for_test()
                            } else {
                                original.ready_handle_for_test().is_some()
                            }
                        }));
                    }
                    if phase == 4 {
                        let StartupPoll::Ready(driver) = original.poll() else {
                            panic!("original Ready transfers its exact joining owner")
                        };
                        fixture.runner.install_retirement_driver_for_test(
                            fixture.retired,
                            fixture.instance,
                            driver,
                        );
                        drop(original);
                    } else {
                        fixture.runner.install_startup_for_test(
                            fixture.retired,
                            fixture.instance,
                            original,
                        );
                    }
                    let live = spawn_instance(249, Arc::new(SystemClock::new()), |_| {});
                    let live_handle = live.handle();
                    assert!(observed_within(Duration::from_secs(5), || {
                        live_handle.waiting_after_empty_for_test()
                    }));
                    fixture.runner.install_retirement_driver_for_test(
                        fixture.active,
                        live.instance,
                        live.running,
                    );
                    let stop = std::sync::atomic::AtomicBool::new(false);
                    let requested_turn = std::sync::atomic::AtomicBool::new(false);
                    let (acknowledge, observed_turn) = mpsc::sync_channel(1);
                    let _setup_release = StopRetiredSyncOnDrop {
                        stop: &stop,
                        gate: Arc::clone(fixture.gate),
                    };
                    let (correct_owner, progressed, joined) = std::thread::scope(|scope| {
                        let _scope_release = StopRetiredSyncOnDrop {
                            stop: &stop,
                            gate: Arc::clone(fixture.gate),
                        };
                        let lifecycle = scope.spawn(|| {
                            while !stop.load(Ordering::Acquire) {
                                let turn = requested_turn.swap(false, Ordering::AcqRel);
                                fixture.runner.drive_retirement_for_test();
                                if turn {
                                    let _ = acknowledge.send(());
                                }
                                std::thread::sleep(Duration::from_millis(5));
                            }
                        });
                        let entered = fixture.gate.wait_entered();
                        let correct_owner =
                            entered.is_ok() && fixture.gate.synchronizer() == Some(joiner);
                        live.fakes.exec.add_tx(2);
                        fixture.runner.handle().transactions_available();
                        requested_turn.store(true, Ordering::Release);
                        let mut full_turn = false;
                        let progressed = correct_owner
                            && observed_within(Duration::from_secs(1), || {
                                full_turn |= observed_turn.try_recv().is_ok();
                                full_turn
                                    && live_handle
                                        .status()
                                        .is_some_and(|s| s.committed_height >= 1)
                                    && live.fakes.exec.state.lock().txs.is_empty()
                            });
                        stop.store(true, Ordering::Release);
                        fixture.gate.release();
                        (correct_owner, progressed, lifecycle.join())
                    });
                    joined.unwrap();
                    let retired = observed_within(Duration::from_secs(5), || {
                        fixture.runner.drive_retirement_for_test();
                        fixture.runner.startup_owner_count_for_test() == 0
                            && fixture.runner.retirement_owner_count_for_test() == 1
                            && fixture.store.height() == 1
                    });
                    // A deliberately omitted continuation remains owned and failed.
                    // Final cleanup physically closes every failed original owner.
                    // The enclosing harness may reopen for cleanup using the exact
                    // original signed input, never changing this captured verdict.
                    fixture.runner.shutdown_startup_for_test(fixture.retired);
                    fixture.runner.drive_retirement_for_test();
                    (
                        correct_owner,
                        progressed,
                        retired,
                        live_handle,
                        live.fakes,
                        fakes,
                        fixture.budget.clone(),
                    )
                },
            );
        assert_driver_retired(&live_handle, &live_fakes);
        assert_eq!(Arc::strong_count(&fakes.net), 1);
        assert_eq!(Arc::strong_count(&fakes.records), 1);
        assert_eq!(Arc::strong_count(&fakes.bodies), 1);
        assert_eq!(Arc::strong_count(&fakes.exec.state), 1);
        assert_eq!(Arc::strong_count(&fakes.observer), 1);
        assert_eq!(fakes.bodies.len(), 0);
        assert_eq!(fakes.blocks.height(), 0);
        collect_retired_native_fixture_state(&budget);
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(
            correct_owner && progressed && retired,
            "committed startup retirement must finish publication on its original joiner without blocking another lane"
        );
    }
}

#[test]
fn final_startup_shutdown_preserves_unpublished_original_store() {
    use crate::sumeragi::driver::{DriverPreparation, PendingDriver, StartupPoll};
    let (stopped, height_before_continuation, fakes, budget) =
        crate::sumeragi::lanes::registry::observe_shutdown_sync_for_test(|fixture| {
            let PreparedRetiringStore {
                driver,
                start,
                fakes,
                ..
            } = prepare_retiring_store_driver(
                fixture.instance,
                Arc::clone(fixture.store),
                fixture.budget.clone(),
                Arc::new(SystemClock::new()),
            );
            let mut original = PendingDriver::spawn(
                fixture.instance,
                &fixture.budget,
                DriverConfig::default().backoff,
                move |_| {
                    Ok(Some(DriverPreparation::new(
                        driver,
                        DriverConfig::default(),
                        start,
                    )))
                },
            )
            .unwrap();
            let awaiting = observed_within(Duration::from_secs(5), || {
                matches!(original.poll(), StartupPoll::AwaitingActivation)
            });
            fixture.admit_pending();
            original.cancel();
            let stopped = observed_within(Duration::from_secs(5), || {
                original.original_joiner_finished_for_test()
            });
            // Independent cleanup closes the exact same owner after recording
            // whether the production final-stop signal actually ended it.
            original.stop_original_publication_for_test();
            fixture.gate.release();
            drop(original);
            let height = fixture.store.height();
            // No ended owner may be resumed. The enclosing harness closes the exact
            // store and authenticates the same visible canonical frame after restart.
            assert!(awaiting);
            (stopped, height, fakes, fixture.budget.clone())
        });
    assert_eq!(Arc::strong_count(&fakes.net), 1);
    assert_eq!(Arc::strong_count(&fakes.records), 1);
    assert_eq!(Arc::strong_count(&fakes.bodies), 1);
    assert_eq!(Arc::strong_count(&fakes.exec.state), 1);
    assert_eq!(Arc::strong_count(&fakes.observer), 1);
    assert_eq!(fakes.bodies.len(), 0);
    assert_eq!(fakes.blocks.height(), 0);
    collect_retired_native_fixture_state(&budget);
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        stopped && height_before_continuation == 0,
        "final startup shutdown must stop its admitted job and preserve the original unpublished store"
    );
}

#[test]
fn original_orphan_publication_does_not_block_other_lane_transaction_delivery() {
    let (entered, progressed, tip_while_held, live_handle, live_fakes, budget) =
        crate::sumeragi::lanes::registry::observe_retired_sync_for_test(|fixture| {
            let publication = crate::sumeragi::driver::PublicationSession::start(
                fixture.store.clone(),
                &fixture.budget,
            );
            fixture.admit_pending();
            let original_joiner = publication.original_thread();
            // Deliberately install no RunningDriver or PendingDriver for the
            // already-admitted retired store. This is the true orphan path.
            let live = spawn_instance(250, Arc::new(SystemClock::new()), |_| {});
            let live_handle = live.handle();
            assert!(observed_within(Duration::from_secs(5), || {
                live_handle.waiting_after_empty_for_test()
            }));
            fixture.runner.install_retirement_driver_for_test(
                fixture.active,
                live.instance,
                live.running,
            );
            let stop = std::sync::atomic::AtomicBool::new(false);
            let requested_turn = std::sync::atomic::AtomicBool::new(false);
            let (acknowledge, observed_turn) = mpsc::sync_channel(1);
            let _setup_release = StopRetiredSyncOnDrop {
                stop: &stop,
                gate: Arc::clone(fixture.gate),
            };
            let (entered, progressed, tip, joined) = std::thread::scope(|scope| {
                let _scope_release = StopRetiredSyncOnDrop {
                    stop: &stop,
                    gate: Arc::clone(fixture.gate),
                };
                let lifecycle = scope.spawn(|| {
                    while !stop.load(Ordering::Acquire) {
                        let turn = requested_turn.swap(false, Ordering::AcqRel);
                        fixture.runner.drive_retirement_for_test();
                        if turn {
                            let _ = acknowledge.send(());
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                });
                let entered = fixture.gate.wait_entered();
                live.fakes.exec.add_tx(2);
                fixture.runner.handle().transactions_available();
                requested_turn.store(true, Ordering::Release);
                let mut full_turn = false;
                let progressed = entered.is_ok()
                    && observed_within(Duration::from_secs(1), || {
                        full_turn |= observed_turn.try_recv().is_ok();
                        full_turn
                            && live_handle
                                .status()
                                .is_some_and(|status| status.committed_height >= 1)
                            && live.fakes.exec.state.lock().txs.is_empty()
                    });
                let tip = fixture.store.height();
                stop.store(true, Ordering::Release);
                fixture.gate.release();
                (entered, progressed, tip, lifecycle.join())
            });
            joined.unwrap();
            fixture.runner.drive_retirement_for_test();
            assert!(
                observed_within(Duration::from_secs(5), || {
                    live_handle
                        .status()
                        .is_some_and(|status| status.committed_height >= 1)
                        && live.fakes.exec.state.lock().txs.is_empty()
                }),
                "the unchanged independent transaction commits after original native I/O is released"
            );
            let completed = observed_within(Duration::from_secs(5), || {
                publication.finished() && publication.complete()
            });
            let exact_thread = fixture.gate.synchronizer() == Some(original_joiner);
            drop(publication);
            assert!(completed);
            (
                entered,
                progressed && exact_thread,
                tip,
                live_handle,
                live.fakes,
                fixture.budget.clone(),
            )
        });
    // Both physical owners are now joined. The enclosing fixture authenticated
    // the exact original signed body/QC and released the exclusive store custody.
    assert_driver_retired(&live_handle, &live_fakes);
    collect_retired_native_fixture_state(&budget);
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(entered.is_ok());
    assert_eq!(
        tip_while_held, 0,
        "unsynchronized orphan bytes cannot advance the durable tip"
    );
    assert!(
        progressed,
        "original orphan SyncDir must not block another lane's actual lifecycle turn and transaction commit"
    );
}

#[test]
fn native_driver_binds_original_publication_before_its_first_append() {
    use crate::execution_attempt::ExecutionAttemptError as Attempt;
    use crate::sumeragi::availability_schedule::AvailabilitySchedule;
    use crate::sumeragi::lanes::store::FileLaneBlockStore;
    struct Schedule(iroha_sumeragi::availability::AvailabilitySource);
    impl AvailabilitySchedule for Schedule {
        fn instance(&self) -> Hash32 {
            self.0.instance()
        }
        fn height_config(&self, _: u64) -> Result<Option<HeightConfig>, Attempt<std::io::Error>> {
            Ok(Some(self.0.config().clone()))
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let (body, certificate, source, budget, crypto) =
        crate::sumeragi::lanes::record::tests::fixture(1025);
    let store = Arc::new(
        FileLaneBlockStore::begin_open(
            dir.path(),
            &source.instance(),
            Arc::new(crypto),
            budget.clone(),
            Arc::new(Schedule(source.clone())),
        )
        .unwrap()
        .complete()
        .unwrap_or_else(|(_, error)| panic!("original empty store: {error}")),
    );
    let instance =
        spawn_retiring_store_driver(source.instance(), Arc::clone(&store), budget.clone());
    let handle = instance.handle();
    let appended = store.append(&body, &certificate).is_ok();
    let restored = store.committed_body(1).unwrap();
    let exact = restored.as_ref().is_some_and(|(original, qc)| {
        original == &body && qc == &certificate && original.admitted_to(&budget)
    });
    instance.running.shutdown();
    assert_driver_retired(&handle, &instance.fakes);
    drop(handle);
    drop((restored, store, body, certificate));
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        appended && exact,
        "native driver readiness must bind its exact funded joining owner before the first append"
    );
}
