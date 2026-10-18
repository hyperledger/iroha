//! Actual worker-prefix cleanup and exact original joiner transfer before exposure.

use std::{cell::Cell, io};

use iroha_allocation::{AllocationBudget, AllocationRefusal};
use iroha_sumeragi::{
    api::LocalParams,
    crypto::Signer,
    testing::{FakeCrypto, FakeSigner},
    types::{ChainParams, Committee, ConfigSlot, Hash32, HeightConfig},
};

use super::*;
use crate::sumeragi::driver::{
    NodeGate, SharedCrypto, assemble_init,
    persist::install_records,
    tests::fakes::{FakeBlocks, FakeBodies, FakeExecutor, FakeNet, FakeRecords, RecordingObserver},
    traits::{Observer, SystemClock},
};

#[derive(Clone, Copy)]
enum SpawnFault {
    ErrorAt(usize),
    PanicAt(usize),
}

std::thread_local! {
    static FAULT: Cell<Option<SpawnFault>> = const { Cell::new(None) };
    static ATTEMPTS: Cell<usize> = const { Cell::new(0) };
}

/// Refuse only a test caller's original thread-creation boundary.
///
/// # Errors
/// Returns the selected local creation error before spawning that thread.
///
/// # Panics
/// The selected local creation boundary can unwind to exercise acquired-prefix cleanup.
pub fn before_thread(name: &str) -> io::Result<()> {
    let attempt = ATTEMPTS.with(|count| {
        let attempt = count.get();
        count.set(attempt + 1);
        attempt
    });
    match FAULT.get() {
        Some(SpawnFault::ErrorAt(selected)) if attempt == selected => Err(io::Error::other(
            format!("original thread creation refused: {name}"),
        )),
        Some(SpawnFault::PanicAt(selected)) if attempt == selected => {
            panic!("original thread creation unwind: {name}")
        }
        _ => Ok(()),
    }
}

struct SpawnProbe {
    previous: Option<SpawnFault>,
    attempts: usize,
}
impl SpawnProbe {
    fn new(fault: Option<SpawnFault>) -> Self {
        Self {
            previous: FAULT.replace(fault),
            attempts: ATTEMPTS.replace(0),
        }
    }
    fn attempts() -> usize {
        ATTEMPTS.get()
    }
}
impl Drop for SpawnProbe {
    fn drop(&mut self) {
        FAULT.set(self.previous);
        ATTEMPTS.set(self.attempts);
    }
}

type TestDriver<C> = Driver<FakeNet, FakeRecords, FakeBodies, FakeBlocks, C, FakeExecutor>;

struct Owners {
    net: Arc<FakeNet>,
    records: Arc<FakeRecords>,
    bodies: Arc<FakeBodies>,
    blocks: Arc<FakeBlocks>,
    executor: FakeExecutor,
    observer: Arc<RecordingObserver>,
    budget: AllocationBudget,
}
impl Owners {
    fn assert_backends_released(&self) {
        assert_eq!(
            Arc::strong_count(&self.net),
            1,
            "original transport released"
        );
        assert_eq!(
            Arc::strong_count(&self.records),
            1,
            "original records released"
        );
        assert_eq!(
            Arc::strong_count(&self.bodies),
            1,
            "original bodies released"
        );
        assert_eq!(
            Arc::strong_count(&self.blocks),
            1,
            "original block store released"
        );
        assert_eq!(
            Arc::strong_count(&self.executor.state),
            1,
            "original executor released"
        );
        assert_eq!(
            Arc::strong_count(&self.observer),
            1,
            "original observer released"
        );
    }
    fn assert_released(&self) {
        self.assert_backends_released();
        assert_eq!(
            self.budget.reserved_bytes(),
            0,
            "original admission fully refunded"
        );
    }
}

struct Fixture<C> {
    driver: TestDriver<C>,
    start: DriverStart,
    owners: Owners,
}

fn startup_input(
    records: &FakeRecords,
    blocks: &FakeBlocks,
    config: &HeightConfig,
    signer: FakeSigner,
    budget: &AllocationBudget,
) -> DriverStart {
    let key = signer.public_key().clone();
    let crypto: SharedCrypto = Arc::new(FakeCrypto::new());
    let instance = Hash32([247; 32]);
    records.install_key(&key, true, 1);
    let mut next = 1_u128;
    let mut fresh = || {
        next += 1;
        next
    };
    let found = install_records(
        records,
        &*crypto,
        &instance,
        iroha_sumeragi::testing::TEST_EPOCH.id,
        &[(key, false)],
        0,
        false,
        &mut fresh,
    )
    .unwrap();
    let genesis = (Hash32([0x31; 32]), Hash32([0x32; 32]));
    let init = assemble_init(
        blocks,
        instance,
        0,
        genesis,
        128,
        found,
        vec![
            (1, ConfigSlot::Ready(config.clone())),
            (2, ConfigSlot::Ready(config.clone())),
        ],
        247,
    )
    .unwrap();
    DriverStart {
        node_gate: Arc::new(NodeGate::new()),
        allocation_budget: budget.clone(),
        local: LocalParams::default(),
        init,
        signers: vec![Arc::new(signer)],
        crypto,
    }
}

fn fixture<C: Clock + 'static>(clock: Arc<C>) -> Fixture<C> {
    let signer = FakeSigner::from_seed(&[247], None);
    let config = HeightConfig {
        epoch: Box::new(iroha_sumeragi::testing::TEST_EPOCH),
        committee: Committee::new(vec![signer.public_key().clone()]).unwrap(),
        params: ChainParams {
            block_time: 10,
            payload_retry_interval: 30,
            ..ChainParams::default()
        },
    };
    let budget = AllocationBudget::new(1 << 28);
    let records = Arc::new(FakeRecords::default());
    let blocks = Arc::new(FakeBlocks::default());
    let start = startup_input(&records, &blocks, &config, signer, &budget);
    let genesis = (Hash32([0x31; 32]), Hash32([0x32; 32]));
    let mut executor = FakeExecutor::new(genesis.0, genesis.1, config);
    executor.budget = budget.clone();
    let owners = Owners {
        net: Arc::new(FakeNet::default()),
        records,
        bodies: Arc::new(FakeBodies::default()),
        blocks,
        executor,
        observer: Arc::new(RecordingObserver::default()),
        budget,
    };
    let observer: Arc<dyn Observer> = owners.observer.clone();
    let driver = Driver::new(
        Arc::clone(&owners.net),
        Arc::clone(&owners.records),
        Arc::clone(&owners.bodies),
        Arc::clone(&owners.blocks),
        clock,
        owners.executor.clone(),
        observer,
    );
    Fixture {
        driver,
        start,
        owners,
    }
}

fn refusal(result: Result<RunningDriver, DriverError>) -> DriverError {
    match result {
        Err(error) => error,
        Ok(running) => {
            running.shutdown();
            panic!("startup unexpectedly succeeded")
        }
    }
}

#[test]
fn every_thread_creation_refusal_joins_original_acquired_prefix() {
    let names = [
        "sumeragi-join",
        "sumeragi-persist",
        "sumeragi-exec",
        "sumeragi-serve",
        "sumeragi-loop",
    ];
    for (selected, name) in names.into_iter().enumerate() {
        let Fixture {
            driver,
            start,
            owners,
        } = fixture(Arc::new(SystemClock::new()));
        let _probe = SpawnProbe::new(Some(SpawnFault::ErrorAt(selected)));
        let error = refusal(driver.spawn(DriverConfig::default(), start));
        owners.assert_released();
        assert_eq!(
            SpawnProbe::attempts(),
            selected + 1,
            "no later worker creation after refusal"
        );
        assert!(
            matches!(error, DriverError::Thread(ref error) if error.kind() == io::ErrorKind::Other && error.to_string() == format!("original thread creation refused: {name}"))
        );
        assert_eq!(
            *owners.observer.finished.lock(),
            0,
            "loop was never started"
        );
    }
}

#[test]
fn every_thread_creation_unwind_joins_original_acquired_prefix() {
    for selected in 0..5 {
        let Fixture {
            driver,
            start,
            owners,
        } = fixture(Arc::new(SystemClock::new()));
        let _probe = SpawnProbe::new(Some(SpawnFault::PanicAt(selected)));
        let result = catch_unwind(AssertUnwindSafe(|| {
            driver.spawn(DriverConfig::default(), start)
        }));
        owners.assert_released();
        assert!(
            result.is_err(),
            "selected local creation boundary must unwind"
        );
        assert_eq!(SpawnProbe::attempts(), selected + 1);
        assert_eq!(*owners.observer.finished.lock(), 0);
    }
}

#[test]
fn admission_refusal_remains_typed_and_starts_no_thread() {
    let Fixture {
        driver,
        start,
        owners,
    } = fixture(Arc::new(SystemClock::new()));
    owners.budget.set_limit_bytes(0);
    let _probe = SpawnProbe::new(None);
    let error = refusal(driver.spawn(DriverConfig::default(), start));
    owners.assert_released();
    assert!(
        matches!(error, DriverError::Admission(AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes: 0 }) if requested_bytes > 0)
    );
    assert_eq!(
        SpawnProbe::attempts(),
        0,
        "resource refusal precedes the original joiner"
    );
}

#[test]
fn kernel_readiness_refusal_preserves_typed_error_and_joins_all_workers() {
    let Fixture {
        driver,
        mut start,
        owners,
    } = fixture(Arc::new(SystemClock::new()));
    start.signers.clear();
    let _probe = SpawnProbe::new(None);
    let error = refusal(driver.spawn(DriverConfig::default(), start));
    owners.assert_released();
    assert!(matches!(
        error,
        DriverError::Config(ConfigError::InvalidInit("no signer for a configured key"))
    ));
    assert_eq!(
        SpawnProbe::attempts(),
        5,
        "real kernel refused after all four workers started"
    );
    assert_eq!(*owners.observer.finished.lock(), 1);
}

#[test]
fn loop_readiness_unwind_preserves_original_error_and_joins_all_workers() {
    struct PanicClock(Arc<()>);
    impl Clock for PanicClock {
        fn now(&self) -> iroha_sumeragi::types::Millis {
            std::panic::panic_any(self.0.clone());
        }
    }
    let original = Arc::new(());
    let Fixture {
        driver,
        start,
        owners,
    } = fixture(Arc::new(PanicClock(original.clone())));
    let _probe = SpawnProbe::new(None);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        driver.spawn(DriverConfig::default(), start)
    }));
    owners.assert_released();
    assert!(
        outcome
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<Arc<()>>())
            .is_some_and(|retained| Arc::ptr_eq(retained, &original)),
        "readiness failure must retain the exact original worker panic after every physical join"
    );
    drop(outcome);
    assert_eq!(Arc::strong_count(&original), 1);
    assert_eq!(SpawnProbe::attempts(), 5);
    assert_eq!(*owners.observer.finished.lock(), 0);
    assert_eq!(*owners.observer.stopped.lock(), vec![Worker::Loop]);
}

#[test]
fn abandoned_ready_preparation_joins_workers_before_cancelled_joiner() {
    let Fixture {
        driver,
        start,
        owners,
    } = fixture(Arc::new(SystemClock::new()));
    let (start, retirement) = WorkerStart::new(driver, DriverConfig::default(), start).unwrap();
    let joiner = OriginalJoiner::start(retirement).unwrap();
    let prepared = start.spawn_workers().unwrap();
    let handle = prepared.handle.clone();
    assert!(handle.ready());
    assert_eq!(prepared.threads.len(), 4);
    drop(prepared);
    owners.assert_backends_released();
    assert!(
        !handle.ready(),
        "abandonment sends the original Stop before joining"
    );
    assert_eq!(*owners.observer.finished.lock(), 1);
    drop(joiner);
    drop(handle);
    owners.assert_released();
}

#[test]
fn successful_attachment_keeps_exact_original_joiner_and_workers() {
    let Fixture {
        driver,
        start,
        owners,
    } = fixture(Arc::new(SystemClock::new()));
    let (start, retirement) = WorkerStart::new(driver, DriverConfig::default(), start).unwrap();
    let joiner = OriginalJoiner::start(retirement).unwrap();
    let original_joiner = joiner.0.as_ref().unwrap().thread.thread().id();
    let prepared = start.spawn_workers().unwrap();
    let original_workers = prepared
        .threads
        .iter()
        .map(|thread| thread.thread().id())
        .collect::<Vec<_>>();
    assert_eq!(original_workers.len(), 4);
    let running = prepared.attach(joiner);
    let handle = running.handle();
    assert!(
        handle.ready(),
        "preparation Drop cannot stop attached workers"
    );
    assert_eq!(
        running.joiner.as_ref().unwrap().thread.thread().id(),
        original_joiner
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
    owners.assert_backends_released();
    assert!(!handle.ready());
    assert_eq!(*owners.observer.finished.lock(), 1);
    drop(handle);
    owners.assert_released();
}

// The ordinary seven controls above are unchanged. These exercise the same
// constructor after original joiner admission and an explicit activation turn.
use super::pending::{PendingDriver, StartupPoll};

type TestPreparation =
    DriverPreparation<FakeNet, FakeRecords, FakeBodies, FakeBlocks, SystemClock, FakeExecutor>;

fn next_pending_phase(pending: &mut PendingDriver) -> Option<StartupPoll> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let phase = pending.poll();
        if !matches!(phase, StartupPoll::Pending) {
            return Some(phase);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::yield_now();
    }
}

fn pending_fixture<C: Clock + 'static>(
    driver: TestDriver<C>,
    start: DriverStart,
    budget: &AllocationBudget,
) -> PendingDriver {
    PendingDriver::spawn(
        start.init.instance,
        budget,
        DriverConfig::default().backoff,
        move |_| {
            Ok(Some(DriverPreparation::new(
                driver,
                DriverConfig::default(),
                start,
            )))
        },
    )
    .unwrap()
}

#[test]
fn pending_startup_exact_control_admission_precedes_original_thread() {
    let bytes = PendingDriver::admission_bytes().unwrap();
    let budget = AllocationBudget::new(bytes - 1);
    let _probe = SpawnProbe::new(None);
    let refused = PendingDriver::spawn(
        Hash32([247; 32]),
        &budget,
        DriverConfig::default().backoff,
        |_| -> Result<
            Option<TestPreparation>,
            crate::execution_attempt::ExecutionAttemptError<StartupPreparationError>,
        > { panic!("unfunded preparation cannot run") },
    );
    let error = match refused {
        Err(error) => error,
        Ok(owner) => {
            drop(owner);
            panic!("short startup control unexpectedly admitted")
        }
    };
    assert!(
        matches!(error, DriverError::Admission(AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes }) if requested_bytes == bytes && limit_bytes == bytes - 1)
    );
    assert_eq!(SpawnProbe::attempts(), 0);
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(bytes);
    let observed = budget.clone();
    let (send, receive) = mpsc::sync_channel(1);
    let pending = PendingDriver::spawn(
        Hash32([247; 32]),
        &budget,
        DriverConfig::default().backoff,
        move |_| -> Result<
            Option<TestPreparation>,
            crate::execution_attempt::ExecutionAttemptError<StartupPreparationError>,
        > {
            send.send(observed.reserved_bytes()).unwrap();
            Ok(None)
        },
    )
    .unwrap();
    let charge = receive.recv_timeout(std::time::Duration::from_secs(5));
    drop(pending);
    assert_eq!(charge.unwrap(), bytes);
    assert_eq!(SpawnProbe::attempts(), 1);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn pending_startup_awaits_activation_and_transfers_original_joiner() {
    let Fixture {
        driver,
        start,
        owners,
    } = fixture(Arc::new(SystemClock::new()));
    let (send, receive) = mpsc::sync_channel(1);
    let mut pending = PendingDriver::spawn(
        start.init.instance,
        &owners.budget,
        DriverConfig::default().backoff,
        move |_| {
            send.send(std::thread::current().id()).unwrap();
            Ok(Some(DriverPreparation::new(
                driver,
                DriverConfig::default(),
                start,
            )))
        },
    )
    .unwrap();
    let original = receive.recv_timeout(std::time::Duration::from_secs(5));
    let awaiting = next_pending_phase(&mut pending);
    let no_finished_worker = *owners.observer.finished.lock() == 0;
    let approved = pending.activate();
    let ready = next_pending_phase(&mut pending);
    let (transferred, same_joiner, original_membership) = match ready {
        Some(StartupPoll::Ready(running)) => {
            let same = running
                .joiner
                .as_ref()
                .map(|joiner| joiner.thread.thread().id())
                == original.as_ref().ok().copied();
            let membership = running.threads.len() == 4
                && running
                    .threads
                    .iter()
                    .all(|worker| pending.owns_worker(worker.thread().id()))
                && !pending.owns_worker(std::thread::current().id());
            running.shutdown();
            (true, same, membership)
        }
        _ => (false, false, false),
    };
    drop(pending);
    owners.assert_released();
    assert!(matches!(awaiting, Some(StartupPoll::AwaitingActivation)));
    assert!(no_finished_worker);
    assert!(
        approved && transferred && same_joiner,
        "exact original joiner must transfer with activated workers"
    );
    assert!(
        original_membership,
        "only exact acquired original workers select self-worker final shutdown"
    );
    assert_eq!(*owners.observer.finished.lock(), 1);
}

#[test]
fn pending_startup_cancellation_before_activation_drops_no_started_worker() {
    let Fixture {
        driver,
        start,
        owners,
    } = fixture(Arc::new(SystemClock::new()));
    let mut pending = pending_fixture(driver, start, &owners.budget);
    let awaiting = next_pending_phase(&mut pending);
    pending.cancel();
    let refused_activation = !pending.activate();
    drop(pending);
    owners.assert_released();
    assert!(matches!(awaiting, Some(StartupPoll::AwaitingActivation)));
    assert!(refused_activation);
    assert_eq!(*owners.observer.finished.lock(), 0);
    assert!(owners.observer.stopped.lock().is_empty());
}

#[test]
fn pending_startup_capacity_retry_retains_original_prepared_inputs() {
    let Fixture {
        driver,
        start,
        owners,
    } = fixture(Arc::new(SystemClock::new()));
    let limit = owners.budget.limit_bytes();
    let bytes = PendingDriver::admission_bytes().unwrap();
    let held = owners.budget.try_reserve_bytes(limit - bytes).unwrap();
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls = Arc::clone(&attempts);
    let (send, receive) = mpsc::sync_channel(1);
    let mut pending = PendingDriver::spawn(
        start.init.instance,
        &owners.budget,
        DriverConfig::default().backoff,
        move |_| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            send.send(()).unwrap();
            Ok(Some(DriverPreparation::new(
                driver,
                DriverConfig::default(),
                start,
            )))
        },
    )
    .unwrap();
    let prepared = receive.recv_timeout(std::time::Duration::from_secs(5));
    let foreign = AllocationBudget::new(1);
    let foreign_hold = foreign.try_reserve_bytes(1).unwrap();
    drop(foreign_hold);
    let before_release = pending.poll();
    let original_still_retained = Arc::strong_count(&owners.executor.state) == 2;
    drop(held);
    let after_release = next_pending_phase(&mut pending);
    pending.cancel();
    drop(pending);
    owners.assert_released();
    assert!(prepared.is_ok());
    assert!(matches!(before_release, StartupPoll::Pending));
    assert!(
        original_still_retained,
        "capacity refusal retains the original recovered executor"
    );
    assert!(
        matches!(after_release, Some(StartupPoll::AwaitingActivation)),
        "genuine original release retries on the same intended joiner"
    );
    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "admission retry must not reconstruct prepared inputs"
    );
    assert_eq!(*owners.observer.finished.lock(), 0);
}

#[test]
fn pending_startup_refuses_foreign_instance_and_resource_pool_before_activation() {
    for foreign_pool in [false, true] {
        let Fixture {
            driver,
            start,
            owners,
        } = fixture(Arc::new(SystemClock::new()));
        let foreign = AllocationBudget::new(1 << 28);
        let budget = if foreign_pool {
            &foreign
        } else {
            &owners.budget
        };
        let instance = if foreign_pool {
            start.init.instance
        } else {
            Hash32([248; 32])
        };
        let mut pending = PendingDriver::spawn(
            instance,
            budget,
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
        let refused = next_pending_phase(&mut pending);
        let terminal = pending.poll();
        drop(pending);
        owners.assert_released();
        assert_eq!(foreign.reserved_bytes(), 0);
        assert!(matches!(
            refused,
            Some(StartupPoll::Refused(DriverError::StartupIdentity))
        ));
        assert!(matches!(terminal, StartupPoll::Failed));
        assert_eq!(*owners.observer.finished.lock(), 0);
    }
}

#[test]
fn pending_startup_reenters_original_gate_after_activation_wait() {
    let Fixture {
        driver,
        start,
        owners,
    } = fixture(Arc::new(SystemClock::new()));
    let gate = Arc::clone(&start.node_gate);
    let mut pending = pending_fixture(driver, start, &owners.budget);
    let awaiting = next_pending_phase(&mut pending);
    gate.close();
    let approved = pending.activate();
    let refused = next_pending_phase(&mut pending);
    drop(pending);
    owners.assert_released();
    assert!(matches!(awaiting, Some(StartupPoll::AwaitingActivation)) && approved);
    assert!(matches!(
        refused,
        Some(StartupPoll::Refused(DriverError::StorageClosed))
    ));
    assert_eq!(*owners.observer.finished.lock(), 0);
}

#[test]
fn pending_startup_readiness_failure_stays_terminal_and_typed() {
    let Fixture {
        driver,
        mut start,
        owners,
    } = fixture(Arc::new(SystemClock::new()));
    start.signers.clear();
    let mut pending = pending_fixture(driver, start, &owners.budget);
    let awaiting = next_pending_phase(&mut pending);
    let approved = pending.activate();
    let refused = next_pending_phase(&mut pending);
    let terminal = pending.poll();
    drop(pending);
    owners.assert_released();
    assert!(matches!(awaiting, Some(StartupPoll::AwaitingActivation)) && approved);
    assert!(matches!(
        refused,
        Some(StartupPoll::Refused(DriverError::Config(
            ConfigError::InvalidInit("no signer for a configured key")
        )))
    ));
    assert!(matches!(terminal, StartupPoll::Failed));
    assert_eq!(*owners.observer.finished.lock(), 1);
}

#[test]
fn pending_startup_worker_creation_failure_joins_original_prefix_without_reprepare() {
    for selected in 0..4 {
        let Fixture {
            driver,
            start,
            owners,
        } = fixture(Arc::new(SystemClock::new()));
        let mut pending = PendingDriver::spawn(
            start.init.instance,
            &owners.budget,
            DriverConfig::default().backoff,
            move |_| {
                // These test locals belong only to the new original joiner.
                // Its exit destroys them; no parent thread fault setting changes.
                ATTEMPTS.set(0);
                FAULT.set(Some(SpawnFault::ErrorAt(selected)));
                Ok(Some(DriverPreparation::new(
                    driver,
                    DriverConfig::default(),
                    start,
                )))
            },
        )
        .unwrap();
        let awaiting = next_pending_phase(&mut pending);
        let approved = pending.activate();
        let refused = next_pending_phase(&mut pending);
        let terminal = pending.poll();
        drop(pending);
        owners.assert_released();
        assert!(matches!(awaiting, Some(StartupPoll::AwaitingActivation)) && approved);
        assert!(matches!(
            refused,
            Some(StartupPoll::Refused(DriverError::Thread(_)))
        ));
        assert!(matches!(terminal, StartupPoll::Failed));
        assert_eq!(*owners.observer.finished.lock(), 0);
    }
}

#[test]
fn pending_startup_preparation_unwind_retains_failed_generation_until_drop() {
    let Fixture {
        driver,
        start,
        owners,
    } = fixture(Arc::new(SystemClock::new()));
    let mut pending = PendingDriver::spawn(
        start.init.instance,
        &owners.budget,
        DriverConfig::default().backoff,
        move |_| -> Result<
            Option<TestPreparation>,
            crate::execution_attempt::ExecutionAttemptError<StartupPreparationError>,
        > {
            let _original = (driver, start);
            panic!("original preparation unwinds before activation")
        },
    )
    .unwrap();
    let failed = next_pending_phase(&mut pending);
    let still_failed = pending.poll();
    drop(pending);
    owners.assert_released();
    assert!(matches!(failed, Some(StartupPoll::Failed)));
    assert!(matches!(still_failed, StartupPoll::Failed));
}

#[test]
fn pending_startup_worker_creation_unwind_joins_every_original_prefix() {
    for selected in 0..4 {
        let Fixture {
            driver,
            start,
            owners,
        } = fixture(Arc::new(SystemClock::new()));
        let mut pending = PendingDriver::spawn(
            start.init.instance,
            &owners.budget,
            DriverConfig::default().backoff,
            move |_| {
                ATTEMPTS.set(0);
                FAULT.set(Some(SpawnFault::PanicAt(selected)));
                Ok(Some(DriverPreparation::new(
                    driver,
                    DriverConfig::default(),
                    start,
                )))
            },
        )
        .unwrap();
        let awaiting = next_pending_phase(&mut pending);
        let approved = pending.activate();
        let failed = next_pending_phase(&mut pending);
        drop(pending);
        owners.assert_released();
        assert!(matches!(awaiting, Some(StartupPoll::AwaitingActivation)) && approved);
        assert!(matches!(failed, Some(StartupPoll::Failed)));
        assert_eq!(*owners.observer.finished.lock(), 0);
    }
}

#[test]
fn pending_startup_preserves_original_preparation_refusal_and_release_source() {
    use crate::execution_attempt::ExecutionAttemptError as Attempt;
    use iroha_allocation::release::ReleaseRegistration;
    use std::task::{Context, Waker};
    let original_pool = AllocationBudget::new(1 << 20);
    let mut registration = ReleaseRegistration::from_reservation(
        &mut original_pool
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap();
    let held = original_pool
        .try_reserve_bytes(original_pool.limit_bytes() - original_pool.reserved_bytes())
        .unwrap();
    let original = original_pool.try_reserve_bytes(1).unwrap_err();
    let budget = AllocationBudget::new(1 << 20);
    let mut pending = PendingDriver::spawn(
        Hash32([247; 32]),
        &budget,
        DriverConfig::default().backoff,
        move |_| -> Result<Option<TestPreparation>, Attempt<StartupPreparationError>> {
            Err(Attempt::Deferred(original.into()))
        },
    )
    .unwrap();
    let result = next_pending_phase(&mut pending);
    let terminal = pending.poll();
    drop(pending);
    assert_eq!(budget.reserved_bytes(), 0);
    let Some(StartupPoll::PreparationRefused(Attempt::Deferred(original))) = result else {
        panic!("original preparation refusal must stay typed")
    };
    let Some(AllocationRefusal::Capacity { release, .. }) = original.allocation_refusal() else {
        panic!("original preparation capacity release must remain owned")
    };
    assert!(
        registration
            .poll_wait(release, &mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(held);
    assert!(
        registration
            .poll_wait(release, &mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    assert!(
        matches!(terminal, StartupPoll::Failed),
        "terminal preparation cannot authorize reconstruction of its generation"
    );
    drop(registration);
    assert_eq!(original_pool.reserved_bytes(), 0);
}

#[test]
fn pending_ready_with_finished_original_joiner_stays_owned_and_unexposed() {
    for failed in [false, true] {
        let Fixture {
            driver,
            start,
            owners,
        } = fixture(Arc::new(SystemClock::new()));
        let (worker_start, retirement) =
            WorkerStart::new(driver, DriverConfig::default(), start).unwrap();
        assert!(retirement.is_none());
        let prepared = worker_start.spawn_workers().unwrap();
        let original = OriginalJoiner::start_preparing(move |_receive| {
            assert!(!failed, "selected original joining-thread unwind");
        })
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !original.0.as_ref().unwrap().thread.is_finished()
            && std::time::Instant::now() < deadline
        {
            std::thread::yield_now();
        }
        let ended = original.0.as_ref().unwrap().thread.is_finished();
        let mut pending =
            PendingDriver::ready_with_joiner_for_test(prepared, original, &owners.budget);
        let first = pending.poll();
        let refused = matches!(first, StartupPoll::Failed);
        let retained = pending.retains_ready_for_test();
        let remains_failed = matches!(pending.poll(), StartupPoll::Failed);
        // The unfixed path may expose Ready. Dispose it before any causal assertion.
        if let StartupPoll::Ready(running) = first {
            running.shutdown();
        }
        drop(pending);
        owners.assert_released();
        assert!(ended, "original joining-thread completion must be observed");
        assert!(
            refused && retained && remains_failed,
            "Ready must remain unexposed with exact workers when its original joiner already ended"
        );
        assert_eq!(*owners.observer.finished.lock(), 1);
    }
}

fn startup_observed(mut observation: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !observation() {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::yield_now();
    }
    true
}

#[test]
fn pending_transfer_retains_original_startup_charge_until_worker_join() {
    use crate::sumeragi::driver::tests::fakes::FakeClock;

    struct ReleaseExecutor(FakeExecutor);
    impl Drop for ReleaseExecutor {
        fn drop(&mut self) {
            self.0.set_open(true);
        }
    }

    let clock = Arc::new(FakeClock::default());
    let Fixture {
        driver,
        start,
        owners,
    } = fixture(Arc::clone(&clock));
    owners.executor.set_open(false);
    let mut running = None;
    let mut pending = PendingDriver::spawn(
        start.init.instance,
        &owners.budget,
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
    // Drop before either real worker owner on setup failure or unwinding.
    let release = ReleaseExecutor(owners.executor.clone());
    let awaiting = next_pending_phase(&mut pending);
    let activated = pending.activate();
    let mut notified = false;
    let ready_and_blocked = startup_observed(|| {
        // Idle chains do not build. Submit real work to the exact Ready owner
        // before requiring its original executor to be held at the build latch.
        if !notified && let Some(handle) = pending.ready_handle_for_test() {
            owners.executor.add_tx(1);
            clock.advance(owners.executor.state.lock().config.params.block_time);
            handle.transactions_available();
            notified = true;
        }
        pending.ready_handle_for_test().is_some() && owners.executor.waiting() == 1
    });
    let before = owners.budget.reserved_bytes();
    if let StartupPoll::Ready(original) = pending.poll() {
        running = Some(original);
    }
    let transferred = running.is_some();
    let receiving = startup_observed(|| pending.original_join_wait_entered_for_test());
    let after = owners.budget.reserved_bytes();
    let still_blocked = owners.executor.waiting() == 1;
    drop(release);
    if let Some(original) = running {
        original.shutdown();
    }
    drop(pending);
    owners.assert_released();
    assert!(matches!(awaiting, Some(StartupPoll::AwaitingActivation)) && activated);
    assert!(
        ready_and_blocked && transferred && receiving && still_blocked,
        "the original joiner must receive custody while its original executor remains blocked"
    );
    assert!(before >= PendingDriver::admission_bytes().unwrap());
    assert_eq!(
        after, before,
        "original startup registration and control charge must survive transfer until workers join"
    );
    assert_eq!(*owners.observer.finished.lock(), 1);
}

#[test]
fn cancelled_readiness_refusal_retires_only_after_original_cleanup() {
    let Fixture {
        driver,
        mut start,
        owners,
    } = fixture(Arc::new(SystemClock::new()));
    start.signers.clear();
    let mut pending = pending_fixture(driver, start, &owners.budget);
    let awaiting = next_pending_phase(&mut pending);
    let activated = pending.activate();
    let refusal = next_pending_phase(&mut pending);
    let still_active = pending.poll_cancelled_failure();
    pending.retire();
    let joined = startup_observed(|| pending.poll_cancelled_failure() == StartupRetirement::Joined);
    let backends_released = Arc::strong_count(&owners.executor.state) == 1;
    drop(pending);
    owners.assert_released();
    assert!(matches!(awaiting, Some(StartupPoll::AwaitingActivation)) && activated);
    assert!(matches!(
        refusal,
        Some(StartupPoll::Refused(DriverError::Config(
            ConfigError::InvalidInit("no signer for a configured key")
        )))
    ));
    assert_eq!(
        still_active,
        StartupRetirement::Pending,
        "a still-current failed generation must remain excluded"
    );
    assert!(
        joined && backends_released,
        "explicit retirement must reap the successfully joined original startup refusal"
    );
    assert_eq!(*owners.observer.finished.lock(), 1);
}

#[test]
fn cancelled_failed_joiner_cannot_report_startup_retirement_success() {
    for ready in [false, true] {
        let Fixture {
            driver,
            start,
            owners,
        } = fixture(Arc::new(SystemClock::new()));
        let mut pending = if ready {
            let (worker_start, retirement) =
                WorkerStart::new(driver, DriverConfig::default(), start).unwrap();
            assert!(retirement.is_none());
            let prepared = worker_start.spawn_workers().unwrap();
            let original = OriginalJoiner::start_preparing(|_| {}).unwrap();
            let ended = startup_observed(|| original.0.as_ref().unwrap().thread.is_finished());
            assert!(ended);
            PendingDriver::ready_with_joiner_for_test(prepared, original, &owners.budget)
        } else {
            PendingDriver::spawn(
                start.init.instance,
                &owners.budget,
                DriverConfig::default().backoff,
                move |_| -> Result<
                    Option<TestPreparation>,
                    crate::execution_attempt::ExecutionAttemptError<StartupPreparationError>,
                > {
                    let _original = (driver, start);
                    panic!("original failed joiner cannot certify physical retirement");
                },
            )
            .unwrap()
        };
        let failed = next_pending_phase(&mut pending);
        pending.cancel();
        let retired = pending.poll_cancelled_failure();
        let still_failed = pending.poll();
        let ready_retained = !ready || pending.retains_ready_for_test();
        // A broken observation may expose Ready. Cleanup precedes the causal assertion.
        if let Some(StartupPoll::Ready(running)) = failed {
            running.shutdown();
        }
        drop(pending);
        owners.assert_released();
        assert_eq!(
            retired,
            StartupRetirement::Failed,
            "failed or missing original joiner must never certify retired startup success"
        );
        assert!(matches!(still_failed, StartupPoll::Failed) && ready_retained);
    }
}

// A one-shot native observation on the original joining thread, configured only
// by its own test preparation closure. The production build has no hook or wait.
std::thread_local! {
    static TRANSFER_OBSERVATION: std::cell::RefCell<Option<(
        mpsc::SyncSender<std::thread::ThreadId>, mpsc::Receiver<()>,
    )>> = const { std::cell::RefCell::new(None) };
}

/// Observe the original transfer decision after its actual mutex has been released.
///
/// # Panics
/// Panics when the test fails to release its observed original joining thread.
pub(super) fn after_transfer_observation() {
    let observation = TRANSFER_OBSERVATION.with(|slot| slot.borrow_mut().take());
    if let Some((observed, release)) = observation {
        let _ = observed.send(std::thread::current().id());
        release
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("release the original joining thread after its ownership observation");
    }
}

#[test]
fn cancelled_ready_transfer_keeps_original_joiner_until_every_worker_finishes() {
    use crate::sumeragi::driver::tests::fakes::FakeClock;

    struct ReleaseOriginals {
        executor: FakeExecutor,
        joiner: Option<mpsc::SyncSender<()>>,
    }
    impl ReleaseOriginals {
        fn release_joiner(&mut self) {
            if let Some(release) = self.joiner.take() {
                let _ = release.send(());
            }
        }
    }
    impl Drop for ReleaseOriginals {
        fn drop(&mut self) {
            self.release_joiner();
            self.executor.set_open(true);
        }
    }

    let clock = Arc::new(FakeClock::default());
    let Fixture {
        driver,
        start,
        owners,
    } = fixture(Arc::clone(&clock));
    owners.executor.set_open(false);
    let (observed, observation) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    let mut running = None;
    let mut pending = PendingDriver::spawn(
        start.init.instance,
        &owners.budget,
        DriverConfig::default().backoff,
        move |_| {
            TRANSFER_OBSERVATION.with(|slot| {
                assert!(slot.borrow_mut().replace((observed, resume)).is_none());
            });
            Ok(Some(DriverPreparation::new(
                driver,
                DriverConfig::default(),
                start,
            )))
        },
    )
    .unwrap();
    // This releases both held physical workers before either original owner drops.
    let mut release = ReleaseOriginals {
        executor: owners.executor.clone(),
        joiner: Some(release),
    };
    let awaiting = next_pending_phase(&mut pending);
    let activated = pending.activate();
    let original_joiner = observation.recv_timeout(std::time::Duration::from_secs(5));
    // Hold actual work before cancelling Ready; idle startup never promises a build.
    if let Some(handle) = pending.ready_handle_for_test() {
        owners.executor.add_tx(1);
        clock.advance(owners.executor.state.lock().config.params.block_time);
        handle.transactions_available();
    }
    let blocked = startup_observed(|| owners.executor.waiting() == 1);
    pending.cancel();
    let mut same_joiner = false;
    if let StartupPoll::Ready(original) = pending.poll() {
        same_joiner = original
            .joiner
            .as_ref()
            .map(|joiner| joiner.thread.thread().id())
            == original_joiner.as_ref().ok().copied();
        running = Some(original);
    }
    let transferred = running.is_some();
    release.release_joiner();
    let held_retirement = running
        .as_mut()
        .is_some_and(|driver| !driver.poll_shutdown());
    owners.executor.set_open(true);
    let joined = running
        .as_mut()
        .is_some_and(|driver| startup_observed(|| driver.poll_shutdown()));
    drop(release);
    if let Some(original) = running {
        original.shutdown();
    }
    drop(pending);
    owners.assert_released();
    assert_eq!(*owners.observer.finished.lock(), 1);
    assert!(matches!(awaiting, Some(StartupPoll::AwaitingActivation)) && activated);
    assert!(
        original_joiner.is_ok() && blocked && transferred && same_joiner,
        "actual original Ready must transfer after cancellation in the observed ownership window"
    );
    assert!(
        held_retirement,
        "the blocked original executor must prevent physical retirement"
    );
    assert!(
        joined,
        "cancelled Ready transfer must retain its original physical joining owner"
    );
}

/// Install a fault on only the actual deferred startup's original thread.
pub(super) fn refuse_startup_thread(selected: usize) {
    ATTEMPTS.set(0);
    FAULT.set(Some(SpawnFault::ErrorAt(selected)));
}

struct PanickingStartupClock;
impl Clock for PanickingStartupClock {
    fn now(&self) -> u64 {
        panic!("original startup worker clock panic")
    }
}

#[test]
fn refused_startup_retains_original_worker_panic_after_all_prefix_joins() {
    let Fixture {
        driver,
        start,
        owners,
    } = fixture(Arc::new(PanickingStartupClock));
    let mut pending = pending_fixture(driver, start, &owners.budget);
    let awaiting = next_pending_phase(&mut pending);
    let activated = pending.activate();
    let refused = next_pending_phase(&mut pending);
    pending.retire();
    let ended = startup_observed(|| pending.original_joiner_finished_for_test());
    let retired = pending.poll_cancelled_failure();
    let original_panic =
        pending.original_join_failure_for_test("original startup worker clock panic");
    drop(pending);
    owners.assert_released();
    assert!(matches!(awaiting, Some(StartupPoll::AwaitingActivation)) && activated && ended);
    assert!(matches!(
        refused,
        Some(StartupPoll::Refused(DriverError::Config(
            ConfigError::InvalidInit("event loop died")
        )))
    ));
    assert!(original_panic);
    assert_eq!(retired, StartupRetirement::Failed);
}

struct RefusingOriginalBinding {
    blocks: Arc<FakeBlocks>,
    budget: AllocationBudget,
    instance: Hash32,
    original: Arc<()>,
    panic: bool,
    entered: std::sync::OnceLock<std::thread::ThreadId>,
}
#[derive(Debug)]
struct OriginalStartupBindingError(Arc<()>);
impl std::fmt::Display for OriginalStartupBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original startup binding error")
    }
}
impl std::error::Error for OriginalStartupBindingError {}
impl crate::sumeragi::driver::traits::RetiredPublication for RefusingOriginalBinding {
    fn instance(&self) -> Hash32 {
        self.instance
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.budget.same_pool(budget)
    }
    fn bind_owner(
        &self,
        owner: crate::sumeragi::driver::OriginalPublicationOwner,
    ) -> io::Result<()> {
        owner.require_binding_thread()?;
        self.entered.set(std::thread::current().id()).unwrap();
        if self.panic {
            std::panic::panic_any(self.original.clone());
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            OriginalStartupBindingError(self.original.clone()),
        ))
    }
    fn resume(
        &self,
        _: &crate::sumeragi::driver::OriginalPublicationOwner,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<io::Error>> {
        panic!("failed original binding cannot authorize publication")
    }
}
impl crate::sumeragi::durable_artifact::BodyReader for RefusingOriginalBinding {
    fn begin_read(
        &self,
        source: iroha_sumeragi::availability::AvailabilitySource,
    ) -> Result<
        Box<dyn crate::sumeragi::durable_artifact::BodyReadJob>,
        crate::sumeragi::durable_artifact::BodyReadError,
    > {
        crate::sumeragi::durable_artifact::BodyReader::begin_read(&*self.blocks, source)
    }
}
impl BlockStore for RefusingOriginalBinding {
    fn retired_publication(
        self: Arc<Self>,
    ) -> Option<Arc<dyn crate::sumeragi::driver::traits::RetiredPublication>> {
        Some(self)
    }
    fn height(&self) -> u64 {
        self.blocks.height()
    }
    fn committed_body(
        &self,
        height: u64,
    ) -> Result<
        Option<(
            iroha_sumeragi::availability::AvailableBody,
            iroha_sumeragi::message::Qc,
        )>,
        crate::execution_attempt::ExecutionAttemptError<io::Error>,
    > {
        self.blocks.committed_body(height)
    }
    fn entry(
        &self,
        height: u64,
    ) -> Result<
        Option<iroha_sumeragi::message::SyncEntry>,
        crate::execution_attempt::ExecutionAttemptError<io::Error>,
    > {
        self.blocks.entry(height)
    }
    fn availability_source(
        &self,
        height: u64,
        hash: Hash32,
    ) -> Result<
        Option<iroha_sumeragi::availability::AvailabilitySource>,
        crate::execution_attempt::ExecutionAttemptError<io::Error>,
    > {
        self.blocks.availability_source(height, hash)
    }
    fn append(
        &self,
        body: &iroha_sumeragi::availability::AvailableBody,
        qc: &iroha_sumeragi::message::Qc,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<io::Error>> {
        self.blocks.append(body, qc)
    }
}

#[test]
fn real_driver_binding_failure_preserves_original_error_or_panic_before_any_worker() {
    for panics in [false, true] {
        let Fixture {
            driver,
            start,
            owners,
        } = fixture(Arc::new(SystemClock::new()));
        drop(driver);
        let original = Arc::new(());
        let store = Arc::new(RefusingOriginalBinding {
            blocks: owners.blocks.clone(),
            budget: owners.budget.clone(),
            instance: start.init.instance,
            original: original.clone(),
            panic: panics,
            entered: std::sync::OnceLock::new(),
        });
        let observer: Arc<dyn Observer> = owners.observer.clone();
        let driver = Driver::new(
            owners.net.clone(),
            owners.records.clone(),
            owners.bodies.clone(),
            store.clone(),
            Arc::new(SystemClock::new()),
            owners.executor.clone(),
            observer,
        );
        let _probe = SpawnProbe::new(None);
        let result = catch_unwind(AssertUnwindSafe(|| {
            driver.spawn(DriverConfig::default(), start)
        }));
        let exact = match &result {
            Err(payload) if panics => payload
                .downcast_ref::<Arc<()>>()
                .is_some_and(|retained| Arc::ptr_eq(retained, &original)),
            Ok(Err(DriverError::RetirementBinding(error))) if !panics => error
                .get_ref()
                .and_then(|error| error.downcast_ref::<OriginalStartupBindingError>())
                .is_some_and(|retained| Arc::ptr_eq(&retained.0, &original)),
            _ => false,
        };
        assert!(
            store
                .entered
                .get()
                .is_some_and(|thread| *thread != std::thread::current().id())
        );
        drop((result, store));
        owners.assert_released();
        assert_eq!(
            SpawnProbe::attempts(),
            1,
            "binding readiness precedes every protocol worker"
        );
        assert!(owners.observer.stopped.lock().is_empty());
        assert_eq!(*owners.observer.finished.lock(), 0);
        assert_eq!(Arc::strong_count(&original), 1);
        assert!(
            exact,
            "ordinary startup must preserve the original joining-thread refusal or panic after physical cleanup"
        );
    }
}

#[test]
fn prepared_worker_refusal_and_unwind_join_all_before_payload_cleanup() {
    use crate::sumeragi::driver::worker_panic::tests::{
        PanicWorkers, join_barrier, with_before_join,
    };
    for already_unwinding in [false, true] {
        let Fixture {
            driver,
            start,
            owners,
        } = fixture(Arc::new(SystemClock::new()));
        let mut workers = PanicWorkers::new();
        let handles = std::mem::take(&mut workers.handles);
        let outer = Arc::new(());
        let outer_panic = outer.clone();
        let (hook, observed, release_hook) = join_barrier();
        let cleanup = std::thread::spawn(move || {
            let (start, retirement) =
                WorkerStart::new(driver, DriverConfig::default(), start).unwrap();
            assert!(retirement.is_none());
            let mut prepared = PreparedWorkers::new(
                DriverHandle {
                    shared: start.shared.clone(),
                    inputs: start.inputs.clone(),
                },
                None,
            );
            prepared.threads = handles;
            with_before_join(hook, || {
                if already_unwinding {
                    let _prepared = prepared;
                    std::panic::panic_any(outer_panic);
                } else {
                    let _ = prepared.finish_refusal(DriverError::StorageClosed);
                }
            });
        });
        let entered = observed.recv_timeout(std::time::Duration::from_secs(5));
        let early = workers.premature.load(std::sync::atomic::Ordering::SeqCst);
        let retained = workers.budget.reserved_bytes();
        workers.release();
        let _ = release_hook.send(());
        let joined = cleanup.join();
        let expected = if already_unwinding {
            &outer
        } else {
            &workers.original
        };
        let exact = joined
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<Arc<()>>())
            .is_some_and(|error| Arc::ptr_eq(error, expected));
        let exact_box = already_unwinding
            || joined.as_ref().err().is_some_and(|error| {
                std::ptr::from_ref(error.as_ref()).cast::<()>() as usize == workers.original_address
            });
        drop(joined);
        workers.assert_clean();
        owners.assert_released();
        assert_eq!(Arc::strong_count(&outer), 1);
        assert!(entered.is_ok() && exact && exact_box);
        assert!(
            !early && retained == 1,
            "prepared worker cleanup must finish all physical joins before panic-payload destruction"
        );
    }
}

#[test]
fn original_joiner_and_terminal_driver_drop_contain_payload_panic_during_unwind() {
    struct Payload {
        charge: Option<iroha_allocation::AllocationReservation>,
        drops: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl Drop for Payload {
        fn drop(&mut self) {
            self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(self.charge.take());
            std::panic::panic_any(self.drops.clone());
        }
    }
    for original_joiner in [true, false] {
        let budget = AllocationBudget::new(1);
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let payload = Payload {
            charge: Some(budget.try_reserve_bytes(1).unwrap()),
            drops: drops.clone(),
        };
        let outer = Arc::new(());
        let backends = std::cell::OnceCell::new();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            if original_joiner {
                let _owner = OriginalJoiner(Some(
                    DriverJoiner::start_with(move |_| {
                        std::panic::panic_any(payload);
                    })
                    .unwrap(),
                ));
                std::panic::panic_any(outer.clone());
            } else {
                let Fixture {
                    driver,
                    start,
                    owners,
                } = fixture(Arc::new(SystemClock::new()));
                assert!(backends.set(owners).is_ok());
                let mut owner = driver.spawn(DriverConfig::default(), start).unwrap();
                owner.join_failure = Some(OriginalWorkerPanic::new(Box::new(payload)));
                let _owner = owner;
                std::panic::panic_any(outer.clone());
            }
        }));
        let exact = outcome
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<Arc<()>>())
            .is_some_and(|error| Arc::ptr_eq(error, &outer));
        drop(outcome);
        assert_eq!(backends.get().is_some(), !original_joiner);
        if let Some(owners) = backends.into_inner() {
            owners.assert_released();
        }
        assert!(exact);
        assert_eq!(Arc::strong_count(&outer), 1);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            Arc::strong_count(&drops),
            1,
            "replacement payload was consumed after finite destructor panic"
        );
    }
}
