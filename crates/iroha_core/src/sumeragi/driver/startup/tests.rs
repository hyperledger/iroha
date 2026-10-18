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
    struct PanicClock;
    impl Clock for PanicClock {
        fn now(&self) -> iroha_sumeragi::types::Millis {
            panic!("original startup clock callback unwinds")
        }
    }
    let Fixture {
        driver,
        start,
        owners,
    } = fixture(Arc::new(PanicClock));
    let _probe = SpawnProbe::new(None);
    let error = refusal(driver.spawn(DriverConfig::default(), start));
    owners.assert_released();
    assert!(matches!(
        error,
        DriverError::Config(ConfigError::InvalidInit("event loop died"))
    ));
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
