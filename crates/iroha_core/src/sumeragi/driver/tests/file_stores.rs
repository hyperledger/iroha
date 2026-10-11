//! The full driver over the production file stores (`sumeragi::records`, `sumeragi::bodies`)
//! with injected disk errors: `ENOSPC` and `EIO` at record, store-id and body write steps are
//! retried by the persistence worker (never skipped), a single validator keeps committing, and
//! what is on disk afterwards is the latest record and only unapplied bodies.

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use iroha_sumeragi::{
    api::LocalParams,
    crypto::Signer,
    safety::{RecordState, SafetyRecord},
    testing::{FakeCrypto, FakeSigner},
    types::{ChainParams, Committee, Hash32, HeightConfig},
};

use super::{
    super::{
        Driver, DriverConfig, DriverStart, NodeGate, SharedCrypto, assemble_init,
        traits::{BlockStore, Observer, RecordStore, SystemClock},
    },
    fakes::{FakeBlocks, FakeExecutor, FakeNet, RecordingObserver},
};
use crate::sumeragi::{
    bodies::{BodyLimits, FileBodyStore},
    records::{FileRecordStore, FreshKeyAssertion, FsStep, install},
};

/// Fails every `every`-th write step (alternating `ENOSPC` and `EIO`) until `budget` failures
/// were injected.
struct Flaky {
    every: usize,
    budget: AtomicUsize,
    steps: AtomicUsize,
    injected: AtomicUsize,
}

impl Flaky {
    fn new(every: usize, budget: usize) -> Arc<Self> {
        Arc::new(Self {
            every,
            budget: AtomicUsize::new(budget),
            steps: AtomicUsize::new(0),
            injected: AtomicUsize::new(0),
        })
    }
}

impl crate::sumeragi::records::Faults for Flaky {
    fn before(&self, step: FsStep, _path: &Path) -> std::io::Result<()> {
        let n = self.steps.fetch_add(1, Ordering::SeqCst);
        let write = matches!(
            step,
            FsStep::CreateTemp | FsStep::WriteTempRest | FsStep::SyncFile | FsStep::Rename
        );
        if write
            && n % self.every == 0
            && self
                .budget
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |b| b.checked_sub(1))
                .is_ok()
        {
            let k = self.injected.fetch_add(1, Ordering::SeqCst);
            return Err(std::io::Error::from_raw_os_error(if k % 2 == 0 {
                28
            } else {
                5
            }));
        }
        Ok(())
    }
}

fn wait_until(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < limit, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A single validator on the file stores commits through injected `ENOSPC`/`EIO`; the
/// persistence worker retries every failed write; the record on disk is the latest one and
/// applied bodies are pruned.
#[test]
fn file_stores_survive_disk_errors() {
    let dir = tempfile::tempdir().unwrap();
    let crypto: SharedCrypto = Arc::new(FakeCrypto::new());
    let signer = FakeSigner::from_seed(&[42], None);
    let key = signer.public_key().clone();
    let instance = Hash32([42; 32]);
    let record_faults = Flaky::new(3, 12);
    let body_faults = Flaky::new(4, 12);
    let records = Arc::new(
        FileRecordStore::open_with_faults(
            dir.path().join("records"),
            dir.path().join("keys").join("installation.log"),
            record_faults.clone(),
        )
        .unwrap(),
    );
    // A fresh network: the key was generated off-node, so the operator asserts it.
    let assertion = FreshKeyAssertion::from_operator_flag(true);
    let found = loop {
        // Installation itself retries through the injected errors (the node would retry
        // its start).
        match install(
            &*records,
            &*crypto,
            &instance,
            iroha_sumeragi::testing::TEST_EPOCH.id,
            &[(key.clone(), false)],
            0,
            assertion.as_ref(),
        ) {
            Ok(found) => break found,
            Err(error) => assert!(matches!(error.raw_os_error(), Some(28 | 5))),
        }
    };
    assert!(matches!(found[0].1, RecordState::Present(_)));
    let bodies = Arc::new(
        FileBodyStore::open_with_faults(
            dir.path(),
            &instance,
            Arc::clone(&crypto),
            BodyLimits::default(),
            super::test_budget(),
            body_faults.clone(),
        )
        .unwrap(),
    );
    let config = HeightConfig {
        epoch: Box::new(iroha_sumeragi::testing::TEST_EPOCH),
        committee: Committee::new(vec![key.clone()]).unwrap(),
        params: ChainParams {
            block_time: 10,
            payload_retry_interval: 30,
            ..ChainParams::default()
        },
    };
    let blocks = Arc::new(FakeBlocks::default());
    let genesis = (Hash32([1; 32]), Hash32([2; 32]));
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
        7,
    )
    .unwrap();
    let exec = FakeExecutor::new(genesis.0, genesis.1, config);
    let observer: Arc<dyn Observer> = Arc::new(RecordingObserver::default());
    let running = Driver::new(
        Arc::new(FakeNet::default()),
        Arc::clone(&records),
        Arc::clone(&bodies),
        Arc::clone(&blocks),
        Arc::new(SystemClock::new()),
        exec.clone(),
        observer,
    )
    .spawn(
        DriverConfig::default(),
        DriverStart {
            node_gate: Arc::new(NodeGate::new()),
            allocation_budget: super::test_budget(),
            local: LocalParams::default(),
            init,
            signers: vec![Arc::new(signer)],
            crypto: Arc::clone(&crypto),
        },
    )
    .unwrap();
    for id in 0..10 {
        exec.add_tx(id);
    }
    running.handle().transactions_available();
    // Blocks are work-driven (§6.10): keep work queued so heights keep coming.
    let work = exec.pump(running.handle());
    let committed = || {
        running
            .handle()
            .status()
            .map_or(0, |status| status.committed_height)
    };
    wait_until("15 heights", Duration::from_secs(30), || committed() >= 15);
    assert!(running.handle().halted().is_none());
    drop(work);
    running.shutdown();
    assert!(
        record_faults.injected.load(Ordering::SeqCst) >= 6,
        "record writes failed and were retried"
    );
    assert!(
        body_faults.injected.load(Ordering::SeqCst) >= 3,
        "body writes failed and were retried"
    );
    // The record on disk is whole and at least at the applied height (every apply waited for
    // the record of its height to be durable, O2).
    let applied = blocks.height();
    assert!(applied >= 13, "applied {applied}");
    let RecordState::Present(bytes) = records.load(&instance, &key).unwrap() else {
        panic!("the record is on disk");
    };
    let record = SafetyRecord::decode(&*crypto, &bytes).unwrap();
    assert!(
        record.height >= applied,
        "record at {} with {applied} applied",
        record.height
    );
    // Bodies at applied heights were pruned (the last prunes may still have been queued).
    let held = bodies.heights().unwrap();
    assert!(
        held.len() <= 4 && held.iter().all(|h| h + 3 > applied),
        "bodies {held:?} with {applied} applied"
    );
    for height in 1..applied.saturating_sub(3) {
        use crate::sumeragi::durable_artifact::{BodyReadPoll, BodyReader};
        let entry = blocks.entry(height).unwrap().unwrap();
        let source = blocks
            .availability_source(height, entry.commit_qc.block_hash)
            .unwrap()
            .unwrap();
        let mut read = bodies.begin_read(source).unwrap();
        assert!(matches!(
            read.poll(&super::test_budget()).unwrap(),
            BodyReadPoll::Absent
        ));
    }
}
