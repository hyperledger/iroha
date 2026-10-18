//! Genuine proof publication and fresh verification after missing-source replay.
use super::*;
use crate::sumeragi::{certified_chain::CertifiedChain, test_chain::CertifiedTestChain};
use iroha_crypto::Hash;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::atomic::AtomicUsize,
    time::Duration,
};

/// Observation delegates every input and output to the actual production engine.
/// It cannot fabricate a receipt or make an unavailable artifact look complete.
struct ObservedRealEngine {
    inner: RealProofEngine,
    calls: Arc<AtomicUsize>,
    produced: Arc<AtomicUsize>,
}
impl FastpqProofEngine for ObservedRealEngine {
    fn limits(&self) -> (ProvingLimits, ExecutionEffectVerificationLimits) {
        self.inner.limits()
    }
    fn prove(
        &self,
        statement: &SourceExecutionEffectStatement<'_>,
        expected: ExpectedExecutionEffects<'_>,
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<FastpqProofOutput, ProvingError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let output = self.inner.prove(statement, expected, budget, reservation)?;
        assert!(matches!(&output, FastpqProofOutput::Produced(_)));
        self.produced.fetch_add(1, Ordering::SeqCst);
        Ok(output)
    }
}

fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                visit(root, &entry.path(), output);
            } else {
                assert!(kind.is_file(), "fixture custody contains no symlinks");
                output.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    output
}

// This census records only immutable statement-position identities. Both later
// producer generations must authenticate their source again after the tapes vanish.
fn original_positions(chain: &CertifiedTestChain) -> BTreeMap<Hash, (u64, usize)> {
    let mut positions = BTreeMap::new();
    for height in [1, 2] {
        let native = CertifiedChain::new(&chain.state().view())
            .unwrap()
            .authenticated_execution(height)
            .unwrap();
        let mut read = NativeFastpqSourceRead::new(
            chain.kura().clone(),
            native,
            chain.state().ivm_execution_budget(),
            SourceReadLimits {
                max_entries: 64,
                max_statements: 64,
                max_effects_per_statement: 128,
            },
        );
        let mut job = (0..256)
            .find_map(|_| read.poll().unwrap())
            .map(FastpqWitnessJob::from_recovered)
            .expect("finite original source read");
        assert!(
            !job.source.leaves().is_empty(),
            "H{height} must be nonempty"
        );
        for index in 0..job.source.leaves().len() {
            job.next_statement = index;
            let key = durable::position_for_test(&job).unwrap();
            assert!(positions.insert(key, (height, index)).is_none());
        }
    }
    positions
}

// This is the same default blocking runtime used by the existing worker. Fixture
// construction's pre-existing larger stack does not wrap replay or proof work.
async fn tick(mut producer: Producer, engine: Arc<dyn FastpqProofEngine>) -> Producer {
    tokio::task::spawn_blocking(move || {
        producer.attempt(&engine, 0, &ShutdownSignal::new(), None);
        assert!(
            !producer.stopped,
            "original terminal failure: {:?}",
            producer.cause
        );
        producer
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_nonempty_h1_h2_complete_real_proofs_and_recover_after_restart_without_traffic() {
    let _status = crate::status::operator_status_test_guard();
    let (chain, mut seeds, _) = std::thread::Builder::new()
        .name("missing-fastpq-proof-fixture".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| crate::sumeragi::node::isolated_replay_source_fixture_for_test(3))
        .unwrap()
        .join()
        .unwrap_or_else(|failure| std::panic::resume_unwind(failure));
    let positions = original_positions(&chain);
    let source_root = chain
        .kura()
        .store_root()
        .join(Kura::fastpq_source_namespace());
    let mut removed = 0;
    for entry in std::fs::read_dir(&source_root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|extension| extension == "fqs") {
            std::fs::remove_file(path).unwrap();
            removed += 1;
        }
    }
    assert!(
        removed >= 2,
        "both actual nonempty source tapes were retained"
    );
    let original_files = files(&chain.kura().store_root());
    assert!(
        original_files
            .keys()
            .all(|path| !path.extension().is_some_and(|ext| ext == "producer"))
    );
    let original_root = chain.state().verify_world_state_accumulator().unwrap();
    let original_pool_limit = chain.state().ivm_execution_budget().limit_bytes();
    let original_status = crate::status::lane_scoped_status_fingerprint_for_tests();
    let original_settlements = format!("{:?}", crate::status::settlement_snapshot());
    let calls = Arc::new(AtomicUsize::new(0));
    let produced = Arc::new(AtomicUsize::new(0));
    let engine: Arc<dyn FastpqProofEngine> = Arc::new(ObservedRealEngine {
        inner: RealProofEngine {
            proving: ProvingLimits::default(),
            verification: ExecutionEffectVerificationLimits::default(),
        },
        calls: Arc::clone(&calls),
        produced: Arc::clone(&produced),
    });
    let policy = FastpqProducer {
        poll_interval: Duration::from_millis(1),
        ..FastpqProducer::default()
    };

    // Crash boundary before immutable publication: drop the genuine output and
    // its in-memory source. Presence of that output must not advance disk progress.
    let mut first = Producer::new(Arc::clone(chain.state()), policy, seeds.pop());
    for _ in 0..256 {
        first = tick(first, Arc::clone(&engine)).await;
        if first.completed.is_some() {
            break;
        }
    }
    let unpublished = first
        .completed
        .as_ref()
        .expect("genuine H1 artifact completed");
    assert_eq!(unpublished.job.height(), 1);
    let receipt = unpublished
        .verified()
        .expect("actual mandatory proof verifier succeeded");
    assert_eq!(
        receipt.identity().artifact_bytes,
        unpublished.bytes().len() as u64
    );
    assert_eq!(
        receipt.identity().artifact_digest,
        *Hash::new(unpublished.bytes()).as_ref()
    );
    let first_key = durable::position_for_test(&unpublished.job).unwrap();
    assert_eq!(positions.get(&first_key), Some(&(1, 0)));
    assert!(
        chain
            .kura()
            .read_fastpq_producer_record(first_key)
            .unwrap()
            .is_none()
    );
    assert_eq!(files(&chain.kura().store_root()), original_files);
    drop(first);
    assert_eq!(produced.load(Ordering::SeqCst), 1);

    // Restart uses only its own original startup seed, signed history and existing
    // timer/queue service. The sender stays open but never receives one work item.
    let producer = Producer::new(Arc::clone(chain.state()), policy, seeds.pop());
    let (_sender, receiver) = tokio::sync::mpsc::channel(1);
    let shutdown = ShutdownSignal::new();
    let worker_engine = Arc::clone(&engine);
    let task = spawn_worker(
        receiver,
        Arc::new(AtomicBool::new(false)),
        Some(producer),
        Arc::new(FastpqLaneGenerationLease { generation: 1 }),
        shutdown.clone(),
        None,
        move || Some(worker_engine),
    );
    // Preserve the existing missing-tape worker test's bound; no daemon/protocol
    // timeout, thread stack, pool ceiling or proof policy is enlarged for this test.
    let observed = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let mut complete = true;
            for key in positions.keys() {
                complete &= chain.kura().read_fastpq_producer_record(*key)?.is_some();
            }
            if complete {
                return Ok::<(), crate::kura::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    shutdown.send();
    task.await.unwrap(); // wait for the original durability barrier to retire naturally
    assert!(
        matches!(observed, Ok(Ok(()))),
        "actual H1 and H2 artifacts must complete on the idle worker: {observed:?}"
    );
    assert_eq!(produced.load(Ordering::SeqCst), 1 + positions.len());
    let published = files(&chain.kura().store_root());
    assert_eq!(
        published
            .keys()
            .filter(|path| path.extension().is_some_and(|ext| ext == "producer"))
            .count(),
        positions.len(),
        "exactly one immutable record per authenticated statement position"
    );
    let without_artifacts: BTreeMap<_, _> = published
        .iter()
        .filter(|(path, _)| !path.extension().is_some_and(|ext| ext == "producer"))
        .map(|(path, bytes)| (path.clone(), bytes.clone()))
        .collect();
    assert_eq!(
        without_artifacts, original_files,
        "no native tape, block or other live custody was rewritten"
    );

    // Restart after publication. The production cursor must rederive source
    // expectations from fresh isolated replay and actually verify every exact
    // artifact. The observed real engine must receive no new proving call.
    let calls_before_recovery = calls.load(Ordering::SeqCst);
    let mut recovered_positions = BTreeSet::new();
    let mut foreign_source_rejected = false;
    let mut restarted = Producer::new(Arc::clone(chain.state()), policy, seeds.pop());
    for _ in 0..256 {
        let before = restarted.job.as_ref().and_then(|job| {
            (job.next_statement < job.source.leaves().len()).then(|| {
                (
                    durable::position_for_test(job).unwrap(),
                    job.height(),
                    job.next_statement,
                )
            })
        });
        if let Some((key, 2, 0)) = before {
            // The bytes are a genuine completed H1 proof. Offering them at an
            // independently reconstructed H2 position must fail before the cursor
            // advances. This separate untrusted store never alters live custody.
            let foreign = Kura::blank_with_fastpq_artifact_policy_for_testing(
                iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
            );
            let h1_bytes = chain
                .kura()
                .read_fastpq_producer_record(first_key)
                .unwrap()
                .unwrap();
            let receipt = foreign
                .persist_fastpq_producer_record(key, &h1_bytes)
                .unwrap();
            assert!(receipt.is_from(&foreign));
            assert!(!receipt.is_from(chain.kura()));
            assert_eq!(receipt.reference().digest(), *Hash::new(&h1_bytes).as_ref());
            assert_eq!(receipt.reference().byte_len(), h1_bytes.len() as u64);
            let job = restarted.job.as_mut().unwrap();
            let original = std::ptr::from_ref(job.source.entry(0).unwrap().effects());
            assert!(matches!(
                job.recover_next(
                    &foreign,
                    ProvingLimits::default(),
                    &ExecutionEffectVerificationLimits::default(),
                ),
                Err(durable::DurableError::Verification(_))
            ));
            assert_eq!(job.next_statement, 0);
            assert_eq!(
                std::ptr::from_ref(job.source.entry(0).unwrap().effects()),
                original
            );
            assert!(!foreign_source_rejected);
            foreign_source_rejected = true;
        }
        restarted = tick(restarted, Arc::clone(&engine)).await;
        if let Some((key, height, index)) = before {
            let job = restarted
                .job
                .as_ref()
                .expect("verified disk recovery retains the source");
            assert_eq!(job.height(), height);
            assert_eq!(
                job.next_statement,
                index + 1,
                "only actual fresh proof verification may advance"
            );
            assert_eq!(positions.get(&key), Some(&(height, index)));
            assert!(recovered_positions.insert(key));
        }
        assert_eq!(calls.load(Ordering::SeqCst), calls_before_recovery);
        assert!(
            restarted.completed.is_none(),
            "restart must recover the exact durable artifacts"
        );
        if restarted.height == 3 {
            break;
        }
    }
    assert_eq!(
        restarted.height, 3,
        "both nonempty sources completely verified"
    );
    assert_eq!(
        recovered_positions,
        positions.keys().copied().collect::<BTreeSet<_>>()
    );
    assert!(foreign_source_rejected);
    assert!(seeds.is_empty());
    drop(restarted);
    assert_eq!(
        files(&chain.kura().store_root()),
        published,
        "verification adds or rewrites no record"
    );
    assert_eq!(
        chain.state().committed_height(),
        2,
        "no H3 or unrelated ledger traffic"
    );
    assert_eq!(
        chain.state().verify_world_state_accumulator().unwrap(),
        original_root
    );
    assert_eq!(
        chain.state().ivm_execution_budget().limit_bytes(),
        original_pool_limit
    );
    assert_eq!(
        crate::status::lane_scoped_status_fingerprint_for_tests(),
        original_status
    );
    assert_eq!(
        format!("{:?}", crate::status::settlement_snapshot()),
        original_settlements
    );
}
