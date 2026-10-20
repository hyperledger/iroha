//! Genuine proof publication and fresh verification after missing-source replay.
use super::*;
use crate::sumeragi::{
    certified_chain::CertifiedChain, node::NativeReplaySeed, test_chain::CertifiedTestChain,
};
use iroha_crypto::Hash;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::atomic::AtomicUsize,
    time::Duration,
};

// The real prover is synchronous and bounded by structural work policy, not
// wall time. Observe its intervals separately from finite worker liveness.
#[derive(Default)]
struct ProofActivity {
    started: Option<Instant>,
    completed: Duration,
}
impl ProofActivity {
    fn begin(&mut self, now: Instant) {
        assert!(
            self.started.is_none(),
            "one original worker proof at a time"
        );
        self.started = Some(now);
    }

    fn finish(&mut self, now: Instant, produced: bool) {
        let started = self.started.take().expect("original proving interval");
        if produced {
            self.completed += now.saturating_duration_since(started);
        }
    }

    fn elapsed(&self, now: Instant) -> Duration {
        self.completed
            + self.started.map_or(Duration::ZERO, |started| {
                now.saturating_duration_since(started)
            })
    }
}

struct ProofActivityGuard<'a> {
    activity: &'a parking_lot::Mutex<ProofActivity>,
    active: bool,
}
impl<'a> ProofActivityGuard<'a> {
    fn begin(activity: &'a parking_lot::Mutex<ProofActivity>) -> Self {
        activity.lock().begin(Instant::now());
        Self {
            activity,
            active: true,
        }
    }

    fn finish(mut self, produced: bool) {
        self.activity.lock().finish(Instant::now(), produced);
        self.active = false;
    }
}
impl Drop for ProofActivityGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            // A panic grants no successful proving interval or fresh idle budget.
            self.activity.lock().finish(Instant::now(), false);
        }
    }
}

#[test]
fn proof_activity_excludes_only_nonoverlapping_real_proving_intervals() {
    let start = Instant::now();
    let at = |seconds| start + Duration::from_secs(seconds);
    let mut activity = ProofActivity::default();
    activity.begin(at(5));
    assert_eq!(activity.elapsed(at(50)), Duration::from_secs(45));
    activity.finish(at(100), true);
    assert_eq!(activity.elapsed(at(200)), Duration::from_secs(95));

    let phase_start = at(200);
    let baseline = activity.elapsed(phase_start);
    activity.begin(at(250));
    let proving = activity.elapsed(at(300)).saturating_sub(baseline);
    assert_eq!(at(300) - phase_start - proving, Duration::from_secs(50));
    activity.finish(at(310), true);
    let proving = activity.elapsed(at(350)).saturating_sub(baseline);
    assert_eq!(at(350) - phase_start - proving, Duration::from_secs(90));

    // Busy, errors and skipped outputs restore all wall time to the idle allowance.
    activity.begin(at(350));
    activity.finish(at(360), false);
    let proving = activity.elapsed(at(380)).saturating_sub(baseline);
    assert_eq!(at(380) - phase_start - proving, Duration::from_secs(120));
    activity.begin(at(380));
    activity.finish(at(390), false);
    let proving = activity.elapsed(at(390)).saturating_sub(baseline);
    assert_eq!(at(390) - phase_start - proving, Duration::from_secs(130));
    activity.begin(at(390));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            activity.begin(at(391));
        }))
        .is_err()
    );
    assert_eq!(activity.started, Some(at(390)));
    activity.finish(at(400), false);
}

/// Observation delegates every input and output to the actual production engine.
/// It cannot fabricate a receipt or make an unavailable artifact look complete.
struct ObservedRealEngine {
    inner: RealProofEngine,
    calls: Arc<AtomicUsize>,
    produced: Arc<AtomicUsize>,
    activity: Arc<parking_lot::Mutex<ProofActivity>>,
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
        let activity = ProofActivityGuard::begin(&self.activity);
        let result = self.inner.prove(statement, expected, budget, reservation);
        // Only a produced real proof excludes its synchronous work interval.
        // Busy, errors, skipped outputs and panics retain their full idle cost.
        activity.finish(matches!(&result, Ok(FastpqProofOutput::Produced(_))));
        let output = result?;
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
#[inline(never)]
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
#[inline(never)]
async fn tick(mut producer: Box<Producer>, engine: Arc<dyn FastpqProofEngine>) -> Box<Producer> {
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

// Only fixture construction uses its existing larger stack. Every census,
// replay, proof and recovery phase runs on the ordinary test or worker stacks.
#[inline(never)]
fn original_fixture() -> (Box<CertifiedTestChain>, Vec<NativeReplaySeed>) {
    std::thread::Builder::new()
        .name("missing-fastpq-proof-fixture".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let (chain, seeds, _) =
                crate::sumeragi::node::isolated_replay_source_fixture_for_test(3);
            (Box::new(chain), seeds)
        })
        .unwrap()
        .join()
        .unwrap_or_else(|failure| std::panic::resume_unwind(failure))
}

#[inline(never)]
fn remove_original_tapes(chain: &CertifiedTestChain) -> BTreeMap<PathBuf, Vec<u8>> {
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
    original_files
}

// Own the same producer on the heap so phase futures transport its pointer,
// rather than retaining copies of its large State/replay machine on the stack.
#[inline(never)]
fn fresh_producer(
    chain: &CertifiedTestChain,
    policy: FastpqProducer,
    seed: Option<NativeReplaySeed>,
) -> Box<Producer> {
    Box::new(Producer::new(Arc::clone(chain.state()), policy, seed))
}

#[inline(never)]
fn start_idle_worker(
    producer: WorkerProducer,
    engine: Arc<dyn FastpqProofEngine>,
) -> (
    tokio::sync::mpsc::Sender<WorkRequest>,
    ShutdownSignal,
    tokio::task::JoinHandle<()>,
) {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let shutdown = ShutdownSignal::new();
    let task = spawn_worker(
        receiver,
        Arc::new(AtomicBool::new(false)),
        Some(producer),
        Arc::new(FastpqLaneGenerationLease { generation: 1 }),
        shutdown.clone(),
        None,
        move || Some(engine),
    );
    (sender, shutdown, task)
}

#[inline(never)]
async fn discard_unpublished_proof(
    chain: &CertifiedTestChain,
    seed: Option<NativeReplaySeed>,
    policy: FastpqProducer,
    positions: &BTreeMap<Hash, (u64, usize)>,
    original_files: &BTreeMap<PathBuf, Vec<u8>>,
    engine: Arc<dyn FastpqProofEngine>,
    produced: &AtomicUsize,
) -> Hash {
    // Crash boundary before immutable publication: drop the genuine output and
    // its in-memory source. Presence of that output must not advance disk progress.
    let mut first = fresh_producer(chain, policy, seed);
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
    assert_eq!(&files(&chain.kura().store_root()), original_files);
    drop(first);
    assert_eq!(produced.load(Ordering::SeqCst), 1);

    first_key
}

#[inline(never)]
async fn publish_on_idle_worker(
    chain: &CertifiedTestChain,
    seed: Option<NativeReplaySeed>,
    policy: FastpqProducer,
    positions: &BTreeMap<Hash, (u64, usize)>,
    original_files: &BTreeMap<PathBuf, Vec<u8>>,
    engine: Arc<dyn FastpqProofEngine>,
    produced: &AtomicUsize,
    activity: &parking_lot::Mutex<ProofActivity>,
) -> BTreeMap<PathBuf, Vec<u8>> {
    // Restart uses only its own original startup seed, signed history and existing
    // timer/queue service. The sender stays open but never receives one work item.
    let producer = WorkerProducer::new(Arc::clone(chain.state()), policy, seed);
    let started = Instant::now();
    let proof_baseline = activity.lock().elapsed(started);
    let (_sender, shutdown, task) = start_idle_worker(producer, engine);
    // Keep the existing 120-second finite allowance for idle wakes, replay and
    // publication. Real synchronous proving may exceed that wall time in debug
    // builds; it retains the original default structural work and memory policy.
    let observed = async {
        loop {
            let mut complete = true;
            for key in positions.keys() {
                complete &= chain.kura().read_fastpq_producer_record(*key)?.is_some();
            }
            if complete {
                return Ok::<bool, crate::kura::Error>(true);
            }
            let idle = {
                let activity = activity.lock();
                let now = Instant::now();
                let proving = activity.elapsed(now).saturating_sub(proof_baseline);
                now.duration_since(started).saturating_sub(proving)
            };
            if idle >= Duration::from_secs(120) {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    .await;
    shutdown.send();
    task.await.unwrap(); // wait for the original durability barrier to retire naturally
    assert!(
        matches!(observed, Ok(true)),
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
        &without_artifacts, original_files,
        "no native tape, block or other live custody was rewritten"
    );

    published
}

#[inline(never)]
fn reject_foreign_artifact(
    chain: &CertifiedTestChain,
    restarted: &mut Producer,
    first_key: Hash,
    key: Hash,
) {
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
}

#[inline(never)]
async fn verify_after_restart(
    chain: &CertifiedTestChain,
    seed: Option<NativeReplaySeed>,
    policy: FastpqProducer,
    positions: &BTreeMap<Hash, (u64, usize)>,
    first_key: Hash,
    engine: Arc<dyn FastpqProofEngine>,
    calls: &AtomicUsize,
) {
    // Restart after publication. The production cursor must rederive source
    // expectations from fresh isolated replay and actually verify every exact
    // artifact. The observed real engine must receive no new proving call.
    let calls_before_recovery = calls.load(Ordering::SeqCst);
    let mut recovered_positions = BTreeSet::new();
    let mut foreign_source_rejected = false;
    let mut restarted = fresh_producer(chain, policy, seed);
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
            reject_foreign_artifact(chain, &mut restarted, first_key, key);
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
    drop(restarted);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_nonempty_h1_h2_complete_real_proofs_and_recover_after_restart_without_traffic() {
    // The original nonblocking prover lock is process-wide. Give this real-proof
    // lifecycle its own globals so sibling proofs cannot exhaust its finite turns.
    if crate::unit_test_support::run_in_isolated_harness(
        "fastpq::lane::producer::proof_completion_tests::missing_nonempty_h1_h2_complete_real_proofs_and_recover_after_restart_without_traffic",
    ) {
        return;
    }
    let _status = crate::status::operator_status_test_guard();
    let (chain, mut seeds) = original_fixture();
    let positions = original_positions(&chain);
    let original_files = remove_original_tapes(&chain);
    let original_root = chain.state().verify_world_state_accumulator().unwrap();
    let original_pool_limit = chain.state().ivm_execution_budget().limit_bytes();
    let original_status = crate::status::lane_scoped_status_fingerprint_for_tests();
    let original_settlements = format!("{:?}", crate::status::settlement_snapshot());
    let calls = Arc::new(AtomicUsize::new(0));
    let produced = Arc::new(AtomicUsize::new(0));
    let activity = Arc::new(parking_lot::Mutex::new(ProofActivity::default()));
    let engine: Arc<dyn FastpqProofEngine> = Arc::new(ObservedRealEngine {
        inner: RealProofEngine {
            proving: ProvingLimits::default(),
            verification: ExecutionEffectVerificationLimits::default(),
        },
        calls: Arc::clone(&calls),
        produced: Arc::clone(&produced),
        activity: Arc::clone(&activity),
    });
    let policy = FastpqProducer {
        poll_interval: Duration::from_millis(1),
        ..FastpqProducer::default()
    };

    let first_key = Box::pin(discard_unpublished_proof(
        &chain,
        seeds.pop(),
        policy,
        &positions,
        &original_files,
        Arc::clone(&engine),
        &produced,
    ))
    .await;
    let published = Box::pin(publish_on_idle_worker(
        &chain,
        seeds.pop(),
        policy,
        &positions,
        &original_files,
        Arc::clone(&engine),
        &produced,
        &activity,
    ))
    .await;
    Box::pin(verify_after_restart(
        &chain,
        seeds.pop(),
        policy,
        &positions,
        first_key,
        engine,
        &calls,
    ))
    .await;
    assert!(seeds.is_empty());
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
