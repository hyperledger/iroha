//! Genuine native Load resource diagnostic at public API boundaries.
//! No measurement influences production admission. Setup contributes to absolute
//! process-lifetime RSS, and accepted-owner memos may already be warm at sample 0.

use std::{
    fs::File,
    io::Read as _,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use ff::PrimeField as _;
use group::GroupEncoding as _;
use iroha_measurement::probe::{ProbeError, ProcessSnapshot};
use iroha_pasta::{
    Eq, PastaCurve,
    msm::{MemoryBudget, PROCESS_MSM_SCRATCH_BYTES, SharedMemoryBudget},
};
use iroha_plonk::ProverConfig;
use iroha_plonk_recursion::{FoldConfig, FoldInput};
use norito::json::Value;
use sha2::{Digest as _, Sha256};

use super::{LoadFixture, Original, Prover, bootstrap_outer, common};

/// Reject implicit/default worker counts in this diagnostic.
pub(crate) fn parse_workers(value: Option<&str>) -> Result<usize, &'static str> {
    match value {
        Some("1") => Ok(1),
        Some("4") => Ok(4),
        _ => Err("RAYON_NUM_THREADS must be explicitly 1 or 4"),
    }
}

/// Check the actual pool and every worker, independently of the environment.
pub(crate) fn worker_census(pool: &rayon::ThreadPool, requested: usize) -> Vec<usize> {
    assert_eq!(pool.install(rayon::current_num_threads), requested);
    let mut indices = pool.broadcast(|context| context.index());
    indices.sort_unstable();
    assert_eq!(indices, (0..requested).collect::<Vec<_>>());
    indices
}

/// A rejected required probe or impossible resource sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObservationError {
    /// Original required probe failure, retained without conversion to zero.
    Probe(ProbeError),
    /// The kernel lifetime high-water mark cannot decrease.
    RssWentBackwards,
}

/// One closed phase; RSS remains absolute rather than a meaningless difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Metrics {
    /// Required start observation.
    pub before: ProcessSnapshot,
    /// Required end observation.
    pub after: ProcessSnapshot,
    /// Process CPU including every worker.
    pub cpu_ns: u64,
    /// Observed wall time without load normalization.
    pub elapsed_ns: u64,
}

/// Validate independently captured boundary observations.
pub(crate) fn metrics(
    before: Result<ProcessSnapshot, ProbeError>,
    after: Result<ProcessSnapshot, ProbeError>,
    elapsed_ns: u64,
) -> Result<Metrics, ObservationError> {
    let before = before.map_err(ObservationError::Probe)?;
    let after = after.map_err(ObservationError::Probe)?;
    if before.peak_rss_bytes == 0 || after.peak_rss_bytes == 0 {
        return Err(ObservationError::Probe(ProbeError::PeakRssUnavailable));
    }
    let cpu_ns = after.cpu_since(before).map_err(ObservationError::Probe)?;
    if after.peak_rss_bytes < before.peak_rss_bytes {
        return Err(ObservationError::RssWentBackwards);
    }
    Ok(Metrics {
        before,
        after,
        cpu_ns,
        elapsed_ns,
    })
}

fn snapshot_json(value: ProcessSnapshot) -> Value {
    norito::json!({
        "cpu_ns": (value.cpu_ns), "kernel_lifetime_peak_rss_bytes": (value.peak_rss_bytes),
        "load_milli": (value.load_milli), "thermal": (value.thermal.as_str()),
    })
}

fn scratch_json(budget: &SharedMemoryBudget) -> Value {
    assert_eq!(budget.limit_bytes(), PROCESS_MSM_SCRATCH_BYTES);
    assert!(budget.peak_bytes() <= budget.limit_bytes());
    norito::json!({
        "limit_bytes": (budget.limit_bytes()), "cumulative_peak_bytes": (budget.peak_bytes()),
        "in_use_bytes": (budget.in_use_bytes()),
    })
}

struct PhaseFailure(&'static str, Option<usize>);
impl Drop for PhaseFailure {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "NATIVE_LOAD_RESOURCE_INVALID phase={} sample={:?}",
                self.0, self.1
            );
        }
    }
}

fn observe<T>(
    phases: &mut Vec<Value>,
    label: &'static str,
    sample: Option<usize>,
    action: impl FnOnce() -> T,
) -> (T, Metrics) {
    let _failure = PhaseFailure(label, sample);
    eprintln!("NATIVE_LOAD_RESOURCE_BEGIN phase={label} sample={sample:?}");
    let scratch = SharedMemoryBudget::process_default();
    let scratch_before = scratch_json(&scratch);
    let before = ProcessSnapshot::capture().expect("required pre-phase process probes");
    let started = Instant::now();
    let result = action();
    let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).expect("phase duration fits u64");
    let after = ProcessSnapshot::capture();
    let observed = metrics(Ok(before), after, elapsed_ns).expect("valid process observations");
    let phase = norito::json!({
        "phase": label, "sample": sample, "before": (snapshot_json(before)),
        "after": (snapshot_json(observed.after)), "cpu_ns": (observed.cpu_ns),
        "elapsed_ns": elapsed_ns, "scratch_before": scratch_before,
        "scratch_after": (scratch_json(&scratch)),
    });
    // Preserve every closed phase even if a subsequent proof, probe or assertion fails.
    eprintln!(
        "NATIVE_LOAD_RESOURCE_PHASE {}",
        norito::json::to_json(&phase).expect("phase JSON")
    );
    phases.push(phase);
    (result, observed)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

// Hash a public file incrementally; do not duplicate a large artifact for JSON.
fn file_digest(path: &Path) -> (String, u64) {
    assert!(
        std::fs::symlink_metadata(path)
            .expect("public artifact metadata")
            .file_type()
            .is_file()
    );
    let mut file = File::open(path).expect("open public artifact");
    let expected = file.metadata().expect("opened artifact metadata").len();
    let mut hash = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer).expect("read public artifact");
        if read == 0 {
            break;
        }
        count = count
            .checked_add(u64::try_from(read).unwrap())
            .expect("file length fits u64");
        assert!(count <= expected, "artifact grew while hashing");
        hash.update(&buffer[..read]);
    }
    assert_eq!(count, expected, "artifact length changed while hashing");
    (hex(&hash.finalize()), count)
}

fn fields_digest<F: ff::PrimeField>(columns: &[&[F]]) -> String {
    let mut hash = Sha256::new();
    hash.update(u64::try_from(columns.len()).unwrap().to_le_bytes());
    for column in columns {
        hash.update(u64::try_from(column.len()).unwrap().to_le_bytes());
        for value in *column {
            hash.update(value.to_repr().as_ref());
        }
    }
    hex(&hash.finalize())
}

fn opening_digest<C: PastaCurve>(opening: &FoldInput<C>) -> String {
    let mut hash = Sha256::new();
    hash.update(opening.source_k().to_le_bytes());
    hash.update(opening.g().to_bytes().as_ref());
    for value in opening.challenges() {
        hash.update(value.to_repr().as_ref());
    }
    hex(&hash.finalize())
}

fn original_identity(original: &Original) -> Value {
    let (pk_sha256, pk_bytes) = file_digest(&original.path);
    assert_eq!(pk_sha256, hex(&original.sha256));
    assert_eq!(pk_bytes, u64::try_from(original.length).unwrap());
    norito::json!({
        "descriptor_sha256": (digest(&original.descriptor)),
        "verifying_key_sha256": (digest(&original.verifying_key)),
        "proving_key_sha256": pk_sha256, "proving_key_bytes": pk_bytes,
    })
}

fn required_digest(name: &str) -> String {
    let value = std::env::var(name)
        .unwrap_or_else(|error| panic!("required diagnostic identity {name}: {error}"));
    assert!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid diagnostic SHA-256 identity {name}"
    );
    value
}

/// Compact public success data retained after a sample's large owners are dropped.
#[derive(Clone, Debug)]
pub(crate) struct Sample {
    /// Expected fresh-call position, 0 or 1.
    pub index: usize,
    /// Public identity of the fixed admitted input and key specimen.
    pub identity_sha256: String,
    /// Fresh proof digest.
    pub proof_sha256: String,
    /// Actual proof length.
    pub proof_bytes: usize,
    /// Public output frame length.
    pub frame_words: usize,
    /// Success means the real terminal returned after full verify and decide.
    pub native_terminal_accepted: bool,
    /// Direct terminal-call timing.
    pub terminal: Metrics,
    /// Charged process scratch after the output owners are dropped.
    pub scratch_retained_bytes: usize,
    /// Public output digests only; no witness or handle is serialized.
    pub output: Value,
}

fn sample_json(sample: &Sample) -> Value {
    norito::json!({
        "index": (sample.index), "identity_sha256": (&sample.identity_sha256),
        "proof_sha256": (&sample.proof_sha256), "proof_bytes": (sample.proof_bytes),
        "frame_words": (sample.frame_words), "native_terminal_accepted": (sample.native_terminal_accepted),
        "cpu_ns": (sample.terminal.cpu_ns), "elapsed_ns": (sample.terminal.elapsed_ns),
        "scratch_retained_bytes": (sample.scratch_retained_bytes), "output": (&sample.output),
    })
}

/// Refuse incomplete/duplicate samples and select CPU and wall maxima independently.
pub(crate) fn validate_samples(
    samples: &[Sample],
    identity: &str,
) -> Result<(usize, usize), &'static str> {
    if samples.len() != 2 {
        return Err("exactly two fresh terminal calls required");
    }
    for (index, sample) in samples.iter().enumerate() {
        if sample.index != index
            || sample.identity_sha256 != identity
            || !sample.native_terminal_accepted
            || sample.proof_bytes == 0
            || sample.frame_words != 69
            || sample.scratch_retained_bytes != 0
            || sample.terminal.cpu_ns == 0
            || sample.terminal.elapsed_ns == 0
        {
            return Err("invalid terminal sample");
        }
    }
    if samples[0].proof_sha256 == samples[1].proof_sha256 {
        return Err("fresh proof hashes must differ");
    }
    Ok((
        usize::from(samples[1].terminal.cpu_ns > samples[0].terminal.cpu_ns),
        usize::from(samples[1].terminal.elapsed_ns > samples[0].terminal.elapsed_ns),
    ))
}

/// Measure two fresh proofs from one BLS-admitted original in an explicit worker pool.
///
/// The fixture constructor runs inside the pool because its opaque callback is not
/// Send. Required diagnostic identity environment variables are test-only metadata.
/// Existing production-default kernel budgets and the process-wide cap are unchanged.
pub fn measure(
    make_fixture: impl FnOnce() -> (LoadFixture, Arc<AtomicUsize>) + Send,
    capture: impl Fn() -> String + Send + Sync,
) {
    let _failure = PhaseFailure("run", None);
    let requested = parse_workers(std::env::var("RAYON_NUM_THREADS").ok().as_deref())
        .expect("explicit workers");
    let source_digest = required_digest("KAGEMUSHA_RESOURCE_SOURCE_DIGEST");
    let runner_sha256 = required_digest("KAGEMUSHA_RESOURCE_RUNNER_SHA256");
    let executable = std::env::current_exe().expect("current diagnostic executable");
    let binary_before = file_digest(&executable);
    let process_before = ProcessSnapshot::capture().expect("required process start probes");
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(requested)
        .build()
        .expect("explicit pool");
    let worker_indices = worker_census(&pool, requested);
    pool.install(|| {
        assert_eq!(rayon::current_num_threads(), requested);
        let mut phases = Vec::new();
        let scratch = SharedMemoryBudget::process_default();
        assert_eq!(scratch.in_use_bytes(), 0, "exclusive diagnostic starts without live MSM reservations");
        let process_scratch_before = scratch_json(&scratch);
        let capture_before = digest(capture().as_bytes());
        let ((fixture, rebuilds, rooted, source), _) = observe(&mut phases, "setup", None, || {
            let (fixture, rebuilds) = make_fixture();
            let rooted = bootstrap_outer::rooted_bootstrap_omega_with_profile(
                false, bootstrap_outer::bootstrap_chain::SourceProfile::Tagged { buses: 3 },
            );
            let source = fixture(&rooted);
            assert_eq!(rebuilds.load(Ordering::Relaxed), 1);
            (fixture, rebuilds, rooted, source)
        });
        assert_eq!(source.inputs.predecessor.proof, rooted.proof);
        assert_eq!(source.inputs.predecessor.pallas, rooted.source.pallas.to_bytes());
        assert_eq!(source.inputs.predecessor.vesta, rooted.vesta.to_bytes());
        assert_eq!(source.inputs.state.predecessor.core, rooted.source.state.core);
        assert_eq!(source.inputs.state.predecessor.rest, rooted.source.state.rest);
        assert_eq!(source.inputs.state.predecessor.lineage, rooted.source.state.lineage);
        let original_before = original_identity(&source.terminal);
        let q = source.plan.context().operation().q(0).expect("one own receipt Q");
        let inputs = norito::json!({
            "native_bls_capture_sha256": capture_before,
            "receipt_sha256": (digest(&source.inputs.receipt)),
            "own_receipt_sha256": (digest(&source.inputs.objects[0])),
            "predecessor_proof_sha256": (digest(&rooted.proof)),
            "predecessor_descriptor_sha256": (digest(rooted.binding.encoded())),
            "predecessor_verifying_key_sha256": (digest(rooted.key.to_bytes())),
            "predecessor_pallas_sha256": (digest(&source.inputs.predecessor.pallas)),
            "predecessor_vesta_sha256": (digest(&source.inputs.predecessor.vesta)),
            "q_proof_sha256": (digest(&source.inputs.q[0].proof)),
            "q_instances_sha256": (fields_digest(&source.inputs.q[0].instances.iter().map(Vec::as_slice).collect::<Vec<_>>())),
            "q_descriptor_sha256": (digest(q.verifier().binding().encoded())),
            "context_schema_sha256": (fields_digest(&[source.plan.context().schema()])),
            "terminal_original": original_before,
        });
        let identity = digest(norito::json::to_json(&inputs).expect("public input identities").as_bytes());
        // Moving the plan avoids cloning a large graph purely for instrumentation.
        let (prover, _) = observe(&mut phases, "install", None, || {
            Prover::from_artifacts(source.plan, source.terminal.metadata::<Eq>()).expect("exact installed terminal source")
        });
        let (seal, _) = observe(&mut phases, "admission", None, || {
            let bytes = source.terminal.read(source.read.maximum_bytes);
            prover.import_terminal(&bytes, source.read).expect("strict original source admission")
        });
        let active = prover.bind_terminal(&seal, None).expect("exact admitted source binding");
        assert_eq!(active.binding().encoded(), source.terminal.descriptor);
        assert_eq!(active.verifying_key().to_bytes(), source.terminal.verifying_key);
        assert_eq!(prover.descriptors()[0], active.binding());
        assert_eq!(active.binding().descriptor().k, 16);
        assert_eq!(active.binding().descriptor().instance_lengths, [69]);
        let fold = FoldConfig::default();
        let config = ProverConfig::default();
        assert_eq!(fold.shared_budget.limit_bytes(), PROCESS_MSM_SCRATCH_BYTES);
        let mut samples = Vec::with_capacity(2);
        for index in 0..2 {
            let (session, _) = observe(&mut phases, "prepare", Some(index), || {
                // API ownership requires one input copy per fresh preparation.
                // No proof arrays or large handles are copied for record serialization.
                prover.prepare(source.inputs.clone(), MemoryBudget::DEFAULT).expect("genuine predecessor and Q preparation")
            });
            let tape_first = 201 + u64::try_from(index).unwrap();
            let tape = common::public_fixture_tape(tape_first);
            let randomness = common::fresh_randomness();
            let (terminal, timing) = observe(&mut phases, "terminal", Some(index), || {
                session.terminal(&active, tape, &fold, randomness, config)
                    .expect("full native terminal verification and complete decisions")
            });
            let (mut sample, _) = observe(&mut phases, "output_and_drop", Some(index), || {
                assert_eq!(terminal.instances.len(), 69);
                assert_eq!(terminal.opening.source_k(), 16);
                assert_eq!(terminal.predecessor_vesta.to_bytes(), source.inputs.predecessor.vesta);
                let sample = Sample {
                    index, identity_sha256: identity.clone(), proof_sha256: digest(&terminal.proof),
                    proof_bytes: terminal.proof.len(), frame_words: terminal.instances.len(),
                    native_terminal_accepted: true, terminal: timing, scratch_retained_bytes: 0,
                    output: norito::json!({
                        "frame_sha256": (fields_digest(&[&terminal.instances])),
                        "pallas_sha256": (digest(&terminal.pallas.to_bytes())),
                        "predecessor_vesta_sha256": (digest(&terminal.predecessor_vesta.to_bytes())),
                        "opening_sha256": (opening_digest(&terminal.opening)),
                        "opening_k": (terminal.opening.source_k()),
                        "randomness": "fresh-hedged", "fold_tape": "public-component-test-data",
                        "fold_tape_first": tape_first,
                    }),
                };
                drop(terminal);
                drop(session);
                sample
            });
            sample.scratch_retained_bytes = scratch.in_use_bytes();
            // A later failure must not erase an already completed proof's receipt.
            eprintln!("NATIVE_LOAD_RESOURCE_SAMPLE {}", norito::json::to_json(&sample_json(&sample)).expect("public sample JSON"));
            samples.push(sample);
        }
        let (original_after, _) = observe(&mut phases, "identity_recheck", None, || {
            assert_eq!(digest(capture().as_bytes()), capture_before);
            assert_eq!(rebuilds.load(Ordering::Relaxed), 1);
            let after = original_identity(&source.terminal);
            assert_eq!(after, original_before);
            assert_eq!(active.binding().encoded(), source.terminal.descriptor);
            assert_eq!(active.verifying_key().to_bytes(), source.terminal.verifying_key);
            after
        });
        let (slower_cpu, slower_elapsed) = validate_samples(&samples, &identity).expect("two complete fresh samples");
        // All borrowed bound views are last used before dropping their owners.
        observe(&mut phases, "cleanup", None, || {
            drop(prover); drop(source.inputs); drop(source.terminal);
            drop(rooted); drop(fixture); drop(rebuilds);
        });
        assert_eq!(scratch.in_use_bytes(), 0, "all MSM reservations released");
        assert_eq!(file_digest(&executable), binary_before, "running executable unchanged");
        let process_after = ProcessSnapshot::capture().expect("required final process probes");
        let overall = metrics(Ok(process_before), Ok(process_after), 0).expect("valid lifetime observations");
        let sample_records = samples.iter().map(sample_json).collect::<Vec<_>>();
        let report = norito::json!({
            "schema": "kagemusha.native-load.resources.v1", "outcome": "complete", "qualified": false,
            "scope": "genuine-native-single-terminal-load-bootstrap-only-predecessor",
            "catalog_qualification": false, "m3_qualification": false, "process_id": (std::process::id()),
            "source_digest": source_digest, "runner_sha256": runner_sha256, "binary_sha256": (binary_before.0),
            "worker_scope": "explicit-rayon-pool", "workers_requested": requested, "workers_observed": (rayon::current_num_threads()),
            "worker_indices": worker_indices, "curve": "vesta", "k": 16, "frame_words": 69,
            "source_profile": "tagged-3", "fixed_fixture_reuse": true,
            "memo_policy": "same-parameter-owner; fixture preparation may warm accepted memos before sample 0",
            "terminal_scope": "fold+source-bound-PK-rebuild+owned-witness-prove+PK-drop+full-verify+complete-decisions",
            "rss_scope": "kernel-lifetime-high-water-including-setup; never phase-local or subtracted",
            "prover_kernel_budget_bytes": (config.msm_budget.bytes()),
            "prepare_kernel_budget_bytes": (MemoryBudget::DEFAULT.bytes()),
            "fold_kernel_budget_bytes": (fold.kernel_budget.bytes()),
            "process_scratch_before": process_scratch_before, "process_scratch_after": (scratch_json(&scratch)),
            "before": (snapshot_json(process_before)), "after": (snapshot_json(process_after)),
            "process_cpu_ns": (overall.cpu_ns), "identity_sha256": identity, "inputs": inputs,
            "terminal_original_after": original_after, "phases": phases, "samples": sample_records,
            "slower_cpu_sample": slower_cpu, "slower_elapsed_sample": slower_elapsed,
        });
        println!("NATIVE_LOAD_RESOURCE_JSON {}", norito::json::to_json(&report).expect("public resource JSON"));
    });
}
