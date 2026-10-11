//! Measurement harness (M12): native `sigma_send` / `sigma_recv` step proofs
//! of the G1 layout on Vesta in the KAGEMUSHA step format, at `k = 12` with
//! one lane (the shape within the 3.5 KB budget), and at `k = 11` and
//! `k = 10` with the fewest lanes that fit.
//!
//! Each case prints one `M12` line per thread count: the shape, key
//! generation (parameters excluded), and for [`RUNS`] proofs after one
//! warm-up: prove wall time, prove CPU time, verification, each as
//! min/median/p95/max (nearest rank), with the proof length and the
//! 1-minute load average sampled before every proof.
//!
//! - **CPU source.** Process CPU time from
//!   `clock_gettime(CLOCK_PROCESS_CPUTIME_ID)` (nanosecond resolution on
//!   macOS and Linux), read before and after each proof. The line names the
//!   source (`cpu_source=`).
//! - **Load.** `vm.loadavg` (macOS) or `/proc/loadavg` (Linux). A series is
//!   gate-grade only if every sample stayed below [`MAX_GATE_LOAD`]; the
//!   line says so (`gate_grade=`).
//! - **Build.** The harness refuses to run in a debug build.
//! - **Keys.** The keys generated on 1 and on 4 threads must be identical.
//!   The process holds both proving keys while it compares them, so a
//!   measurement process's peak RSS is not a footprint; the
//!   `m12_footprint_*` workloads are.
//!
//! Run one case per process under `/usr/bin/time -l` for its peak RSS, in
//! release:
//!
//! ```text
//! cargo test --release -p iroha_kagemusha_proof --test measure -- --ignored \
//!     --nocapture --test-threads=1 <case>
//! ```

mod common;

use std::time::Instant;

use common::{
    BUDGET_SHAPE, K11_SHAPE, SEND_BLACKLIST, SMALLEST_SHAPE, folded, pinned_shape, recovery,
    vesta_params,
};
use iroha_kagemusha_proof::{
    KeyOptions, Mutation, ProofFormat, SigmaProver, SigmaRelation, SigmaShape, sample_witness,
};
use iroha_pasta::{Eq, Fp};

/// Timed proofs per series (after one warm-up proof).
const RUNS: usize = 20;
/// The 1-minute load average at or above which a series is not gate-grade.
const MAX_GATE_LOAD: f64 = 4.0;
/// The CPU time source, as printed.
const CPU_SOURCE: &str = "clock_gettime(CLOCK_PROCESS_CPUTIME_ID)";

/// Whether this is an optimized build without debug assertions (the
/// measurements refuse to run otherwise).
fn release_build() -> bool {
    !cfg!(debug_assertions)
}

/// Process CPU time of this process in milliseconds (all threads).
fn process_cpu_ms() -> f64 {
    let time = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    // Seconds and nanoseconds of a process's CPU time fit an f64 exactly
    // for any realistic run (below 2^53 ns, about 104 days).
    #[allow(clippy::cast_precision_loss, reason = "exact below 2^53 ns")]
    let ms = (time.tv_sec as f64).mul_add(1_000.0, time.tv_nsec as f64 / 1_000_000.0);
    ms
}

/// The 1-minute load average, if the platform reports one.
fn load1() -> Option<f64> {
    if cfg!(target_os = "linux") {
        let text = std::fs::read_to_string("/proc/loadavg").ok()?;
        return text.split_whitespace().next()?.parse().ok();
    }
    let output = std::process::Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output()
        .ok()?;
    // `{ 1.23 4.56 7.89 }`.
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// `min/median/p95/max` (nearest rank) of `values`.
fn summary(values: &[f64]) -> [f64; 4] {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let Some((&min, &max)) = sorted.first().zip(sorted.last()) else {
        return [f64::NAN; 4];
    };
    let rank = |percent: usize| {
        // The smallest value with at least `percent`% of the samples at or
        // below it.
        let index = (percent * sorted.len()).div_ceil(100).max(1) - 1;
        sorted[index.min(sorted.len() - 1)]
    };
    [min, rank(50), rank(95), max]
}

/// `min/median/p95/max` as text.
fn format_summary(values: &[f64]) -> String {
    summary(values)
        .iter()
        .map(|value| format!("{value:.1}"))
        .collect::<Vec<_>>()
        .join("/")
}

fn pool(threads: usize) -> rayon::ThreadPool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("pool")
}

/// One timed series: `runs` proofs (after one warm-up) and `runs` verifies.
struct Series {
    wall: Vec<f64>,
    cpu: Vec<f64>,
    verify: Vec<f64>,
    load: Vec<f64>,
}

impl Series {
    /// Whether every load sample stayed below [`MAX_GATE_LOAD`] (and the
    /// platform reported one).
    fn gate_grade(&self) -> bool {
        self.load.len() == self.wall.len() && self.load.iter().all(|load| *load < MAX_GATE_LOAD)
    }
}

fn series(
    prover: &SigmaProver<Eq>,
    relation: SigmaRelation,
    threads: usize,
    runs: usize,
) -> Series {
    let pool = pool(threads);
    let witness = sample_witness::<Fp>(7, relation, Mutation::None);
    let verifier = prover.verifier();
    let warm = pool
        .install(|| prover.prove(&witness, recovery(1)))
        .expect("warm-up proof");
    verifier
        .verify(&warm.public, &warm.bytes)
        .expect("warm-up verifies");
    let mut out = Series {
        wall: Vec::new(),
        cpu: Vec::new(),
        verify: Vec::new(),
        load: Vec::new(),
    };
    for run in 0..runs {
        let seed = u8::try_from(run % 200 + 2).expect("small run index");
        out.load.extend(load1());
        let cpu = process_cpu_ms();
        let started = Instant::now();
        let proof = pool
            .install(|| prover.prove(&witness, recovery(seed)))
            .expect("proof");
        out.wall.push(started.elapsed().as_secs_f64() * 1_000.0);
        out.cpu.push(process_cpu_ms() - cpu);
        let started = Instant::now();
        pool.install(|| verifier.verify(&proof.public, &proof.bytes))
            .expect("verifies");
        out.verify.push(started.elapsed().as_secs_f64() * 1_000.0);
    }
    out
}

fn measure(label: &str, shape: SigmaShape, options: KeyOptions) {
    assert!(release_build(), "M12 measurements need a release build");
    let relation = shape.params.relation();
    let started = Instant::now();
    let params = vesta_params(shape.k);
    let params_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let mut keygen = Vec::new();
    let mut prover: Option<SigmaProver<Eq>> = None;
    for threads in [1, 4] {
        let started = Instant::now();
        let keys = pool(threads)
            .install(|| {
                SigmaProver::keygen_with_options(
                    shape,
                    ProofFormat::KAGEMUSHA_STEP,
                    params.clone(),
                    options,
                )
            })
            .expect("keygen");
        keygen.push(started.elapsed().as_secs_f64() * 1_000.0);
        // The pool size changes no key byte.
        if let Some(previous) = prover.take() {
            assert_eq!(
                previous.verifier().vk_bytes(),
                keys.verifier().vk_bytes(),
                "keys depend on the pool size"
            );
        }
        prover = Some(keys);
    }
    let prover = prover.expect("keys");
    let inventory = shape.inventory::<Fp>().expect("inventory");
    let descriptor = prover.proving_key().binding().descriptor().clone();
    let bytes = shape
        .proof_length::<Eq>(ProofFormat::KAGEMUSHA_STEP)
        .expect("length");
    for (threads, keygen_ms) in [(1, keygen[0]), (4, keygen[1])] {
        let s = series(&prover, relation.relation, threads, RUNS);
        println!(
            "M12 {label} case={} k={} lanes={} limb_bits={} advice_cols={} fixed_cols={} \
             permutations={} cells={} threads={threads} runs={RUNS} params_ms={params_ms:.0} \
             keygen_ms={keygen_ms:.0} prove_wall_ms={} prove_cpu_ms={} verify_ms={} \
             proof_bytes={bytes} cpu_source={CPU_SOURCE} load1={} gate_grade={}",
            relation.label(),
            shape.k,
            shape.params.lanes(),
            shape.params.limb_bits(),
            descriptor.num_advice_columns,
            descriptor.num_fixed_columns,
            inventory.permutations(),
            inventory.cells,
            format_summary(&s.wall),
            format_summary(&s.cpu),
            format_summary(&s.verify),
            format_summary(&s.load),
            s.gate_grade(),
        );
    }
}

/// The measured shape of `relation` at `(k, lanes)`.
fn measured(relation: SigmaRelation, at: (u32, usize)) -> SigmaShape {
    pinned_shape(folded(relation), at)
}

#[test]
#[ignore = "M12 measurement; run in release, one case per process"]
fn m12_send_k12() {
    measure(
        "k12",
        measured(SigmaRelation::SEND, BUDGET_SHAPE),
        KeyOptions::default(),
    );
}

#[test]
#[ignore = "M12 measurement; run in release, one case per process"]
fn m12_recv_k12() {
    measure(
        "k12",
        measured(SigmaRelation::RECEIVE, BUDGET_SHAPE),
        KeyOptions::default(),
    );
}

#[test]
#[ignore = "M12 measurement; run in release, one case per process"]
fn m12_send_blacklist_k12() {
    measure(
        "k12",
        measured(SEND_BLACKLIST, BUDGET_SHAPE),
        KeyOptions::default(),
    );
}

#[test]
#[ignore = "M12 measurement; run in release, one case per process"]
fn m12_send_k11() {
    measure(
        "k11",
        measured(SigmaRelation::SEND, K11_SHAPE),
        KeyOptions::default(),
    );
}

#[test]
#[ignore = "M12 measurement; run in release, one case per process"]
fn m12_recv_k11() {
    measure(
        "k11",
        measured(SigmaRelation::RECEIVE, K11_SHAPE),
        KeyOptions::default(),
    );
}

#[test]
#[ignore = "M12 measurement; run in release, one case per process"]
fn m12_send_k10() {
    measure(
        "k10",
        measured(SigmaRelation::SEND, SMALLEST_SHAPE),
        KeyOptions::default(),
    );
}

#[test]
#[ignore = "M12 measurement; run in release, one case per process"]
fn m12_recv_k10() {
    measure(
        "k10",
        measured(SigmaRelation::RECEIVE, SMALLEST_SHAPE),
        KeyOptions::default(),
    );
}

/// Repeats `runs` proofs (or verifications) of the `k = 12` relation on one
/// thread, for a sampling profiler.
fn profile(relation: SigmaRelation, runs: usize, verify_only: bool) {
    assert!(release_build(), "profile a release build");
    let shape = measured(relation, BUDGET_SHAPE);
    let prover =
        SigmaProver::keygen_with_params(shape, ProofFormat::KAGEMUSHA_STEP, vesta_params(shape.k))
            .expect("keygen");
    let verifier = prover.verifier();
    let witness = sample_witness::<Fp>(7, relation, Mutation::None);
    let pool = pool(1);
    let proof = pool
        .install(|| prover.prove(&witness, recovery(1)))
        .expect("proof");
    let started = Instant::now();
    for run in 0..runs {
        if verify_only {
            pool.install(|| verifier.verify(&proof.public, &proof.bytes))
                .expect("verifies");
        } else {
            let seed = u8::try_from(run % 200).expect("seed");
            pool.install(|| prover.prove(&witness, recovery(seed)))
                .expect("proof");
        }
    }
    println!(
        "M12_PROFILE relation={} verify_only={verify_only} runs={runs} mean_ms={:.2}",
        relation.label(),
        started.elapsed().as_secs_f64() * 1_000.0 / f64::from(u32::try_from(runs).expect("runs"))
    );
}

/// One key generation, one proof and one verification on one thread: the
/// process's peak RSS is the footprint of a single step prover.
///
/// The shape is built directly (a deployed prover pins it; the selector is a
/// build-time tool), so no selection dry run inflates the footprint;
/// `tests/shapes.rs` checks the pinned shapes are the selector's.
fn footprint(relation: SigmaRelation, at: (u32, usize), options: KeyOptions) {
    assert!(release_build(), "M12 footprints need a release build");
    let shape = measured(relation, at);
    pool(1).install(|| {
        let params = vesta_params(shape.k);
        let prover = SigmaProver::<Eq>::keygen_with_options(
            shape,
            ProofFormat::KAGEMUSHA_STEP,
            params,
            options,
        )
        .expect("keys");
        let witness = sample_witness::<Fp>(7, relation, Mutation::None);
        let proof = prover.prove(&witness, recovery(1)).expect("proof");
        prover
            .verifier()
            .verify(&proof.public, &proof.bytes)
            .expect("verifies");
        println!(
            "M12_FOOTPRINT case={} k={} lanes={} tables={} proof_bytes={}",
            shape.params.relation().label(),
            shape.k,
            shape.params.lanes(),
            options.commitment_tables.is_some(),
            proof.bytes.len()
        );
    });
}

#[test]
#[ignore = "M12 footprint; run in release under /usr/bin/time -l"]
fn m12_footprint_send_k12() {
    footprint(SigmaRelation::SEND, BUDGET_SHAPE, KeyOptions::default());
}

#[test]
#[ignore = "M12 footprint; run in release under /usr/bin/time -l"]
fn m12_footprint_recv_k12() {
    footprint(SigmaRelation::RECEIVE, BUDGET_SHAPE, KeyOptions::default());
}

#[test]
#[ignore = "M12 footprint; run in release under /usr/bin/time -l"]
fn m12_footprint_send_blacklist_k12() {
    footprint(SEND_BLACKLIST, BUDGET_SHAPE, KeyOptions::default());
}

#[test]
#[ignore = "M12 footprint; run in release under /usr/bin/time -l"]
fn m12_footprint_send_k11() {
    footprint(SigmaRelation::SEND, K11_SHAPE, KeyOptions::default());
}

#[test]
#[ignore = "M12 footprint; run in release under /usr/bin/time -l"]
fn m12_footprint_recv_k11() {
    footprint(SigmaRelation::RECEIVE, K11_SHAPE, KeyOptions::default());
}

#[test]
#[ignore = "M12 footprint; run in release under /usr/bin/time -l"]
fn m12_footprint_send_k10() {
    footprint(SigmaRelation::SEND, SMALLEST_SHAPE, KeyOptions::default());
}

#[test]
#[ignore = "M12 footprint; run in release under /usr/bin/time -l"]
fn m12_footprint_recv_k10() {
    footprint(
        SigmaRelation::RECEIVE,
        SMALLEST_SHAPE,
        KeyOptions::default(),
    );
}

#[test]
#[ignore = "M12 measurement; run in release, one case per process"]
fn m12_send_k12_tables() {
    measure(
        "k12_tables",
        measured(SigmaRelation::SEND, BUDGET_SHAPE),
        KeyOptions::WITH_TABLES,
    );
}

#[test]
#[ignore = "M12 measurement; run in release, one case per process"]
fn m12_recv_k12_tables() {
    measure(
        "k12_tables",
        measured(SigmaRelation::RECEIVE, BUDGET_SHAPE),
        KeyOptions::WITH_TABLES,
    );
}

#[test]
#[ignore = "M12 footprint; run in release under /usr/bin/time -l"]
fn m12_footprint_send_k12_tables() {
    footprint(SigmaRelation::SEND, BUDGET_SHAPE, KeyOptions::WITH_TABLES);
}

#[test]
#[ignore = "profiling workload; run in release under a sampling profiler"]
fn m12_profile_send_prove() {
    profile(SigmaRelation::SEND, 40, false);
}

#[test]
#[ignore = "profiling workload; run in release under a sampling profiler"]
fn m12_profile_send_verify() {
    profile(SigmaRelation::SEND, 400, true);
}

#[test]
fn summaries_and_probes() {
    let bits = |values: [f64; 4]| values.map(f64::to_bits);
    assert_eq!(bits(summary(&[3.0, 1.0, 2.0])), bits([1.0, 2.0, 3.0, 3.0]));
    // Nearest rank of 20 samples: the median is the 10th, p95 the 19th.
    let values: Vec<f64> = (1..=20).map(f64::from).collect();
    assert_eq!(bits(summary(&values)), bits([1.0, 10.0, 19.0, 20.0]));
    assert_eq!(release_build(), !cfg!(debug_assertions));
    assert!(summary(&[]).iter().all(|value| value.is_nan()));
    assert_eq!(format_summary(&[2.0, 1.0]), "1.0/1.0/2.0/2.0");
    // The CPU clock advances with work and has sub-millisecond resolution.
    let start = process_cpu_ms();
    let mut x = 1_u64;
    for i in 0..2_000_000_u64 {
        x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(i);
    }
    assert_ne!(x, 0);
    let spent = process_cpu_ms() - start;
    assert!(spent > 0.0, "{spent}");
    assert!(load1().is_none_or(|load| load >= 0.0));
    let series = Series {
        wall: vec![1.0, 2.0],
        cpu: vec![1.0, 2.0],
        verify: vec![1.0, 1.0],
        load: vec![1.0, MAX_GATE_LOAD],
    };
    assert!(!series.gate_grade());
    assert!(!series.cpu.is_empty() && !series.verify.is_empty());
    // The measured shapes are the pinned ones.
    for at in [BUDGET_SHAPE, K11_SHAPE, SMALLEST_SHAPE] {
        let shape = measured(SigmaRelation::SEND, at);
        assert_eq!((shape.k, shape.params.lanes()), at);
        assert_eq!(
            shape.params.limb_bits(),
            usize::try_from(at.0 - 1).expect("k")
        );
    }
}
