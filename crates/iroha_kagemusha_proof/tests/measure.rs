//! Measurement harness (M12): native `sigma_send` / `sigma_recv` step proofs
//! of the G1 layout on Vesta in the KAGEMUSHA step format.
//!
//! - `sigma_send` without a control and `sigma_recv` without the blacklist
//!   bit: at `k = 12` with one lane (the shape within the 3.5 KB budget),
//!   and at `k = 11` and `k = 10` with the fewest lanes that fit;
//! - `sigma_recv` with the blacklist bit at `k = 12` (one lane) and `k = 11`
//!   (its smallest `k`: the 16-node gap path is one lane's site, 1,295
//!   rows, more than a `k = 10` lane holds), and `sigma_send` with the
//!   blacklist control at `k = 12`;
//! - `sigma_send` with every control (the full mask: blacklist gap opening
//!   and list age, quota windows and usage update, lease): at `k = 14`
//!   with one lane (the single-lane shape R9 needs), and at `k = 13` and
//!   `k = 12` with the fewest lanes (no shape at `k <= 11` fits within
//!   [`iroha_kagemusha_proof::MAX_LANES`]).
//! - every Send control mask at the native wallet's one-lane shape: masks
//!   0, 1, 4 and 5 use `k = 12`; quota masks 2, 3, 6 and 7 use `k = 14`.
//!   Both Receive selectors use `k = 12`. The ordinary coverage test binds
//!   this complete grid to `wallet_monetary_shape`.
//!
//! Each case prints one `M12` line per thread count: the shape, key
//! generation (parameters excluded), and for its runs (20, or 8 for the
//! full mask) proofs after one warm-up: prove wall time, prove CPU time,
//! verification, each as min/median/p95/max (nearest rank), with the proof
//! length and the 1-minute load average sampled before every proof.
//! Each `M12_SAMPLE` line retains one verified proof's raw observations;
//! an unavailable load probe keeps its sample position and is never zero.
//!
//! - **CPU source.** Process CPU time from
//!   `clock_gettime(CLOCK_PROCESS_CPUTIME_ID)` (nanosecond resolution on
//!   macOS and Linux), read before and after each proof. The line names the
//!   source (`cpu_source=`).
//! - **Load.** `vm.loadavg` (macOS) or `/proc/loadavg` (Linux). A series is
//!   marked low-load only if every sample stayed below [`MAX_GATE_LOAD`];
//!   this diagnostic does not apply the fresh-process qualification method.
//! - **Build.** The harness refuses to run in a debug build.
//! - **Keys.** The keys generated on 1 and on 4 threads must be identical.
//!   Every measured proof has the exact descriptor length and is verified;
//!   the output binds its descriptor and verifying-key digest. These locally
//!   generated keys do not qualify an installed wallet catalog.
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
    BUDGET_SHAPE, K11_SHAPE, RECEIVE_BLACKLIST, SEND_BLACKLIST, SEND_EVERY, SEND_LEASE,
    SEND_QUOTAS, SMALLEST_SHAPE, folded, pinned_shape, recovery, vesta_params,
};
use iroha_kagemusha_proof::{
    KeyOptions, Mutation, SigmaProver, SigmaRelation, SigmaShape, sample_witness,
};
use iroha_pasta::{Eq, Fp};
use sha2::{Digest as _, Sha256};

/// Timed proofs per series (after one warm-up proof).
const RUNS: usize = 20;
/// Timed proofs per series of a `k >= 14` shape.
const LARGE_RUNS: usize = 8;
/// The 1-minute load average at or above which a series is not low-load.
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
    assert!(time.tv_sec >= 0 && (0..1_000_000_000).contains(&time.tv_nsec));
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
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("pool");
    assert_eq!(pool.current_num_threads(), threads);
    pool
}

/// One timed series: `runs` proofs (after one warm-up) and `runs` verifies.
struct Series {
    wall: Vec<f64>,
    cpu: Vec<f64>,
    verify: Vec<f64>,
    load: Vec<Option<f64>>,
}

impl Series {
    /// Whether every load sample stayed below [`MAX_GATE_LOAD`] (and the
    /// platform reported one).
    fn low_load(&self) -> bool {
        self.load.len() == self.wall.len()
            && self
                .load
                .iter()
                .all(|load| load.is_some_and(|value| value < MAX_GATE_LOAD))
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
    assert_eq!(verifier.relation(), relation);
    let exact_bytes = verifier.proof_bytes().expect("descriptor length");
    let warm = pool
        .install(|| prover.prove(&witness, recovery(1)))
        .expect("warm-up proof");
    assert_eq!(warm.bytes.len(), exact_bytes);
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
        out.load.push(load1());
        let cpu = process_cpu_ms();
        let started = Instant::now();
        let proof = pool
            .install(|| {
                assert_eq!(rayon::current_num_threads(), threads);
                prover.prove(&witness, recovery(seed))
            })
            .expect("proof");
        out.wall.push(started.elapsed().as_secs_f64() * 1_000.0);
        let spent = process_cpu_ms() - cpu;
        assert!(spent.is_finite() && spent > 0.0, "invalid CPU observation");
        out.cpu.push(spent);
        assert_eq!(proof.bytes.len(), exact_bytes);
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
            .install(|| SigmaProver::keygen_with_options(shape, params.clone(), options))
            .expect("keygen");
        keygen.push(started.elapsed().as_secs_f64() * 1_000.0);
        // The pool size changes no key byte.
        if let Some(previous) = prover.take() {
            assert_eq!(
                previous.verifier().vk_bytes(),
                keys.verifier().vk_bytes(),
                "keys depend on the pool size"
            );
            assert_eq!(
                previous.verifier().descriptor_bytes(),
                keys.verifier().descriptor_bytes(),
                "descriptors depend on the pool size"
            );
        }
        prover = Some(keys);
    }
    let prover = prover.expect("keys");
    let inventory = shape.inventory::<Fp>().expect("inventory");
    let descriptor = prover.proving_key().binding().descriptor().clone();
    let verifier = prover.verifier();
    let bytes = verifier.proof_bytes().expect("descriptor length");
    assert_eq!(bytes, shape.proof_length::<Eq>().expect("shape length"));
    let descriptor_sha256 = Sha256::digest(verifier.descriptor_bytes());
    let key_digest = verifier.verifying_key_digest().expect("key digest");
    let key_digest = key_digest.iter().fold(String::new(), |mut out, byte| {
        use core::fmt::Write as _;
        write!(out, "{byte:02x}").expect("string write");
        out
    });
    let runs = if shape.k >= 14 { LARGE_RUNS } else { RUNS };
    for (threads, keygen_ms) in [(1, keygen[0]), (4, keygen[1])] {
        let s = series(&prover, relation.relation, threads, runs);
        println!(
            "M12 {label} case={} k={} lanes={} limb_bits={} advice_cols={} fixed_cols={} \
             permutations={} cells={} threads={threads} runs={runs} params_ms={params_ms:.0} \
             keygen_ms={keygen_ms:.0} prove_wall_ms={} prove_cpu_ms={} verify_ms={} \
             proof_bytes={bytes} descriptor_sha256={descriptor_sha256:x} vk_digest={key_digest} \
             cpu_source={CPU_SOURCE} load1={} low_load={} catalog_qualified=false",
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
            format_summary(&s.load.iter().filter_map(|load| *load).collect::<Vec<_>>()),
            s.low_load(),
        );
        for run in 0..runs {
            let load =
                s.load[run].map_or_else(|| "unavailable".to_owned(), |value| value.to_string());
            println!(
                "M12_SAMPLE {label} case={} threads={threads} index={run} wall_ms={} \
                 cpu_ms={} verify_ms={} load1={load} proof_bytes={bytes} verified=true",
                relation.label(),
                s.wall[run],
                s.cpu[run],
                s.verify[run],
            );
        }
    }
}

/// The measured shape of `relation` at `(k, lanes)`.
fn measured(relation: SigmaRelation, at: (u32, usize)) -> SigmaShape {
    pinned_shape(folded(relation), at)
}

/// The full mask's single-lane shape (the one R9 needs).
const FULL_K14_SHAPE: (u32, usize) = (14, 1);
/// The full mask's fewest lanes at `k = 13`.
const FULL_K13_SHAPE: (u32, usize) = (13, 2);
/// The full mask's fewest lanes at `k = 12` (its smallest `k`).
const FULL_K12_SHAPE: (u32, usize) = (12, 4);

/// Measurement and footprint tests of `relation` at a shape.
macro_rules! cases {
    ($($measure:ident, $footprint:ident: $relation:expr, $label:literal, $at:expr;)*) => {
        const MEASUREMENT_CASES: &[(&str, SigmaRelation, (u32, usize))] = &[
            $((stringify!($measure), $relation, $at)),*
        ];
        $(
            #[test]
            #[ignore = "M12 measurement; run in release, one case per process"]
            fn $measure() {
                measure($label, measured($relation, $at), KeyOptions::default());
            }

            #[test]
            #[ignore = "M12 footprint; run in release under /usr/bin/time -l"]
            fn $footprint() {
                footprint($relation, $at, KeyOptions::default());
            }
        )*
    };
}

cases! {
    m12_send_k12, m12_footprint_send_k12: SigmaRelation::SEND, "k12", BUDGET_SHAPE;
    m12_send_k11, m12_footprint_send_k11: SigmaRelation::SEND, "k11", K11_SHAPE;
    m12_send_k10, m12_footprint_send_k10: SigmaRelation::SEND, "k10", SMALLEST_SHAPE;
    m12_recv_k12, m12_footprint_recv_k12: SigmaRelation::RECEIVE, "k12", BUDGET_SHAPE;
    m12_recv_k11, m12_footprint_recv_k11: SigmaRelation::RECEIVE, "k11", K11_SHAPE;
    m12_recv_k10, m12_footprint_recv_k10: SigmaRelation::RECEIVE, "k10", SMALLEST_SHAPE;
    m12_recv_blacklist_k12, m12_footprint_recv_blacklist_k12:
        RECEIVE_BLACKLIST, "k12", BUDGET_SHAPE;
    m12_recv_blacklist_k11, m12_footprint_recv_blacklist_k11:
        RECEIVE_BLACKLIST, "k11", K11_SHAPE;
    m12_send_blacklist_k12, m12_footprint_send_blacklist_k12:
        SEND_BLACKLIST, "k12", BUDGET_SHAPE;
    m12_send_lease_k12, m12_footprint_send_lease_k12: SEND_LEASE, "k12", BUDGET_SHAPE;
    m12_send_blacklist_lease_k12, m12_footprint_send_blacklist_lease_k12:
        SigmaRelation::send(5), "k12", BUDGET_SHAPE;
    m12_send_quota_k14, m12_footprint_send_quota_k14: SEND_QUOTAS, "k14", FULL_K14_SHAPE;
    m12_send_blacklist_quota_k14, m12_footprint_send_blacklist_quota_k14:
        SigmaRelation::send(3), "k14", FULL_K14_SHAPE;
    m12_send_quota_lease_k14, m12_footprint_send_quota_lease_k14:
        SigmaRelation::send(6), "k14", FULL_K14_SHAPE;
    m12_send_full_k14, m12_footprint_send_full_k14: SEND_EVERY, "k14", FULL_K14_SHAPE;
    m12_send_full_k13, m12_footprint_send_full_k13: SEND_EVERY, "k13", FULL_K13_SHAPE;
    m12_send_full_k12, m12_footprint_send_full_k12: SEND_EVERY, "k12", FULL_K12_SHAPE;
}

/// Repeats `runs` proofs (or verifications) of the `k = 12` relation on one
/// thread, for a sampling profiler.
fn profile(relation: SigmaRelation, runs: usize, verify_only: bool) {
    assert!(release_build(), "profile a release build");
    let shape = measured(relation, BUDGET_SHAPE);
    let prover = SigmaProver::keygen_with_params(shape, vesta_params(shape.k)).expect("keygen");
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
        let prover = SigmaProver::<Eq>::keygen_with_options(shape, params, options).expect("keys");
        let witness = sample_witness::<Fp>(7, relation, Mutation::None);
        let proof = prover.prove(&witness, recovery(1)).expect("proof");
        let verifier = prover.verifier();
        assert_eq!(proof.bytes.len(), verifier.proof_bytes().expect("length"));
        verifier
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
fn monetary_measurements_cover_every_native_selector() {
    use std::collections::BTreeSet;

    use iroha_kagemusha_proof::{CONTROLS_DEFINED, wallet_monetary_shape};

    let mut actual = BTreeSet::new();
    for &(name, relation, at) in MEASUREMENT_CASES {
        let canonical = wallet_monetary_shape(relation).expect("native monetary shape");
        if at == (canonical.k, canonical.params.lanes()) {
            assert_eq!(measured(relation, at), canonical, "{name}");
            assert!(actual.insert(relation.selector()), "duplicate case: {name}");
        }
    }
    let expected: BTreeSet<_> = (0..=CONTROLS_DEFINED)
        .map(|mask| SigmaRelation::send(mask).selector())
        .chain([
            SigmaRelation::RECEIVE.selector(),
            RECEIVE_BLACKLIST.selector(),
        ])
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 10);
}

#[test]
fn measurement_pools_use_every_requested_worker() {
    for workers in [1, 4] {
        let pool = pool(workers);
        let mut indices = pool.broadcast(|context| {
            assert_eq!(rayon::current_num_threads(), workers);
            context.index()
        });
        indices.sort_unstable();
        assert_eq!(indices, (0..workers).collect::<Vec<_>>());
    }
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
    let mut series = Series {
        wall: vec![1.0, 2.0],
        cpu: vec![1.0, 2.0],
        verify: vec![1.0, 1.0],
        load: vec![Some(1.0), Some(MAX_GATE_LOAD)],
    };
    assert!(!series.low_load());
    series.load[1] = None;
    assert!(
        !series.low_load(),
        "unavailable load never qualifies as low"
    );
    series.load[1] = Some(1.0);
    assert!(series.low_load());
    series.load.pop();
    assert!(!series.low_load(), "every proof needs its own observation");
    assert!(!series.cpu.is_empty() && !series.verify.is_empty());
    // The measured shapes are the pinned ones.
    for (relation, at) in [
        (SigmaRelation::SEND, BUDGET_SHAPE),
        (SigmaRelation::SEND, K11_SHAPE),
        (SigmaRelation::SEND, SMALLEST_SHAPE),
        (RECEIVE_BLACKLIST, K11_SHAPE),
        (SEND_EVERY, FULL_K14_SHAPE),
        (SEND_EVERY, FULL_K13_SHAPE),
        (SEND_EVERY, FULL_K12_SHAPE),
    ] {
        let shape = measured(relation, at);
        assert_eq!((shape.k, shape.params.lanes()), at);
        assert_eq!(
            shape.params.limb_bits(),
            usize::try_from(at.0 - 1).expect("k")
        );
    }
}
