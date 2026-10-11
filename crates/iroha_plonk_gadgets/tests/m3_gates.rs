//! M3 measurement gates of `specs/kagemusha_lambda_omega_v1.md` (section 10),
//! measured natively at `k = 16`.
//!
//! Gates G3.1-G3.5 (cells and rows per operation) are pinned by the chips'
//! own inventory tests (`p256_inventory_per_verification`,
//! `sha256_gate_g3_3_measurement`, `ff_inventory_per_operation`,
//! `glv_inventory_at_the_gate_shape`); `g3_6_q_leaf_shape` re-measures the
//! P-256 and SHA-256 cells inside a filled Q leaf. This file holds the proof
//! gates:
//!
//! - **G3.6** (Q leaf, `Fq` circuit, Pallas proof): the 17-column Q-leaf
//!   layout of `iroha_plonk_gadgets::q_leaf` filled with the P-256 and
//!   SHA-256 chips (five witness-key verifications and one fixed-key
//!   verification, each over a Poseidon digest hashed in circuit; 17 advice /
//!   26 fixed before selector compression / 12 equality / 10 lookups), and
//!   the design's exact shape (22 advice / 32 fixed / 8 equality / 3
//!   lookups) filled with degree-6 S-box chains and range lookups;
//! - **G3.7** (A aggregator, `Fp` circuit, Vesta proof): six RP57 Pow5 lanes
//!   running depth-32 IMT-like non-membership paths (leaf hash, 32
//!   select-and-hash levels, index bits recomposed by glue, ordering range
//!   checks on three running-sum tables) filled to capacity, and the exact
//!   shape (32 / 44 / 10 / 3).
//!
//! Each proof test emits a `M3_GATE_JSON` record. CPU comes directly from
//! the process clock, RSS from the kernel's lifetime high-water figure,
//! and each proof is verified outside its timed synthesis/proving/cleanup
//! interval. Probe failures invalidate the run. The harness constructs and
//! checks a one- or four-worker Rayon pool; `RAYON_NUM_THREADS` selects it.
//! Keys use on-demand cosets without commitment tables. The consuming
//! witness API and the shared process MSM budget are measured explicitly.
//! `scripts/kagemusha_qualify.py` owns fresh processes, source/binary
//! provenance, environmental checks and the fixed repetition schedule.
//!
//! ```text
//! scripts/cargo_fast.sh --stable-local-metadata --incremental --target-slot m3b -- \
//!     test -p iroha_plonk_gadgets --release --test m3_gates --no-run
//! RAYON_NUM_THREADS=1 /usr/bin/time -l <test binary> --ignored --exact g3_6_q_leaf_proof --nocapture
//! ```

use std::{
    convert::Infallible,
    fmt::Write as _,
    io::Read as _,
    ops::Range,
    path::{Path, PathBuf},
    time::Instant,
};

use ::ff::{Field as _, PrimeField as _};
use iroha_measurement::probe::ProcessSnapshot;
use iroha_pasta::{
    Ep as Pallas, Eq as Vesta, Fp, Fq, PastaCurve, PastaField,
    msm::{MemoryBudget, SharedMemoryBudget},
    poseidon::{PoseidonField, hash_with_domain},
};
use iroha_plonk::{
    Expression, ProverConfig, ProverRandomness, QuotientWorkspace, Witness,
    check::{CheckMode, check_circuit},
    create_proof_owned_with_workspace,
    cs::{Advice, Column, ConstraintSystem, Fixed, Instance, InstanceType, Rotation, TableColumn},
    frontend::{Cell, Circuit, Error, Layouter, SimpleFloorPlanner, Value, configure, synthesize},
    keys::{CosetCachePolicy, KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    prover::quotient::CompiledExpressions,
    verify_full,
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig, LimbBits, Pow5Columns, RoundConstantColumns, RunningSumChip,
    RunningSumConfig, SpongeChip, SpongeConfig, Word,
    ff::{FF_ADVICE_COLUMNS, ForeignModulus},
    p256::{
        P256Key, VerifyMode,
        native::{
            self, Affine, HALF_N, N, ORDER, verify_prehashed, words_cmp, words_from_be,
            words_is_zero, words_lt,
        },
    },
    poseidon::SharedRoundSelectors,
    q_leaf::{Q_LEAF_ADVICE_COLUMNS, QLeafChips, QLeafConfig, sha_rows},
    sha256::native::sha256_of_digest,
    tamper::undetected_tampers,
};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};
use sha2::{Digest as _, Sha256};

#[path = "m3_gates/advice_schedule.rs"]
mod advice_schedule;
#[path = "m3_gates/export_descriptors.rs"]
mod export_descriptors;

/// The circuit size of every gate.
const K: u32 = 16;
/// Proofs per measurement process (the key is generated once).
const PROVES: usize = 2;
/// The local kernel ceiling; every kernel also reserves against the shared
/// process-wide 64 MiB budget.
const MSM_BUDGET: MemoryBudget = MemoryBudget::new(64 << 20);
/// Explicit caller-owned quotient field-buffer ceiling, independent of MSM.
const QUOTIENT_WORKSPACE_BYTES: usize = 256 << 20;

/// Only the two declared qualification worker counts are accepted.
fn worker_count(value: Option<&str>) -> Result<usize, &'static str> {
    match value.unwrap_or("1") {
        "1" => Ok(1),
        "4" => Ok(4),
        _ => Err("M3 qualification requires exactly one or four Rayon workers"),
    }
}

/// Lowercase hexadecimal without allocating a second copy of the input.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("string write");
    }
    out
}

/// Hash the actual executable with a fixed-size buffer before measurement.
fn binary_digest() -> String {
    let path = std::env::current_exe().expect("benchmark executable");
    let mut file = std::fs::File::open(path).expect("read benchmark executable");
    let mut hash = Sha256::new();
    let mut buffer = [0; 8 << 10];
    loop {
        let count = file.read(&mut buffer).expect("hash benchmark executable");
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    hex(&hash.finalize())
}

/// Convert an elapsed duration to the report's checked nanosecond field.
fn elapsed_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).expect("measurement shorter than 584 years")
}

// ---------------------------------------------------------------------------
// Shapes, inventories and the proof measurement.
// ---------------------------------------------------------------------------

/// Columns, arguments and degree of a constraint system.
fn shape_line<F: PastaField>(cs: &ConstraintSystem<F>) -> String {
    let polys: usize = cs.gates().iter().map(|gate| gate.polynomials().len()).sum();
    let nodes: usize = cs
        .gates()
        .iter()
        .flat_map(|gate| gate.polynomials().iter().map(Expression::node_count))
        .sum();
    format!(
        "advice={} fixed={} selectors={} equality={} lookups={} degree={} gates={} \
         gate_polys={polys} gate_nodes={nodes} instance_columns={} blinding={}",
        cs.num_advice_columns(),
        cs.num_fixed_columns(),
        cs.num_selectors(),
        cs.permutation().columns().len(),
        cs.lookups().len(),
        cs.degree(),
        cs.gates().len(),
        cs.num_instance_columns(),
        cs.blinding_factors(),
    )
}

/// Assigned cells and the row extent `last + 1 - first` of `columns`.
fn column_use(flags: &[Vec<bool>], columns: Range<usize>) -> (usize, usize) {
    let columns = &flags[columns];
    let cells = columns
        .iter()
        .map(|column| column.iter().filter(|flag| **flag).count())
        .sum();
    let first = columns
        .iter()
        .filter_map(|column| column.iter().position(|flag| *flag))
        .min()
        .unwrap_or(0);
    let end = columns
        .iter()
        .filter_map(|column| column.iter().rposition(|flag| *flag))
        .max()
        .map_or(0, |row| row + 1);
    (cells, end.saturating_sub(first))
}

/// Synthesizes `circuit`, prints its inventory per column group and checks
/// it strictly; returns the total assigned advice cells and the span (the
/// first row above every assigned advice cell).
fn inventory<F: PastaField, C: Circuit<F>>(
    name: &str,
    circuit: &C,
    public: &[F],
    groups: &[(&str, Range<usize>)],
) -> (usize, usize) {
    let started = Instant::now();
    let synthesized = synthesize(circuit, K, Some(&[public.to_vec()][..])).expect("synthesis");
    let synthesis_ms = started.elapsed().as_millis();
    let flags = synthesized.tables.advice_assigned();
    let (cells, _) = column_use(flags, 0..flags.len());
    let span = flags
        .iter()
        .filter_map(|column| column.iter().rposition(|flag| *flag))
        .max()
        .map_or(0, |row| row + 1);
    let usable = synthesized.cs.usable_rows(K).expect("usable rows");
    let mut line = format!(
        "M3_INVENTORY circuit={name} k={K} {} usable_rows={usable} span={span} \
         assigned_cells={cells} area_cells={} synthesis_ms={synthesis_ms}",
        shape_line(&synthesized.cs),
        flags.len() * usable,
    );
    for (group, columns) in groups {
        let (group_cells, rows) = column_use(flags, columns.clone());
        write!(
            line,
            " {group}=[columns={} rows={rows} cells={group_cells}]",
            columns.len()
        )
        .expect("write to a string");
    }
    let started = Instant::now();
    let report =
        check_circuit(circuit, K, &[public.to_vec()], CheckMode::Strict).expect("synthesis");
    let check_ms = started.elapsed().as_millis();
    assert!(report.is_satisfied(), "{name}: {report}");
    println!("{line} check_ms={check_ms}");
    assert!(span <= usable, "{name}: span {span} > usable {usable}");
    (cells, span)
}

/// The cache file of the pinned parameters of curve `C` at `k`, in the
/// integration tests' scratch directory of the target directory.
fn params_cache_path<C: PastaCurve>(k: u32) -> PathBuf {
    let curve: String = std::any::type_name::<C>()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("pinned_params_{curve}_k{k}.bin"))
}

/// The pinned parameters at `k` from the cache file when it holds bytes that
/// hash to the pinned digest ([`PinnedParams::from_bytes`] checks the digest
/// and decodes every point), otherwise derived (19-22 s of CPU at `k = 16`)
/// and written to the cache (through a temporary file and a rename, so a
/// concurrent reader sees the old file or the new one). Returns the
/// parameters and where they came from. The cache never changes what a
/// proof or a key is: only pinned bytes are accepted.
fn pinned_params<C: PastaCurve>(k: u32) -> (PinnedParams<C>, &'static str) {
    let path = params_cache_path::<C>(k);
    if let Ok(bytes) = std::fs::read(&path)
        && let Ok(params) = PinnedParams::<C>::from_bytes(&bytes)
        && params.k() == k
    {
        return (params, "cache");
    }
    let params = PinnedParams::<C>::derive(k).expect("params");
    let temporary = path.with_extension(format!("tmp{}", std::process::id()));
    if std::fs::write(&temporary, params.params().to_bytes()).is_ok() {
        let _ = std::fs::rename(&temporary, &path);
    }
    (params, "derived")
}

/// Measure inside a pool whose actual worker count is checked explicitly.
fn measure_proof<C, Ci>(gate: &str, circuit: &Ci, public: &[C::ScalarExt])
where
    C: PastaCurve,
    C::ScalarExt: PoseidonField,
    Ci: Circuit<C::ScalarExt> + Sync,
{
    let requested = std::env::var("RAYON_NUM_THREADS").ok();
    let workers = worker_count(requested.as_deref()).expect("worker configuration");
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .expect("measurement pool");
    let binary_sha256 = binary_digest();
    pool.install(|| {
        assert_eq!(rayon::current_num_threads(), workers);
        measure_in_pool::<C, Ci>(gate, circuit, public, workers, &binary_sha256);
    });
}

/// The same key and transcript configuration for inventory and timed proofs.
fn measurement_key_config() -> KeygenConfigV2 {
    let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Field]);
    config.coset_cache = CosetCachePolicy::OnDemand;
    config
}

/// Bind the measurement workload before executing any qualification schedule.
fn record_layout<C, Ci>(gate: &str, circuit: &Ci)
where
    C: PastaCurve,
    C::ScalarExt: PoseidonField,
    Ci: Circuit<C::ScalarExt>,
{
    let (cs, _) = configure(circuit).expect("configure inventory");
    let (params, _) = pinned_params::<C>(K);
    let pk = keygen_pk_v2(
        &params,
        &circuit.without_witnesses(),
        &measurement_key_config(),
    )
    .expect("inventory proving key");
    let report = norito::json!({
        "gate": gate, "k": K, "shape": (shape_line(&cs)),
        "descriptor_digest": (hex(pk.vk().descriptor_digest())),
        "descriptor_hash": "blake2b256-pipa-v2-circdesc", "transcript_profile": "pipa-r",
    });
    println!(
        "M3_LAYOUT_JSON {}",
        norito::json::to_json(&report).expect("layout JSON")
    );
}

/// Synthesis through witness cleanup is timed independently for each proof.
/// Parameters/keygen and each verification are outside that interval.
fn measure_in_pool<C, Ci>(
    gate: &str,
    circuit: &Ci,
    public: &[C::ScalarExt],
    workers: usize,
    binary_sha256: &str,
) where
    C: PastaCurve,
    C::ScalarExt: PoseidonField,
    Ci: Circuit<C::ScalarExt>,
{
    let process_before = ProcessSnapshot::capture().expect("valid starting resource probes");
    let (cs, _) = configure(circuit).expect("configure");
    let started = Instant::now();
    let (params, params_source) = pinned_params::<C>(K);
    let params_ns = elapsed_ns(started);
    let rss_after_params = ProcessSnapshot::capture()
        .expect("post-params probes")
        .peak_rss_bytes;
    let started = Instant::now();
    let config = measurement_key_config();
    let pk = keygen_pk_v2(&params, &circuit.without_witnesses(), &config).expect("proving key");
    let keygen_ns = elapsed_ns(started);
    let rss_after_keygen = ProcessSnapshot::capture()
        .expect("post-keygen probes")
        .peak_rss_bytes;
    let key_cs = pk.constraint_system().constraint_system();
    let compiled = CompiledExpressions::<C::ScalarExt>::compile(pk.binding().descriptor(), true)
        .expect("compiled expressions");
    let instances = vec![public.to_vec()];
    let mut samples = Vec::with_capacity(PROVES);
    let mut quotient_workspace = QuotientWorkspace::new(QUOTIENT_WORKSPACE_BYTES);
    let seed = std::env::var("M3_SEED")
        .map_or(Ok(7), |value| value.parse::<u64>())
        .expect("M3_SEED must be a u64");
    for index in 0..PROVES {
        let mut seed_bytes = [0; 32];
        seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
        seed_bytes[8..16]
            .copy_from_slice(&u64::try_from(index).expect("proof index").to_le_bytes());
        let workspace_before_bytes = quotient_workspace.allocated_bytes();
        let before = ProcessSnapshot::capture().expect("valid pre-proof resource probes");
        let started = Instant::now();
        let witness = Witness::from_circuit(&pk, circuit, &instances).expect("witness");
        let synthesis_ns = elapsed_ns(started);
        let rss_after_witness = ProcessSnapshot::capture()
            .expect("post-witness probes")
            .peak_rss_bytes;
        let randomness = ProverRandomness::recovery(move |_context: &[u8; 32]| {
            Ok::<_, Infallible>(ChaCha20Rng::from_seed(seed_bytes))
        });
        let proving = Instant::now();
        let output = create_proof_owned_with_workspace(
            &params,
            &pk,
            witness,
            randomness,
            ProverConfig {
                msm_budget: MSM_BUDGET,
                cancellation: None,
            },
            &mut quotient_workspace,
        )
        .expect("proof");
        let proof = output.proof;
        let create_proof_ns = elapsed_ns(proving);
        // The consumed witness has already been released here.
        let total_ns = elapsed_ns(started);
        let after = ProcessSnapshot::capture().expect("valid post-proof resource probes");
        let cpu_ns = after.cpu_since(before).expect("monotonic process CPU");
        let verifying = Instant::now();
        assert_eq!(
            verify_full(
                &params,
                pk.binding(),
                pk.vk(),
                &instances,
                &proof,
                MSM_BUDGET
            ),
            Ok(()),
            "{gate}: proof {index} rejected",
        );
        let verify_ns = elapsed_ns(verifying);
        let rss_after_verify = ProcessSnapshot::capture()
            .expect("post-verify probes")
            .peak_rss_bytes;
        let mut wrong = instances.clone();
        wrong[0][0] += C::ScalarExt::ONE;
        assert!(
            verify_full(&params, pk.binding(), pk.vk(), &wrong, &proof, MSM_BUDGET).is_err(),
            "{gate}: proof {index} accepted the wrong public input",
        );
        samples.push(norito::json!({
            "index": index, "synthesis_ns": synthesis_ns,
            "quotient_workspace_before_bytes": workspace_before_bytes,
            "quotient_workspace_after_bytes": (quotient_workspace.allocated_bytes()),
            "create_proof_ns": create_proof_ns, "total_ns": total_ns,
            "cpu_ns": cpu_ns, "verify_ns": verify_ns,
            "proof_bytes": (proof.len()), "verified": true,
            "rss_before_witness": (before.peak_rss_bytes), "rss_after_witness": rss_after_witness,
            "rss_after_prove": (after.peak_rss_bytes), "rss_after_verify": rss_after_verify,
            "load_milli_before": (before.load_milli), "load_milli_after": (after.load_milli),
            "thermal_before": (before.thermal.as_str()), "thermal_after": (after.thermal.as_str()),
        }));
    }
    let process_after = ProcessSnapshot::capture().expect("valid final resource probes");
    let scratch = SharedMemoryBudget::process_default();
    assert_eq!(scratch.in_use_bytes(), 0, "all MSM scratch released");
    assert!(scratch.peak_bytes() <= scratch.limit_bytes());
    let report = norito::json!({
        "schema": "kagemusha.m3.process.v1", "gate": gate, "k": K,
        "shape": (shape_line(&cs)), "workers": workers,
        "fixed_after_selector_compression": (key_cs.num_fixed_columns()),
        "fixed_commitments": (pk.vk().fixed_commitments().len()),
        "compiled_nodes": (compiled.node_count()), "compiled_gate_polys": (compiled.gate_count()),
        "descriptor_digest": (hex(pk.vk().descriptor_digest())),
        "descriptor_hash": "blake2b256-pipa-v2-circdesc", "transcript_profile": "pipa-r",
        "binary_sha256": binary_sha256, "seed": seed,
        "witness_api": "owned", "coset_cache": "on_demand",
        "quotient_workspace": "caller_owned",
        "quotient_workspace_budget_bytes": QUOTIENT_WORKSPACE_BYTES,
        "quotient_workspace_allocated_bytes": (quotient_workspace.allocated_bytes()),
        "commitment_tables": false, "msm_kernel_budget_bytes": (64_u64 << 20),
        "msm_process_budget_bytes": (iroha_pasta::msm::PROCESS_MSM_SCRATCH_BYTES),
        "msm_process_peak_bytes": (scratch.peak_bytes()),
        "msm_process_retained_bytes": (scratch.in_use_bytes()),
        "params_source": params_source, "params_ns": params_ns, "keygen_ns": keygen_ns,
        "rss_after_params": rss_after_params, "rss_after_keygen": rss_after_keygen,
        "peak_rss_bytes": (process_after.peak_rss_bytes),
        "peak_rss_source": "kernel_lifetime_high_water",
        "process_cpu_ns": (process_after.cpu_since(process_before).expect("monotonic process CPU")),
        "thermal_before": (process_before.thermal.as_str()),
        "thermal_after": (process_after.thermal.as_str()), "samples": samples,
    });
    println!(
        "M3_GATE_JSON {}",
        norito::json::to_json(&report).expect("public report")
    );
}

// ---------------------------------------------------------------------------
// G3.6: the Q leaf filled with the P-256 and SHA-256 chips.
// ---------------------------------------------------------------------------

/// Freeze all four workload descriptors from actual keys before qualification.
#[test]
#[ignore = "key generation for four k=16 qualification workloads; run in release"]
fn qualification_candidate_layouts() {
    record_layout::<Pallas, _>("G3.6/q_leaf_chips", &q_leaf(Q_VARIABLE, Q_FIXED, 60));
    record_layout::<Pallas, _>(
        "G3.6/q_exact_shape",
        &ExactCircuit::<Fq>::new(Q_SHAPE, ExactCircuit::<Fq>::usable_rows(Q_SHAPE, K), 66),
    );
    record_layout::<Vesta, _>("G3.7/a_imt_load", &a_load(70));
    record_layout::<Vesta, _>(
        "G3.7/a_exact_shape",
        &ExactCircuit::<Fp>::new(A_SHAPE, ExactCircuit::<Fp>::usable_rows(A_SHAPE, K), 77),
    );
}

/// A uniform nonzero scalar below `n`.
fn random_scalar(rng: &mut ChaCha20Rng) -> [u64; 4] {
    loop {
        let words = core::array::from_fn(|_| rng.next_u64());
        if words_lt(&words, &N) && !words_is_zero(&words) {
            return words;
        }
    }
}

/// `-s mod n` when `s` is high.
fn low_s(s: &[u64; 4]) -> [u64; 4] {
    if words_cmp(s, &HALF_N) == core::cmp::Ordering::Greater {
        ORDER.neg(s)
    } else {
        *s
    }
}

/// ECDSA over the prehash `e` with `nonce` under `secret` (not normalized).
fn sign(secret: &[u64; 4], nonce: &[u64; 4], e: &[u64; 4]) -> Option<([u64; 4], [u64; 4])> {
    let point = native::mul(&Affine::GENERATOR, nonce)?;
    let r = ORDER.reduce_once(&point.x);
    if words_is_zero(&r) {
        return None;
    }
    let e = ORDER.reduce_once(e);
    let s = ORDER.mul(
        &ORDER.inverse(nonce),
        &ORDER.add(&e, &ORDER.mul(&r, secret)),
    );
    (!words_is_zero(&s)).then_some((r, s))
}

/// The public key of `secret`.
fn public_key(secret: &[u64; 4]) -> Affine {
    native::mul(&Affine::GENERATOR, secret).expect("nonzero key")
}

/// The message scalar of a Poseidon digest: SHA-256 of its 32-byte
/// canonical encoding, big-endian.
fn message_of(digest: &Fp) -> [u64; 4] {
    words_from_be(&sha256_of_digest(digest))
}

/// One P-256 verification of the Q leaf: a signature over a Poseidon digest
/// under a witness key (`key`) or the configured fixed key (`None`).
#[derive(Clone, Debug)]
struct QCase {
    mode: VerifyMode,
    key: Option<Affine>,
    digest: Fp,
    r: [u64; 4],
    s: [u64; 4],
}

impl QCase {
    /// A valid low-S signature by `secret` over a random digest.
    fn signed(rng: &mut ChaCha20Rng, secret: &[u64; 4], mode: VerifyMode, fixed: bool) -> Self {
        let digest = Fp::random(&mut *rng);
        let e = message_of(&digest);
        loop {
            if let Some((r, s)) = sign(secret, &random_scalar(rng), &e) {
                return Self {
                    mode,
                    key: (!fixed).then(|| public_key(secret)),
                    digest,
                    r,
                    s: low_s(&s),
                };
            }
        }
    }

    /// The native verdict.
    fn native(&self, fixed_keys: &[Affine]) -> bool {
        let key = self.key.unwrap_or(fixed_keys[0]);
        verify_prehashed(&message_of(&self.digest), &self.r, &self.s, &key)
    }
}

/// Configuration-time parameters of the Q leaf.
#[derive(Clone, Debug, Default)]
struct QParams {
    fixed_keys: Vec<Affine>,
    cases: usize,
}

/// The Q leaf in the 17-column layout of `iroha_plonk_gadgets::q_leaf`:
/// every case's message hashed first (SHA-256 rows from row 0 on the ten
/// foreign-field columns and three of its own, the window lookups on the
/// glue columns beside them), then the verifications on the foreign-field
/// and glue rows above them; the verdict bits are the public instance.
#[derive(Clone, Debug)]
struct QLeaf {
    params: QParams,
    cases: Vec<QCase>,
    known: bool,
}

/// Advice column groups of the Q leaf (configuration order): the
/// foreign-field columns (also SHA-256 below the split), the glue columns
/// (also the window lookups below the split and the dynamic tables above
/// the shared table's rows) and the SHA-only columns.
const Q_GROUPS: [(&str, Range<usize>); 3] = [
    ("ff_and_sha", 0..FF_ADVICE_COLUMNS),
    ("glue_and_window", FF_ADVICE_COLUMNS..FF_ADVICE_COLUMNS + 4),
    ("sha_only", FF_ADVICE_COLUMNS + 4..Q_LEAF_ADVICE_COLUMNS),
];

impl QLeaf {
    fn new(fixed_keys: Vec<Affine>, cases: Vec<QCase>) -> Self {
        Self {
            params: QParams {
                fixed_keys,
                cases: cases.len(),
            },
            cases,
            known: true,
        }
    }

    /// The public instance: the native verdict bits.
    fn public(&self) -> Vec<Fq> {
        self.cases
            .iter()
            .map(|case| Fq::from(u64::from(case.native(&self.params.fixed_keys))))
            .collect()
    }
}

impl Circuit<Fq> for QLeaf {
    type Config = (QLeafConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = QParams;

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }

    fn params(&self) -> QParams {
        self.params.clone()
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        Self::configure_with_params(meta, QParams::default())
    }

    fn configure_with_params(meta: &mut ConstraintSystem<Fq>, params: QParams) -> Self::Config {
        let advice: [Column<Advice>; Q_LEAF_ADVICE_COLUMNS] =
            core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let leaf = QLeafConfig::configure(meta, advice, constants, &params.fixed_keys);
        let instance = meta.instance_column(params.cases);
        meta.enable_equality(instance);
        (leaf, instance)
    }

    fn synthesize(
        &self,
        (leaf, instance): Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        leaf.load_tables(&mut layouter)?;
        let QLeafChips {
            mut sha,
            mut ff,
            mut glue,
            p256: mut chip,
        } = leaf.chips::<Fq>(sha_rows(self.cases.len()))?;
        let known = self.known;
        let words = |words: [u64; 4]| {
            if known {
                Value::known(words)
            } else {
                Value::unknown()
            }
        };
        let order = ForeignModulus::P256_ORDER;
        let base = ForeignModulus::P256_BASE;
        let bits = layouter.assign_region(
            || "q leaf",
            |mut region| {
                let mut digests = Vec::with_capacity(self.cases.len());
                for case in &self.cases {
                    let m = Fq::from_repr(case.digest.to_repr())
                        .into_option()
                        .ok_or(Error::Synthesis)?;
                    let m = if known {
                        Value::known(m)
                    } else {
                        Value::unknown()
                    };
                    let cell = glue.witness(&mut region, m)?;
                    digests.push(sha.hash_digest::<Fp>(&mut region, &cell)?);
                }
                let mut bits = Vec::with_capacity(self.cases.len());
                for (case, digest) in self.cases.iter().zip(&digests) {
                    let sig_r = ff.witness(&mut region, order, words(case.r))?;
                    let sig_s = ff.witness(&mut region, order, words(case.s))?;
                    let message = chip.message_scalar(&mut ff, &mut glue, &mut region, digest)?;
                    let bit = match case.key {
                        Some(key) => {
                            let key_x = ff.witness(&mut region, base, words(key.x))?;
                            let key_y = ff.witness(&mut region, base, words(key.y))?;
                            let key = P256Key::Variable {
                                x: &key_x,
                                y: &key_y,
                            };
                            chip.verify(
                                &mut ff,
                                &mut glue,
                                &mut region,
                                case.mode,
                                key,
                                &message,
                                &sig_r,
                                &sig_s,
                            )?
                        }
                        None => chip.verify(
                            &mut ff,
                            &mut glue,
                            &mut region,
                            case.mode,
                            P256Key::Fixed(0),
                            &message,
                            &sig_r,
                            &sig_s,
                        )?,
                    };
                    bits.push(bit);
                }
                Ok(bits)
            },
        )?;
        for (row, bit) in bits.iter().enumerate() {
            layouter.constrain_instance(bit.cell(), instance, row)?;
        }
        Ok(())
    }
}

/// Witness-key verifications in the measured Q leaf (each 10,003
/// foreign-field rows plus a 2,094-row SHA-256 block; five is the most a
/// leaf with a fixed-key verification holds, `q_leaf` module documentation).
const Q_VARIABLE: usize = 5;
/// Fixed-key verifications in the measured Q leaf.
const Q_FIXED: usize = 1;

/// The measured Q leaf: [`Q_VARIABLE`] witness-key verifications (soft and
/// hard alternately) and [`Q_FIXED`] fixed-key verifications (hard), every
/// signature valid, every message hashed in circuit.
fn q_leaf(variable: usize, fixed: usize, seed: u64) -> QLeaf {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let issuer = random_scalar(&mut rng);
    let mut cases = Vec::with_capacity(variable + fixed);
    for index in 0..variable {
        let mode = if index % 2 == 0 {
            VerifyMode::Soft
        } else {
            VerifyMode::Hard
        };
        let secret = random_scalar(&mut rng);
        cases.push(QCase::signed(&mut rng, &secret, mode, false));
    }
    for _ in 0..fixed {
        cases.push(QCase::signed(&mut rng, &issuer, VerifyMode::Hard, true));
    }
    QLeaf::new(vec![public_key(&issuer)], cases)
}

// ---------------------------------------------------------------------------
// G3.7: the A aggregator filled with IMT-like Poseidon paths.
// ---------------------------------------------------------------------------

/// Test-only domain word of the IMT-like leaves (no protocol domain).
const D_LEAF: u64 = u64::from_le_bytes(*b"m3imtlf1");
/// Test-only domain word of the IMT-like inner nodes.
const D_NODE: u64 = u64::from_le_bytes(*b"m3imtnd1");
/// Lanes of the measured A load.
const A_LANES: usize = 6;
/// Depth of the measured IMT-like paths (the design's IMT depth).
const A_DEPTH: usize = 32;
/// Limb widths of the three running-sum tables of the measured A load.
const A_RANGE_BITS: [usize; 3] = [15, 12, 8];

/// One IMT-like non-membership path: the low leaf `(low, next, next_index)`
/// with `low < key < next`, hashed at `index` up `siblings` to the root.
#[derive(Clone, Debug)]
struct ImtPath {
    low: Fp,
    key: Fp,
    next: Fp,
    next_index: u64,
    index: u32,
    siblings: Vec<Fp>,
}

impl ImtPath {
    /// A random path of `depth` levels whose gaps are below `2^100`.
    fn random(rng: &mut ChaCha20Rng, depth: usize) -> Self {
        let gap = |rng: &mut ChaCha20Rng| {
            Fp::from_u128((u128::from(rng.next_u64()) << 36) | u128::from(rng.next_u32()))
        };
        let low = Fp::from_u128((u128::from(rng.next_u64()) << 64) | u128::from(rng.next_u64()));
        let key = low + Fp::ONE + gap(rng);
        let next = key + Fp::ONE + gap(rng);
        let mask = if depth >= 32 {
            u32::MAX
        } else {
            (1_u32 << depth) - 1
        };
        Self {
            low,
            key,
            next,
            next_index: rng.next_u64(),
            index: rng.next_u32() & mask,
            siblings: (0..depth).map(|_| Fp::random(&mut *rng)).collect(),
        }
    }

    /// Native reference: the root.
    fn root(&self) -> Fp {
        let mut node = hash_with_domain(D_LEAF, &[self.low, self.next, Fp::from(self.next_index)]);
        for (level, sibling) in self.siblings.iter().enumerate() {
            node = if (self.index >> level) & 1 == 1 {
                hash_with_domain(D_NODE, &[*sibling, node])
            } else {
                hash_with_domain(D_NODE, &[node, *sibling])
            };
        }
        node
    }

    /// Permutations of one path: the folded leaf hash and two per level.
    const fn permutations(depth: usize) -> usize {
        2 + 2 * depth
    }
}

/// Configuration-time parameters of the A load.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AParams {
    lanes: usize,
    range_bits: [usize; 3],
    paths: usize,
}

/// The A load: per lane a run of IMT-like paths, then (when `fill` is set)
/// 2-to-1 node hashes until the lane holds `fill` permutations; the roots are
/// the public instance.
#[derive(Clone, Debug)]
struct ALoad {
    params: AParams,
    lanes: Vec<Vec<ImtPath>>,
    fill: Option<usize>,
    known: bool,
}

/// The configuration of the A load.
#[derive(Clone, Debug)]
struct AConfig {
    glue: GlueConfig,
    sponges: Vec<SpongeConfig<Fp>>,
    ranges: [RunningSumConfig; 3],
    instance: Column<Instance>,
}

impl ALoad {
    fn new(range_bits: [usize; 3], lanes: Vec<Vec<ImtPath>>, fill: Option<usize>) -> Self {
        Self {
            params: AParams {
                lanes: lanes.len(),
                range_bits,
                paths: lanes.iter().map(Vec::len).sum(),
            },
            lanes,
            fill,
            known: true,
        }
    }

    /// The public instance: every root, lane by lane.
    fn public(&self) -> Vec<Fp> {
        self.lanes.iter().flatten().map(ImtPath::root).collect()
    }

    /// Advice column groups (configuration order: glue, lanes, ranges).
    fn groups(&self) -> Vec<(String, Range<usize>)> {
        let lanes = 4 + 4 * self.params.lanes;
        vec![
            ("glue".to_owned(), 0..4),
            ("lanes".to_owned(), 4..lanes),
            ("ranges".to_owned(), lanes..lanes + 3),
        ]
    }
}

/// Lays out one path and returns its root: witnesses, the ordering range
/// checks, the leaf hash, and per level a boolean, a sibling, two selects, a
/// node hash and the index recomposition.
fn imt_path(
    glue: &mut GlueChip<Fp>,
    sponge: &mut SpongeChip<Fp>,
    ranges: &mut [RunningSumChip<Fp>],
    region: &mut iroha_plonk::Region<'_, Fp>,
    path: &ImtPath,
    known: bool,
) -> Result<Word<Fp>, Error> {
    let value = |x: Fp| {
        if known {
            Value::known(x)
        } else {
            Value::unknown()
        }
    };
    let words = glue.witnesses(
        region,
        &[
            value(path.low),
            value(path.key),
            value(path.next),
            value(Fp::from(path.next_index)),
            value(Fp::from(u64::from(path.index))),
        ],
    )?;
    let [low, key, next, next_index, index]: [Word<Fp>; 5] =
        words.try_into().map_err(|_| Error::Synthesis)?;
    // low < key < next as 128-bit gaps, the index widths.
    let gap = glue.sub(region, &key, &low)?;
    let gap = glue.add_constant(region, &gap, -Fp::ONE)?;
    ranges[0].range_check(region, &gap, 128)?;
    let gap = glue.sub(region, &next, &key)?;
    let gap = glue.add_constant(region, &gap, -Fp::ONE)?;
    ranges[1].range_check(region, &gap, 128)?;
    ranges[2].range_check(region, &next_index, 64)?;
    ranges[2].range_check(region, &index, 32)?;
    let mut node = sponge.hash_words(region, D_LEAF, &[low, next, next_index])?;
    let mut recomposed: Option<Word<Fp>> = None;
    for (level, sibling) in path.siblings.iter().enumerate() {
        let bit = glue.boolean(
            region,
            if known {
                Value::known((path.index >> level) & 1 == 1)
            } else {
                Value::unknown()
            },
        )?;
        let sibling = glue.witness(region, value(*sibling))?;
        let left = glue.select(region, &bit, &sibling, &node)?;
        let right = glue.select(region, &bit, &node, &sibling)?;
        node = sponge.hash_words(region, D_NODE, &[left, right])?;
        let weight = Fp::from(1_u64 << level);
        recomposed = Some(match recomposed {
            None => glue.linear(region, &[(weight, bit.word())], Fp::ZERO)?,
            Some(sum) => glue.linear(region, &[(Fp::ONE, &sum), (weight, bit.word())], Fp::ZERO)?,
        });
    }
    if let Some(recomposed) = recomposed {
        GlueChip::assert_equal(region, &recomposed, &index)?;
    }
    Ok(node)
}

impl Circuit<Fp> for ALoad {
    type Config = AConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = AParams;

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }

    fn params(&self) -> AParams {
        self.params
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> AConfig {
        Self::configure_with_params(
            meta,
            AParams {
                lanes: 1,
                range_bits: [8; 3],
                paths: 0,
            },
        )
    }

    fn configure_with_params(meta: &mut ConstraintSystem<Fp>, params: AParams) -> AConfig {
        let glue_columns: [Column<Advice>; 4] = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, glue_columns, constants);
        let round_constants = RoundConstantColumns::allocate(meta);
        let folded = [(D_LEAF, 3), (D_NODE, 2)];
        // Every lane performs the same number and sequence of permutations.
        // Sharing their four round schedules reduces fixed columns without
        // changing the actual IMT path workload or its public roots.
        let shared = SharedRoundSelectors::allocate(meta);
        let sponges = (0..params.lanes)
            .map(|_| {
                let lane = Pow5Columns::allocate(meta);
                SpongeConfig::configure_with_shared_round_selectors(
                    meta,
                    lane,
                    round_constants,
                    &folded,
                    shared,
                )
            })
            .collect();
        let ranges = params.range_bits.map(|bits| {
            let z = meta.advice_column();
            RunningSumConfig::configure(meta, z, LimbBits::new(bits).expect("limb width"))
        });
        let instance = meta.instance_column(params.paths);
        meta.enable_equality(instance);
        AConfig {
            glue,
            sponges,
            ranges,
            instance,
        }
    }

    fn synthesize(&self, config: AConfig, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut ranges: Vec<RunningSumChip<Fp>> = config
            .ranges
            .iter()
            .map(|c| RunningSumChip::new(*c))
            .collect();
        for range in &ranges {
            range.load_table(&mut layouter)?;
        }
        let mut glue = GlueChip::new(config.glue);
        let mut sponges: Vec<SpongeChip<Fp>> = config
            .sponges
            .iter()
            .cloned()
            .map(SpongeChip::new)
            .collect();
        let roots = layouter.assign_region(
            || "imt load",
            |mut region| {
                let mut roots = Vec::with_capacity(self.params.paths);
                for (sponge, paths) in sponges.iter_mut().zip(&self.lanes) {
                    let mut last = None;
                    for path in paths {
                        let root = imt_path(
                            &mut glue,
                            sponge,
                            &mut ranges,
                            &mut region,
                            path,
                            self.known,
                        )?;
                        last = Some(root.clone());
                        roots.push(root);
                    }
                    if let Some(fill) = self.fill {
                        let mut node = last.ok_or(Error::Synthesis)?;
                        while sponge.lane().next_block() + 2 <= fill {
                            node = sponge.hash_words(
                                &mut region,
                                D_NODE,
                                &[node.clone(), node.clone()],
                            )?;
                        }
                        if sponge.lane().next_block() < fill {
                            sponge.hash_raw(&mut region, &[])?;
                        }
                    }
                }
                Ok(roots)
            },
        )?;
        for (row, root) in roots.iter().enumerate() {
            layouter.constrain_instance(root.cell(), config.instance, row)?;
        }
        Ok(())
    }
}

/// The usable rows of an A load with `lanes` lanes at `k = 16`.
fn a_usable_rows(lanes: usize) -> usize {
    let probe = ALoad::new(A_RANGE_BITS, vec![Vec::new(); lanes], None);
    let (cs, _) = configure(&probe).expect("configure");
    cs.usable_rows(K).expect("usable rows")
}

/// The measured A load: [`A_LANES`] lanes, each with as many depth-32 paths
/// as fit, then filled to capacity with node hashes.
fn a_load(seed: u64) -> ALoad {
    let capacity = a_usable_rows(A_LANES) / iroha_plonk_gadgets::pow5_fq::ROWS_PER_PERMUTATION;
    let per_lane = capacity / ImtPath::permutations(A_DEPTH);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let lanes = (0..A_LANES)
        .map(|_| {
            (0..per_lane)
                .map(|_| ImtPath::random(&mut rng, A_DEPTH))
                .collect()
        })
        .collect();
    ALoad::new(A_RANGE_BITS, lanes, Some(capacity))
}

// ---------------------------------------------------------------------------
// Exact design shapes: degree-6 S-box chains and range lookups.
// ---------------------------------------------------------------------------

/// A circuit shape: column and argument counts. `equality` counts every
/// permutation column, the instance column included.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ExactShape {
    advice: usize,
    fixed: usize,
    equality: usize,
    lookups: usize,
    table_bits: usize,
}

/// The design's Q shape (section 2.1: 22 / ~32 / 8 / 3).
const Q_SHAPE: ExactShape = ExactShape {
    advice: 22,
    fixed: 32,
    equality: 8,
    lookups: 3,
    table_bits: 15,
};

/// The design's A shape (section 2.1: 32 / ~44 / 10 / 3).
const A_SHAPE: ExactShape = ExactShape {
    advice: 32,
    fixed: 44,
    equality: 10,
    lookups: 3,
    table_bits: 15,
};

impl ExactShape {
    /// Chain columns: every advice column that is not a lookup input.
    const fn chain(&self) -> usize {
        self.advice - self.lookups
    }

    /// Coefficient columns: every fixed column but the two enables and the
    /// tables.
    const fn coefficients(&self) -> usize {
        self.fixed - 2 - self.lookups
    }
}

/// `SplitMix64` of `seed`, `a` and `b` (deterministic filler values).
fn mix(seed: u64, a: usize, b: usize) -> u64 {
    let a = u64::try_from(a).unwrap_or(u64::MAX);
    let b = u64::try_from(b).unwrap_or(u64::MAX);
    let mut z = seed ^ a.rotate_left(40) ^ b ^ 0x9e37_79b9_7f4a_7c15;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Fills a shape on `rows` rows. Gate `i` of the chain is
/// `enable (c_(i+1) - (c_i + K_a(i))^5 - K_b(i) c_i)` (degree 6) with the
/// coefficient columns `K` assigned round-robin; row `r + 1` starts from the
/// last chain value of row `r` (a copy); lookup `j` checks
/// `lookup_enable t_j` against a `2^table_bits`-row range table; the last
/// chain value is the public instance.
#[derive(Clone, Debug)]
struct ExactCircuit<F> {
    shape: ExactShape,
    rows: usize,
    seed: u64,
    /// Every lookup input at the table's top value (so a `+1` tamper leaves
    /// the table); random values otherwise.
    saturated: bool,
    known: bool,
    _field: core::marker::PhantomData<F>,
}

/// The configuration of [`ExactCircuit`].
#[derive(Clone, Debug)]
struct ExactConfig {
    chain: Vec<Column<Advice>>,
    inputs: Vec<Column<Advice>>,
    enable: Column<Fixed>,
    lookup_enable: Column<Fixed>,
    tables: Vec<TableColumn>,
    coefficients: Vec<Column<Fixed>>,
    instance: Column<Instance>,
}

impl<F: PastaField> ExactCircuit<F> {
    fn new(shape: ExactShape, rows: usize, seed: u64) -> Self {
        Self {
            shape,
            rows,
            seed,
            saturated: false,
            known: true,
            _field: core::marker::PhantomData,
        }
    }

    /// The usable rows of `shape` at `k`.
    fn usable_rows(shape: ExactShape, k: u32) -> usize {
        let (cs, _) = configure(&Self::new(shape, 0, 0)).expect("configure");
        cs.usable_rows(k).expect("usable rows")
    }

    /// The coefficient columns of gate `gate`: `(additive, multiplicative)`.
    const fn gate_coefficients(&self, gate: usize) -> (usize, usize) {
        let columns = self.shape.coefficients();
        (gate % columns, (self.shape.chain() - 1 + gate) % columns)
    }

    /// The coefficient at `(column, row)`.
    fn coefficient(&self, column: usize, row: usize) -> F {
        F::from(mix(self.seed, column, row))
    }

    /// The lookup input `j` at `row`.
    fn input(&self, lookup: usize, row: usize) -> u64 {
        let top = (1_u64 << self.shape.table_bits) - 1;
        if self.saturated {
            top
        } else {
            mix(!self.seed, lookup, row) & top
        }
    }

    /// The chain values of `row` entering with `first`.
    fn chain_row(&self, row: usize, first: F) -> Vec<F> {
        let mut values = Vec::with_capacity(self.shape.chain());
        values.push(first);
        for gate in 0..self.shape.chain() - 1 {
            let (additive, multiplicative) = self.gate_coefficients(gate);
            let current = values[gate];
            let shifted = current + self.coefficient(additive, row);
            let next = shifted.square().square() * shifted
                + self.coefficient(multiplicative, row) * current;
            values.push(next);
        }
        values
    }

    /// The first chain value of row 0.
    fn start(&self) -> F {
        F::from(self.seed) + F::ONE
    }

    /// Native reference: the last chain value of the last row.
    fn output(&self) -> F {
        let mut carry = self.start();
        for row in 0..self.rows {
            carry = *self.chain_row(row, carry).last().expect("nonempty chain");
        }
        carry
    }
}

impl<F: PastaField> Circuit<F> for ExactCircuit<F> {
    type Config = ExactConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ExactShape;

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }

    fn params(&self) -> ExactShape {
        self.shape
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> ExactConfig {
        Self::configure_with_params(
            meta,
            ExactShape {
                advice: 4,
                fixed: 6,
                equality: 3,
                lookups: 1,
                table_bits: 4,
            },
        )
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, shape: ExactShape) -> ExactConfig {
        assert!(shape.chain() >= 2, "a chain needs two columns");
        assert!(
            shape.coefficients() >= 1,
            "a gate needs a coefficient column"
        );
        assert!(
            (3..=shape.chain() + 1).contains(&shape.equality),
            "equality counts the instance and both chain ends"
        );
        let chain: Vec<Column<Advice>> = (0..shape.chain()).map(|_| meta.advice_column()).collect();
        let inputs: Vec<Column<Advice>> =
            (0..shape.lookups).map(|_| meta.advice_column()).collect();
        let enable = meta.fixed_column();
        let lookup_enable = meta.fixed_column();
        let tables: Vec<TableColumn> = (0..shape.lookups)
            .map(|_| meta.lookup_table_column())
            .collect();
        let coefficients: Vec<Column<Fixed>> = (0..shape.coefficients())
            .map(|_| meta.fixed_column())
            .collect();
        let probe = Self::new(shape, 0, 0);
        for gate in 0..shape.chain() - 1 {
            let (additive, multiplicative) = probe.gate_coefficients(gate);
            let (current, next) = (chain[gate], chain[gate + 1]);
            let (additive, multiplicative) = (coefficients[additive], coefficients[multiplicative]);
            meta.create_gate("exact s-box chain", |cells| {
                let enable = cells.query_fixed(enable, Rotation::cur());
                let current = cells.query_advice(current, Rotation::cur());
                let next = cells.query_advice(next, Rotation::cur());
                let additive = cells.query_fixed(additive, Rotation::cur());
                let multiplicative = cells.query_fixed(multiplicative, Rotation::cur());
                let shifted = current.clone() + additive;
                let fifth = shifted.clone().square().square() * shifted;
                vec![enable * (next - fifth - multiplicative * current)]
            });
        }
        for (input, table) in inputs.iter().zip(&tables) {
            meta.lookup("exact range", |cells| {
                let enable = cells.query_fixed(lookup_enable, Rotation::cur());
                let input = cells.query_advice(*input, Rotation::cur());
                vec![(enable * input, *table)]
            });
        }
        let instance = meta.instance_column(1);
        meta.enable_equality(instance);
        meta.enable_equality(chain[0]);
        meta.enable_equality(chain[shape.chain() - 1]);
        for column in &chain[1..shape.equality - 2] {
            meta.enable_equality(*column);
        }
        ExactConfig {
            chain,
            inputs,
            enable,
            lookup_enable,
            tables,
            coefficients,
            instance,
        }
    }

    fn synthesize(&self, config: ExactConfig, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let table_rows = 1_usize << self.shape.table_bits;
        for table in &config.tables {
            layouter.assign_table(
                || "exact range table",
                |mut cells| {
                    for row in 0..table_rows {
                        let value = F::from(u64::try_from(row).map_err(|_| Error::Synthesis)?);
                        cells.assign_cell(|| "range", *table, row, || Value::known(value))?;
                    }
                    Ok(())
                },
            )?;
        }
        let last = layouter.assign_region(
            || "exact shape",
            |mut region| {
                let mut carry = self.start();
                let mut previous: Option<Cell> = None;
                for row in 0..self.rows {
                    region.assign_fixed(config.enable, row, F::ONE)?;
                    region.assign_fixed(config.lookup_enable, row, F::ONE)?;
                    for (index, column) in config.coefficients.iter().enumerate() {
                        region.assign_fixed(*column, row, self.coefficient(index, row))?;
                    }
                    let values = self.known.then(|| self.chain_row(row, carry));
                    let mut cells = Vec::with_capacity(config.chain.len());
                    for (index, column) in config.chain.iter().enumerate() {
                        let value = values
                            .as_ref()
                            .map_or_else(Value::unknown, |values| Value::known(values[index]));
                        cells.push(region.assign_advice(*column, row, value)?.cell());
                    }
                    for (lookup, column) in config.inputs.iter().enumerate() {
                        let value = if self.known {
                            Value::known(F::from(self.input(lookup, row)))
                        } else {
                            Value::unknown()
                        };
                        region.assign_advice(*column, row, value)?;
                    }
                    if let Some(previous) = previous {
                        region.constrain_equal(previous, cells[0])?;
                    }
                    previous = cells.last().copied();
                    if let Some(values) = values {
                        carry = *values.last().ok_or(Error::Synthesis)?;
                    }
                }
                previous.ok_or(Error::Synthesis)
            },
        )?;
        layouter.constrain_instance(last, config.instance, 0)
    }
}

// ---------------------------------------------------------------------------
// Tests of the harness pieces (debug-sized).
// ---------------------------------------------------------------------------

#[test]
fn qualification_workers_are_explicit_and_actual() {
    assert_eq!(worker_count(None), Ok(1));
    for count in [1, 4] {
        assert_eq!(worker_count(Some(&count.to_string())), Ok(count));
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(count)
            .build()
            .unwrap();
        assert_eq!(pool.install(rayon::current_num_threads), count);
    }
    for bad in ["", "0", "2", "default", "-1"] {
        assert!(worker_count(Some(bad)).is_err());
    }
}

#[test]
fn qualification_records_the_executable_and_checked_duration() {
    assert_eq!(hex(&[0, 1, 0xfe, 0xff]), "0001feff");
    assert_eq!(binary_digest().len(), 64);
    assert_eq!(binary_digest(), binary_digest());
    assert!(elapsed_ns(Instant::now()) < 1_000_000_000);
}

#[test]
fn column_use_counts_cells_and_extent() {
    let flags = vec![
        vec![false, true, true, false],
        vec![false, false, false, true],
        vec![false; 4],
    ];
    assert_eq!(column_use(&flags, 0..2), (3, 3));
    assert_eq!(column_use(&flags, 2..3), (0, 0));
}

#[test]
fn harness_signatures_verify_natively_and_with_the_p256_crate() {
    use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier as _};

    let leaf = q_leaf(2, 2, 1);
    for case in &leaf.cases {
        assert!(case.native(&leaf.params.fixed_keys));
        assert!(words_cmp(&case.s, &HALF_N) != core::cmp::Ordering::Greater);
        let key = case.key.unwrap_or(leaf.params.fixed_keys[0]);
        let mut sec1 = vec![4_u8];
        sec1.extend_from_slice(&native::words_to_be(&key.x));
        sec1.extend_from_slice(&native::words_to_be(&key.y));
        let verifying = VerifyingKey::from_sec1_bytes(&sec1).expect("key");
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&native::words_to_be(&case.r));
        bytes[32..].copy_from_slice(&native::words_to_be(&case.s));
        let signature = Signature::from_slice(&bytes).expect("signature");
        let prehash = sha256_of_digest(&case.digest);
        assert!(verifying.verify_prehash(&prehash, &signature).is_ok());
        // Another digest fails.
        let other = sha256_of_digest(&(case.digest + Fp::ONE));
        assert!(verifying.verify_prehash(&other, &signature).is_err());
    }
    assert_eq!(leaf.public(), vec![Fq::ONE; 4]);
}

/// A fixed-key leaf with a valid hard case and an invalid soft case (`r`
/// replaced by `0`): satisfied exactly with the native bits `[1, 0]`.
#[test]
fn q_leaf_matches_native_verdicts() {
    let mut leaf = q_leaf(0, 2, 2);
    leaf.cases[1].mode = VerifyMode::Soft;
    leaf.cases[1].r = [0; 4];
    leaf.params.cases = leaf.cases.len();
    let public = leaf.public();
    assert_eq!(public, vec![Fq::ONE, Fq::ZERO]);
    let check = |leaf: &QLeaf, public: &[Fq]| {
        check_circuit(leaf, K, &[public.to_vec()], CheckMode::Strict)
            .expect("synthesis")
            .is_satisfied()
    };
    assert!(check(&leaf, &public));
    assert!(
        !check(&leaf, &[Fq::ONE, Fq::ONE]),
        "flipped soft bit accepted"
    );
    // The invalid signature in hard mode is unsatisfiable.
    leaf.cases[1].mode = VerifyMode::Hard;
    assert!(
        !check(&leaf, &[Fq::ONE, Fq::ONE]),
        "invalid hard signature accepted"
    );
}

/// The IMT-like load at a small shape: the roots match the native reference,
/// the lane fill reaches its target, and wrong roots or out-of-order keys
/// are rejected.
#[test]
fn a_load_roots_match_native_and_reject_forgeries() {
    let k = 10;
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let paths: Vec<ImtPath> = (0..2).map(|_| ImtPath::random(&mut rng, 4)).collect();
    let check = |load: &ALoad, public: &[Fp]| {
        check_circuit(load, k, &[public.to_vec()], CheckMode::Strict)
            .expect("synthesis")
            .is_satisfied()
    };
    let load = ALoad::new([8, 8, 8], vec![paths.clone()], None);
    let public = load.public();
    assert!(check(&load, &public));
    let mut wrong = public.clone();
    wrong[1] += Fp::ONE;
    assert!(!check(&load, &wrong), "wrong root accepted");
    // One path (10 permutations) filled to 13: a node hash, then a raw one.
    let one = ALoad::new([8, 8, 8], vec![paths[..1].to_vec()], Some(13));
    let one_public = one.public();
    assert!(check(&one, &one_public));
    let synthesized = synthesize(&one, k, Some(&[one_public][..])).expect("synthesis");
    let lane_rows = column_use(synthesized.tables.advice_assigned(), 4..8).1;
    assert_eq!(
        lane_rows,
        13 * iroha_plonk_gadgets::pow5_fq::ROWS_PER_PERMUTATION
    );
    // key >= next: the second gap underflows and leaves the range.
    let mut disordered = paths[..1].to_vec();
    disordered[0].key = disordered[0].next;
    let disordered = ALoad::new([8, 8, 8], vec![disordered], None);
    assert!(!check(&disordered, &disordered.public()));
    // key <= low: the first gap underflows.
    let mut below = paths[..1].to_vec();
    below[0].key = below[0].low;
    let below = ALoad::new([8, 8, 8], vec![below], None);
    assert!(!check(&below, &below.public()));
}

/// Every assigned cell of a small A load is pinned by a gate, a lookup or a
/// copy.
#[test]
fn a_load_every_cell_is_pinned() {
    let k = 9;
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let path = ImtPath::random(&mut rng, 1);
    // Four path permutations, a node hash and a raw hash of the fill.
    let load = ALoad::new([4, 4, 4], vec![vec![path]], Some(7));
    let public = load.public();
    let undetected = undetected_tampers(&load, k, &[public]).expect("honest witness accepted");
    assert!(undetected.is_empty(), "unpinned cells: {undetected:?}");
}

/// The exact-shape filler: the configured counts are exact, the output
/// matches the native recurrence, a wrong output is rejected, and every
/// assigned cell is pinned when the lookup inputs sit at the table's top.
#[test]
fn exact_shape_matches_its_counts_and_pins_every_cell() {
    let k = 7;
    let shape = ExactShape {
        advice: 6,
        fixed: 8,
        equality: 4,
        lookups: 2,
        table_bits: 4,
    };
    let rows = ExactCircuit::<Fp>::usable_rows(shape, k);
    let mut circuit = ExactCircuit::<Fp>::new(shape, rows, 9);
    let (cs, _) = configure(&circuit).expect("configure");
    assert_eq!(cs.num_advice_columns(), shape.advice);
    assert_eq!(cs.num_fixed_columns(), shape.fixed);
    assert_eq!(cs.permutation().columns().len(), shape.equality);
    assert_eq!(cs.lookups().len(), shape.lookups);
    assert_eq!(cs.degree(), 6);
    let public = vec![circuit.output()];
    let accepts = |circuit: &ExactCircuit<Fp>, public: &[Fp]| {
        check_circuit(circuit, k, &[public.to_vec()], CheckMode::Strict)
            .expect("synthesis")
            .is_satisfied()
    };
    assert!(accepts(&circuit, &public));
    assert!(!accepts(&circuit, &[public[0] + Fp::ONE]));
    circuit.saturated = true;
    let undetected = undetected_tampers(&circuit, k, &[public]).expect("honest witness accepted");
    assert!(undetected.is_empty(), "unpinned cells: {undetected:?}");
    // The design shapes configure with their exact counts.
    for shape in [Q_SHAPE, A_SHAPE] {
        let (cs, _) = configure(&ExactCircuit::<Fq>::new(shape, 0, 0)).expect("configure");
        assert_eq!(
            (
                cs.num_advice_columns(),
                cs.num_fixed_columns(),
                cs.permutation().columns().len(),
                cs.lookups().len(),
                cs.degree()
            ),
            (shape.advice, shape.fixed, shape.equality, shape.lookups, 6)
        );
    }
}

// ---------------------------------------------------------------------------
// The k = 16 measurements (release).
// ---------------------------------------------------------------------------

/// G3.6 inventory: the filled Q leaf synthesized and strictly checked.
#[test]
#[ignore = "k = 16 synthesis and strict check of the filled Q leaf; run in release"]
fn g3_6_q_leaf_shape() {
    let leaf = q_leaf(Q_VARIABLE, Q_FIXED, 60);
    let public = leaf.public();
    assert_eq!(public, vec![Fq::ONE; Q_VARIABLE + Q_FIXED]);
    let (cells, span) = inventory("q_leaf_chips", &leaf, &public, &Q_GROUPS);
    // The shared-table conditions on the key-generation tables (the
    // patterns are witness independent).
    let (_, (config, _)) = configure(&leaf).expect("configure");
    let keygen = synthesize(&leaf, K, None).expect("synthesis");
    assert_eq!(config.audit(&keygen.tables), Ok(()));
    assert_eq!(span, 64_238, "5 V + 1 F: 6 SHA blocks and the FF rows");
    // One verification of each kind alone, for the per-verification costs.
    let single_variable = q_leaf(1, 0, 61);
    let (variable_cells, variable_span) = inventory(
        "q_leaf_one_variable",
        &single_variable,
        &single_variable.public(),
        &Q_GROUPS,
    );
    let single_fixed = q_leaf(0, 1, 62);
    let (fixed_cells, fixed_span) = inventory(
        "q_leaf_one_fixed",
        &single_fixed,
        &single_fixed.public(),
        &Q_GROUPS,
    );
    println!(
        "M3_Q_LEAF verifications={Q_VARIABLE}+{Q_FIXED} cells={cells} span={span} \
         one_variable_with_sha=[cells={variable_cells} span={variable_span}] \
         one_fixed_with_sha=[cells={fixed_cells} span={fixed_span}]"
    );
}

/// The pinned-parameter cache of the harness: derivation, the cache write
/// and the load (SHA-256 against the pinned digest and the decoding of
/// every point) at `k = 16` for both curves, timed on the current thread
/// pool (`RAYON_NUM_THREADS`). Parameter setup precedes key generation and
/// the proof timers, so this is process start-up time only.
#[test]
#[ignore = "k = 16 parameter derivation and cache load; run in release"]
fn pinned_params_cache_load_time() {
    fn measure<C: PastaCurve>() {
        let path = params_cache_path::<C>(K);
        let _ = std::fs::remove_file(&path);
        let started = Instant::now();
        let (derived, source) = pinned_params::<C>(K);
        let derive_ms = started.elapsed().as_millis();
        assert_eq!(source, "derived");
        let bytes = std::fs::read(&path).expect("cache written");
        let started = Instant::now();
        let (loaded, source) = pinned_params::<C>(K);
        let load_ms = started.elapsed().as_millis();
        assert_eq!(source, "cache");
        assert_eq!(loaded, derived);
        // A corrupted cache is refused (and rewritten).
        let mut corrupted = bytes.clone();
        corrupted[100] ^= 1;
        assert!(PinnedParams::<C>::from_bytes(&corrupted).is_err());
        println!(
            "M3_PARAMS curve={} k={K} bytes={} derive_ms={derive_ms} cache_load_ms={load_ms} \
             threads={:?}",
            std::any::type_name::<C>(),
            bytes.len(),
            std::env::var("RAYON_NUM_THREADS").ok(),
        );
    }
    measure::<Pallas>();
    measure::<Vesta>();
}

/// G3.6: the filled Q leaf proved on Pallas.
#[test]
#[ignore = "k = 16 Pallas proof of the filled Q leaf; run in release"]
fn g3_6_q_leaf_proof() {
    let leaf = q_leaf(Q_VARIABLE, Q_FIXED, 60);
    let public = leaf.public();
    measure_proof::<Pallas, _>("G3.6/q_leaf_chips", &leaf, &public);
}

/// G3.6: the design's exact Q shape filled on every usable row, proved on
/// Pallas.
#[test]
#[ignore = "k = 16 Pallas proof of the exact Q shape; run in release"]
fn g3_6_q_exact_shape_proof() {
    let rows = ExactCircuit::<Fq>::usable_rows(Q_SHAPE, K);
    let circuit = ExactCircuit::<Fq>::new(Q_SHAPE, rows, 66);
    let public = vec![circuit.output()];
    measure_proof::<Pallas, _>("G3.6/q_exact_shape", &circuit, &public);
}

/// G3.7 inventory: the IMT-like A load synthesized and strictly checked.
#[test]
#[ignore = "k = 16 synthesis and strict check of the A load; run in release"]
fn g3_7_a_load_shape() {
    let load = a_load(70);
    let public = load.public();
    let groups = load.groups();
    let groups: Vec<(&str, Range<usize>)> = groups
        .iter()
        .map(|(name, columns)| (name.as_str(), columns.clone()))
        .collect();
    let (cells, span) = inventory("a_imt_load", &load, &public, &groups);
    println!(
        "M3_A_LOAD lanes={} paths={} depth={A_DEPTH} cells={cells} span={span}",
        load.params.lanes, load.params.paths
    );
}

/// G3.7: the IMT-like A load proved on Vesta.
#[test]
#[ignore = "k = 16 Vesta proof of the A load; run in release"]
fn g3_7_a_load_proof() {
    let load = a_load(70);
    let public = load.public();
    measure_proof::<Vesta, _>("G3.7/a_imt_load", &load, &public);
}

/// G3.7: the design's exact A shape filled on every usable row, proved on
/// Vesta.
#[test]
#[ignore = "k = 16 Vesta proof of the exact A shape; run in release"]
fn g3_7_a_exact_shape_proof() {
    let rows = ExactCircuit::<Fp>::usable_rows(A_SHAPE, K);
    let circuit = ExactCircuit::<Fp>::new(A_SHAPE, rows, 77);
    let public = vec![circuit.output()];
    measure_proof::<Vesta, _>("G3.7/a_exact_shape", &circuit, &public);
}

/// Both exact shapes synthesized and strictly checked at `k = 16`.
#[test]
#[ignore = "k = 16 strict checks of the exact shapes; run in release"]
fn exact_shapes_check_at_k16() {
    for (name, shape) in [("q_exact_shape", Q_SHAPE), ("a_exact_shape", A_SHAPE)] {
        let rows = ExactCircuit::<Fq>::usable_rows(shape, K);
        let circuit = ExactCircuit::<Fq>::new(shape, rows, 5);
        let public = vec![circuit.output()];
        inventory(name, &circuit, &public, &[]);
    }
}
