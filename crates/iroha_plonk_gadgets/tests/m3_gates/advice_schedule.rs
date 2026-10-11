//! Actual M3 advice commitments with two submission schedules; diagnostic only.

use rayon::prelude::*;

use super::*;
use iroha_plonk::{
    pcs::ipa::commit::{Secrecy, commit_lagrange},
    transcript::encode_point,
};

/// Owns and clears the public test fixture's witness buffers and blinds.
struct AdviceValues<F: PastaField> {
    columns: Vec<Vec<F>>,
    blinds: Vec<F>,
}

impl<F: PastaField> Drop for AdviceValues<F> {
    fn drop(&mut self) {
        for value in self.columns.iter_mut().flatten().chain(&mut self.blinds) {
            value.zeroize();
        }
    }
}

fn commitments<C: PastaCurve>(
    params: &PinnedParams<C>,
    advice: &AdviceValues<C::ScalarExt>,
    nested: bool,
) -> Vec<C::AffineExt> {
    assert_eq!(advice.columns.len(), advice.blinds.len());
    let commit = |(column, blind): (&Vec<C::ScalarExt>, &C::ScalarExt)| {
        commit_lagrange(params.params(), column, blind, Secrecy::Secret, MSM_BUDGET)
            .expect("secret commitment")
            .to_affine()
    };
    if nested {
        advice
            .columns
            .par_iter()
            .zip(advice.blinds.par_iter())
            .map(commit)
            .collect()
    } else {
        advice
            .columns
            .iter()
            .zip(&advice.blinds)
            .map(commit)
            .collect()
    }
}

fn output_digest<C: PastaCurve>(points: &[C::AffineExt]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"iroha.m3.advice-schedule.outputs.v1\0");
    digest.update(u64::try_from(points.len()).unwrap().to_le_bytes());
    for point in points {
        let encoded = encode_point::<C>(point);
        // Production transcript writes reject the identity as well.
        assert_ne!(encoded, [0; 32], "identity advice commitment");
        digest.update(encoded);
    }
    hex(&digest.finalize())
}

fn compare<C, Ci>(
    name: &str,
    circuit: &Ci,
    public: Vec<C::ScalarExt>,
    expected_columns: usize,
    mode: &str,
) where
    C: PastaCurve,
    C::ScalarExt: PoseidonField,
    Ci: Circuit<C::ScalarExt>,
{
    let (params, parameter_source) = pinned_params::<C>(K);
    let config = measurement_key_config();
    assert!(
        config.table_budget.is_none(),
        "this diagnostic uses the no-table M3 path"
    );
    let fingerprint = iroha_plonk::keys::source_fingerprint_v2(
        &params,
        &circuit.without_witnesses(),
        &config,
        None,
    )
    .expect("exact source descriptor");
    let mut assigned = synthesize(circuit, K, Some(&[public])).expect("actual M3 witness");
    let n = assigned.tables.n();
    let usable_rows = assigned.tables.usable_rows();
    assert_eq!(n, 1usize << K);
    assert!(usable_rows < n);
    let mut advice = AdviceValues {
        columns: assigned.tables.take_advice().expect("witness columns"),
        blinds: Vec::new(),
    };
    drop(assigned);
    assert_eq!(advice.columns.len(), expected_columns);
    assert!(advice.columns.iter().all(|column| column.len() == n));
    let mut rng = ChaCha20Rng::seed_from_u64(20_261_008);
    // Match production ordering: fill each column's blinding rows first,
    // then draw every commitment blind. Both schedules receive identical data.
    for column in &mut advice.columns {
        for value in &mut column[usable_rows..] {
            *value = C::ScalarExt::random(&mut rng);
        }
    }
    advice.blinds = (0..advice.columns.len())
        .map(|_| C::ScalarExt::random(&mut rng))
        .collect();
    let mut inputs = Sha256::new();
    inputs.update(b"iroha.m3.advice-schedule.inputs.v1\0");
    inputs.update(fingerprint.binding().digest());
    for extent in [advice.columns.len(), n, usable_rows, advice.blinds.len()] {
        inputs.update(u64::try_from(extent).unwrap().to_le_bytes());
    }
    // Fixed-width canonical scalars in column-major order, then all blinds.
    for value in advice.columns.iter().flatten().chain(&advice.blinds) {
        inputs.update(value.to_repr());
    }
    let input_sha256 = hex(&inputs.finalize());
    let scratch = SharedMemoryBudget::process_default();
    assert_eq!(scratch.in_use_bytes(), 0);
    let preparation = ProcessSnapshot::capture().expect("prepared process probes");
    let scratch_before = scratch.peak_bytes();
    let mut samples = Vec::new();
    let mut previous = None;
    let correctness_sha256 = if mode == "compare" {
        let serial = commitments(&params, &advice, false);
        let nested = commitments(&params, &advice, true);
        assert_eq!(serial, nested, "every actual advice commitment must match");
        Some(output_digest::<C>(&serial))
    } else {
        assert!(matches!(mode, "serial" | "nested"));
        None
    };
    let nested = mode == "nested";
    for index in 0..if mode == "compare" { 0 } else { 2 } {
        let before = ProcessSnapshot::capture().expect("pre-commit probes");
        let start = Instant::now();
        let points = commitments(&params, &advice, nested);
        let elapsed = elapsed_ns(start);
        let after = ProcessSnapshot::capture().expect("post-commit probes");
        let cpu_ns = after.cpu_since(before).expect("monotonic direct CPU time");
        assert_eq!(points.len(), expected_columns);
        assert_eq!(scratch.in_use_bytes(), 0);
        let output_sha256 = output_digest::<C>(&points);
        if let Some(expected) = &previous {
            assert_eq!(expected, &output_sha256);
        }
        previous = Some(output_sha256.clone());
        samples.push(norito::json!({
            "index": index, "cpu_ns": cpu_ns, "elapsed_ns": elapsed,
            "output_sha256": output_sha256,
            "thermal_before": (before.thermal.as_str()),
            "thermal_after": (after.thermal.as_str()),
            "load_milli_before": (before.load_milli),
            "load_milli_after": (after.load_milli),
            "kernel_lifetime_peak_rss_bytes_before": (before.peak_rss_bytes),
            "kernel_lifetime_peak_rss_bytes_after": (after.peak_rss_bytes),
        }));
    }
    let after = ProcessSnapshot::capture().expect("final process probes");
    assert_eq!(scratch.in_use_bytes(), 0);
    assert!(scratch.peak_bytes() <= 64 << 20);
    let record = norito::json!({
        "scope": "Actual M3 advice-commitment diagnostic; no proof, timing-gate or device qualification",
        "workload": name, "mode": mode, "workers": (rayon::current_num_threads()),
        "k": K, "columns": (advice.columns.len()), "rows": n, "usable_rows": usable_rows,
        "descriptor_digest": (hex(fingerprint.binding().digest())),
        "input_sha256": input_sha256, "binary_sha256": (binary_digest()),
        "parameter_source": parameter_source,
        "correctness_output_sha256": correctness_sha256,
        "kernel_lifetime_peak_rss_bytes_prepared": (preparation.peak_rss_bytes),
        "kernel_lifetime_peak_rss_bytes_final": (after.peak_rss_bytes),
        "msm_process_lifetime_peak_bytes_prepared": scratch_before,
        "msm_process_lifetime_peak_bytes_final": (scratch.peak_bytes()),
        "samples": samples,
    });
    println!(
        "ADVICE_SCHEDULE_JSON {}",
        norito::json::to_json(&record).unwrap()
    );
}

#[test]
#[ignore = "explicit fresh-process commitment scheduling diagnostic; not an M3 gate"]
fn actual_m3_advice_scheduling() {
    let workers: usize = std::env::var("RAYON_NUM_THREADS").unwrap().parse().unwrap();
    assert!(matches!(workers, 1 | 4));
    let workload = std::env::var("ADVICE_WORKLOAD").unwrap();
    let mode = std::env::var("ADVICE_SCHEDULE").unwrap();
    assert!(matches!(mode.as_str(), "compare" | "serial" | "nested"));
    rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .unwrap()
        .install(|| {
            assert_eq!(rayon::current_num_threads(), workers);
            match workload.as_str() {
                "q" => {
                    let circuit = q_leaf(Q_VARIABLE, Q_FIXED, 60);
                    compare::<Pallas, _>(
                        "q_chips",
                        &circuit,
                        circuit.public(),
                        Q_LEAF_ADVICE_COLUMNS,
                        &mode,
                    );
                }
                "a" => {
                    let circuit = a_load(70);
                    compare::<Vesta, _>(
                        "a_chips",
                        &circuit,
                        circuit.public(),
                        4 + 4 * A_LANES + 3,
                        &mode,
                    );
                }
                _ => panic!("unknown diagnostic workload"),
            }
        });
}
