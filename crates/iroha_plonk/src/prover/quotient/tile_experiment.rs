//! Isolated real-descriptor DAG tiling experiment; never a proof or timing gate.
//! Compare tiled and row-wise evaluation on independently pinned real descriptors.

use std::{hint::black_box, io::Read as _, path::Path, time::Instant};

use iroha_measurement::probe::ProcessSnapshot;
use iroha_pasta::{Fp, Fq};
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::keys::DescriptorBinding;

// This is additional DAG scratch only, not the process-wide MSM budget. The
// actual output/input columns are separately recorded and are not secret data.
const PROCESS_SCRATCH_LIMIT: usize = 16 << 20;
const COLUMN_INPUT_LIMIT: usize = 512 << 20;

fn tile<F: PastaField>(
    expressions: &CompiledExpressions<F>,
    columns: &BoundColumns<'_, F>,
    row: usize,
    width: usize,
    scratch: &mut [F],
) {
    assert_eq!(scratch.len(), expressions.nodes.len() * width);
    for (index, node) in expressions.nodes.iter().enumerate() {
        let (prior, rest) = scratch.split_at_mut(index * width);
        let output = &mut rest[..width];
        match *node {
            Node::Constant(value) => output.fill(value),
            Node::Fixed(query) | Node::Advice(query) | Node::Instance(query) => {
                let (values, rotation) = match *node {
                    Node::Fixed(_) => columns.fixed[query as usize],
                    Node::Advice(_) => columns.advice[query as usize],
                    Node::Instance(_) => columns.instance[query as usize],
                    _ => unreachable!(),
                };
                for (lane, value) in output.iter_mut().enumerate() {
                    *value = values[(row + lane + rotation) & columns.mask];
                }
            }
            Node::Negated(a) => {
                for (lane, value) in output.iter_mut().enumerate() {
                    *value = -prior[a as usize * width + lane];
                }
            }
            Node::Doubled(a) => {
                for (lane, value) in output.iter_mut().enumerate() {
                    *value = prior[a as usize * width + lane].double();
                }
            }
            Node::Squared(a) => {
                for (lane, value) in output.iter_mut().enumerate() {
                    *value = prior[a as usize * width + lane].square();
                }
            }
            Node::Sum(a, b) => {
                for (lane, value) in output.iter_mut().enumerate() {
                    *value = prior[a as usize * width + lane] + prior[b as usize * width + lane];
                }
            }
            Node::Product(a, b) => {
                for (lane, value) in output.iter_mut().enumerate() {
                    *value = prior[a as usize * width + lane] * prior[b as usize * width + lane];
                }
            }
            Node::Scaled(a, factor) => {
                for (lane, value) in output.iter_mut().enumerate() {
                    *value = prior[a as usize * width + lane] * factor;
                }
            }
        }
    }
}

fn verify_every_node<F: PastaField>(
    expressions: &CompiledExpressions<F>,
    columns: &BoundColumns<'_, F>,
    n: usize,
    width: usize,
) {
    let mut tiled = SecretPolynomial::new(vec![F::ZERO; expressions.nodes.len() * width]);
    let mut original = SecretPolynomial::new(vec![F::ZERO; expressions.nodes.len()]);
    // All nodes, all rows, including rotated columns and non-root nodes. No
    // checksum collision can hide a wrong result in this untimed comparison.
    for row in (0..n).step_by(width) {
        tile(expressions, columns, row, width, &mut tiled);
        for lane in 0..width {
            expressions.evaluate_row(columns, row + lane, &mut original);
            for (index, expected) in original.iter().enumerate() {
                assert_eq!(tiled[index * width + lane], *expected);
            }
        }
    }
}

fn kernel<F: PastaField>(
    expressions: &CompiledExpressions<F>,
    columns: &BoundColumns<'_, F>,
    n: usize,
    width: usize,
    cancellation: Option<&CancellationToken>,
    after_chunk: impl Fn(usize) + Sync,
) -> Result<SecretPolynomial<F>, ProverError> {
    CancellationToken::checkpoint(cancellation)?;
    let mut output = SecretPolynomial::new(vec![F::ZERO; n]);
    output
        .par_chunks_mut(ROWS_PER_TASK)
        .enumerate()
        .try_for_each(|(task, rows)| -> Result<(), ProverError> {
            CancellationToken::checkpoint(cancellation)?;
            let mut scratch = SecretPolynomial::new(vec![F::ZERO; expressions.nodes.len() * width]);
            for (chunk, values) in rows.chunks_mut(width).enumerate() {
                let start = task * ROWS_PER_TASK + chunk * width;
                if width == 1 {
                    expressions.evaluate_row(columns, start, &mut scratch);
                } else {
                    tile(expressions, columns, start, width, &mut scratch);
                }
                for (lane, value) in values.iter_mut().enumerate() {
                    // Same public roots and same field addition order for every
                    // arm. Full per-node equality was checked outside timing.
                    *value = expressions
                        .gates
                        .iter()
                        .chain(
                            expressions
                                .lookups
                                .iter()
                                .flat_map(|lookup| lookup.inputs.iter().chain(&lookup.tables)),
                        )
                        .fold(F::ZERO, |sum, root| {
                            sum + scratch[*root as usize * width + lane]
                        });
                }
                black_box(&scratch);
                CancellationToken::checkpoint(cancellation)?;
            }
            after_chunk(task);
            CancellationToken::checkpoint(cancellation)?;
            Ok(())
        })?;
    // try_for_each has joined every Rayon task before this return; every scratch
    // guard and any partial output is wiped on cancellation/error.
    CancellationToken::checkpoint(cancellation)?;
    Ok(output)
}

fn run<F: PastaField>(binding: &DescriptorBinding, width: usize, workers: usize) {
    let n = binding.n();
    assert_eq!(n, 1 << 16);
    let expressions = CompiledExpressions::<F>::compile(binding.descriptor(), true).unwrap();
    let scratch_per_worker = expressions
        .nodes
        .len()
        .checked_mul(width)
        .unwrap()
        .checked_mul(core::mem::size_of::<F>())
        .unwrap();
    let scratch_bound = scratch_per_worker.checked_mul(workers).unwrap();
    let verification_scratch = expressions
        .nodes
        .len()
        .checked_mul(width + 1)
        .unwrap()
        .checked_mul(core::mem::size_of::<F>())
        .unwrap();
    assert!(scratch_bound.max(verification_scratch) <= PROCESS_SCRATCH_LIMIT);
    let d = binding.descriptor();
    let counts = [
        d.num_fixed_columns as usize,
        d.num_advice_columns as usize,
        d.instance_lengths.len(),
    ];
    let input_bytes = counts
        .iter()
        .sum::<usize>()
        .checked_mul(n)
        .unwrap()
        .checked_mul(core::mem::size_of::<F>())
        .unwrap();
    assert!(input_bytes <= COLUMN_INPUT_LIMIT);
    let mut rng = ChaCha20Rng::from_seed([0x6d; 32]);
    let mut make = |count: usize| {
        SecretColumns::new(
            (0..count)
                .map(|_| (0..n).map(|_| F::random(&mut rng)).collect())
                .collect(),
        )
    };
    // Deterministic full-field inputs on the real workload's descriptor. They
    // model dense quotient coset values; they are not a satisfying witness.
    let fixed = make(counts[0]);
    let advice = make(counts[1]);
    let instance = make(counts[2]);
    let (fixed_slices, advice_slices, instance_slices) =
        (slices(&fixed), slices(&advice), slices(&instance));
    let columns = expressions
        .bind(&fixed_slices, &advice_slices, &instance_slices, n)
        .unwrap();
    verify_every_node(&expressions, &columns, n, width);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .unwrap();
    pool.install(|| {
        assert_eq!(rayon::current_num_threads(), workers);
        let expected = kernel(&expressions, &columns, n, 1, None, |_| {}).unwrap();
        let token = CancellationToken::new();
        let cancelled = kernel(&expressions, &columns, n, width, Some(&token), |_| {
            token.cancel()
        });
        assert!(matches!(cancelled, Err(ProverError::Cancelled)));
        assert_eq!(
            *kernel(&expressions, &columns, n, width, None, |_| {}).unwrap(),
            *expected
        );
        let before =
            ProcessSnapshot::capture().expect("CPU/RSS probe failures invalidate this experiment");
        let start = Instant::now();
        let actual = kernel(&expressions, &columns, n, width, None, |_| {}).unwrap();
        let elapsed_ns =
            u64::try_from(start.elapsed().as_nanos()).expect("bounded experiment duration");
        let after = ProcessSnapshot::capture().expect("post-kernel probes");
        let cpu_ns = after.cpu_since(before).expect("monotonic process CPU");
        assert_eq!(*actual, *expected);
        let report = norito::json!({
            "scope": "DAG kernel experiment only; no proof/RSS/timing gate qualification",
            "tile": width, "workers": workers, "rows": n, "nodes": (expressions.nodes.len()),
            "cpu_ns": cpu_ns, "elapsed_ns": elapsed_ns,
            "kernel_peak_rss_bytes": (after.peak_rss_bytes),
            "input_bytes": input_bytes, "output_bytes": (n * core::mem::size_of::<F>()),
            "dag_scratch_upper_bound_bytes": scratch_bound,
            "untimed_verification_scratch_bytes": verification_scratch,
            "retained_expected_output_bytes": (n * core::mem::size_of::<F>()),
            "all_node_row_equality": true, "cancel_then_fresh_retry_equal": true,
        });
        println!("DAG_TILE_JSON {}", norito::json::to_json(&report).unwrap());
    });
}

#[test]
#[ignore = "explicit representative DAG diagnostic, not a proof or M3 qualification"]
fn actual_descriptor_node_major_tile_experiment() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let path = std::path::PathBuf::from(
        std::env::var_os("DAG_TILE_DESCRIPTOR").expect("independently pinned actual M3 descriptor"),
    );
    assert_eq!(path.canonicalize().unwrap(), path);
    assert!(path.starts_with(repo.join("target")));
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_file() && metadata.len() > 0 && metadata.len() <= 1 << 20);
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .take((1 << 20) + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes.len() as u64, metadata.len());
    let expected =
        std::env::var("DAG_TILE_DESCRIPTOR_SHA256").expect("independently pinned SHA256");
    let actual = format!("{:x}", Sha256::digest(&bytes));
    assert_eq!(expected, actual);
    let binding = DescriptorBinding::decode_v2(&bytes).unwrap();
    let width: usize = std::env::var("DAG_TILE_WIDTH").unwrap().parse().unwrap();
    let workers: usize = std::env::var("DAG_TILE_WORKERS").unwrap().parse().unwrap();
    assert!([1, 4, 8, 16].contains(&width));
    assert!([1, 4].contains(&workers));
    match binding.descriptor().curve {
        crate::cs::CurveV1::Pallas => run::<Fq>(&binding, width, workers),
        crate::cs::CurveV1::Vesta => run::<Fp>(&binding, width, workers),
    }
}
