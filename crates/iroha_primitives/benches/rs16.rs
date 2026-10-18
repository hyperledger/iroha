//! Criterion benchmarks for the compact RS16 payload-availability codec.
//!
//! Measures the recommended consensus layout (4 data rows, 2 parity rows, 256 KiB rows) for
//! 1 MiB and 16 MiB payloads on the host SIMD backend and on the scalar fallback. Reconstruction
//! erases the first two data rows of every stripe, so each stripe inverts a decoding matrix and
//! decodes two rows, and uses an accept-all row predicate so only codec work is measured.
use criterion::{BenchmarkId, Criterion, Throughput};
use iroha_allocation::AllocationBudget;
use iroha_primitives::erasure::rs16::{
    self,
    compact::{CompactShape, encode_funded, reconstruct_funded},
};
use std::{hint::black_box, time::Duration};

const DATA_ROWS: usize = 4;
const PARITY_ROWS: usize = 2;
const MAXIMUM_ROW: usize = 256 * 1024;
const SIZES: [(usize, &str); 2] = [(1 << 20, "1MiB"), (16 << 20, "16MiB")];

/// Deterministic xorshift64* payload bytes.
fn payload(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    (0..len)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes()[7]
        })
        .collect()
}

/// Benchmark caller-owned and funded encode/reconstruct for one backend selection.
fn bench_backend(c: &mut Criterion, simd: bool) {
    rs16::set_simd_enabled(simd);
    let mut group = c.benchmark_group(if simd {
        "rs16_compact_simd"
    } else {
        "rs16_compact_scalar"
    });
    group
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(4));
    for (len, label) in SIZES {
        let data = payload(len);
        let shape = CompactShape::new(len, DATA_ROWS, PARITY_ROWS, MAXIMUM_ROW).expect("shape");
        let mut workspace = vec![0; shape.workspace_words()];
        let mut encoded = vec![0; shape.encoded_bytes()];
        shape
            .encode_into(&data, &mut encoded, &mut workspace)
            .expect("encode");
        let received = (0..shape.chunk_count())
            .map(|index| {
                (index % (DATA_ROWS + PARITY_ROWS) >= PARITY_ROWS)
                    .then(|| &encoded[shape.chunk_range(index).expect("row")])
            })
            .collect::<Vec<_>>();
        let mut output = vec![0; shape.encoded_bytes()];
        let mut recovered = vec![0; len];
        let budget = AllocationBudget::new(usize::MAX / 2);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_function(BenchmarkId::new("encode_into", label), |b| {
            b.iter(|| {
                shape
                    .encode_into(black_box(&data), &mut output, &mut workspace)
                    .expect("encode");
            });
        });
        group.bench_function(BenchmarkId::new("reconstruct_into", label), |b| {
            b.iter(|| {
                shape
                    .reconstruct_into(
                        black_box(&received),
                        &mut recovered,
                        &mut output,
                        &mut workspace,
                        |_, _| true,
                    )
                    .expect("reconstruct");
            });
        });
        assert!(recovered == data && output == encoded, "codec roundtrip");
        group.bench_function(BenchmarkId::new("encode_funded", label), |b| {
            b.iter(|| black_box(encode_funded(shape, black_box(&data), &budget).expect("encode")));
        });
        group.bench_function(BenchmarkId::new("reconstruct_funded", label), |b| {
            b.iter(|| {
                black_box(
                    reconstruct_funded(shape, black_box(&received), &budget, |_, _| true)
                        .expect("reconstruct"),
                )
            });
        });
    }
    group.finish();
}

/// Criterion entry point for the RS16 benchmark binary.
fn main() {
    let mut c = Criterion::default().configure_from_args();
    bench_backend(&mut c, true);
    bench_backend(&mut c, false);
    rs16::set_simd_enabled(true);
    c.final_summary();
}
