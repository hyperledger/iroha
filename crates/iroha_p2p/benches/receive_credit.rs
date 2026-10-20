//! Absolute measurements of canonical record sealing, writing and grant release.

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use iroha_p2p::benchmark::{RecordFixture, ReleaseFixture};
use std::{hint::black_box, time::Duration};

fn records(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("receive_credit_record");
    for bytes in [256, 4096, 65_536, 1_048_576] {
        let fixture = RecordFixture::new(bytes);
        group.throughput(Throughput::Bytes(bytes as u64));
        group.bench_with_input(BenchmarkId::new("seal", bytes), &bytes, |b, _| {
            b.iter(|| black_box(fixture.seal()));
        });
        for (name, chunk) in [("write_contiguous", usize::MAX), ("write_4k", 4096)] {
            group.bench_with_input(BenchmarkId::new(name, bytes), &bytes, |b, _| {
                b.iter_batched(
                    || fixture.prepare_write(chunk),
                    |write| black_box(runtime.block_on(write.finish())),
                    BatchSize::PerIteration,
                );
            });
        }
    }
    group.finish();
}

fn releases(c: &mut Criterion) {
    let fixture = ReleaseFixture::default();
    let mut group = c.benchmark_group("receive_credit_release");
    for waiters in [0, 1, 8, 64] {
        group.bench_with_input(
            BenchmarkId::new("waiters", waiters),
            &waiters,
            |b, &waiters| {
                b.iter_batched(
                    || fixture.prepare(waiters),
                    |case| black_box(case.release()),
                    BatchSize::PerIteration,
                );
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30).warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(2));
    targets = records, releases
}
criterion_main!(benches);
