//! Absolute production queue-cleanup and inbound transaction-admission measurements.

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use iroha_core::gossiper::benchmark::HotPathFixture;
use std::{hint::black_box, time::Duration};

fn queue_commit(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let mut group = c.benchmark_group("queue_committed_cleanup");
    for resident in [64, 1024, 16_384] {
        let fixture = HotPathFixture::new(resident);
        for committed in [1, 8, 64] {
            group.throughput(Throughput::Elements(committed as u64));
            group.bench_function(
                BenchmarkId::new(format!("resident_{resident}"), committed),
                |b| {
                    b.iter_batched(
                        || fixture.restore(committed),
                        |()| black_box(fixture.remove(committed)),
                        BatchSize::PerIteration,
                    );
                },
            );
            fixture.restore(committed);
        }
    }
    group.finish();
}

fn inbound_gossip(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let mut group = c.benchmark_group("inbound_gossip");
    for count in [1, 16, 128, 512] {
        let fixture = HotPathFixture::new(count);
        group.throughput(Throughput::Elements(count as u64));
        group.bench_function(BenchmarkId::new("known", count), |b| {
            b.iter_batched(
                || fixture.batch(count),
                |batch| fixture.receive(black_box(batch)),
                BatchSize::PerIteration,
            );
        });
        group.bench_function(
            BenchmarkId::new("unknown_cold_signature_cache", count),
            |b| {
                b.iter_batched(
                    || fixture.prepare_unknown(count),
                    |batch| fixture.receive(black_box(batch)),
                    BatchSize::PerIteration,
                );
            },
        );
        assert_eq!(fixture.resident(), count);
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30).warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(2));
    targets = queue_commit, inbound_gossip
}
criterion_main!(benches);
