#![allow(missing_docs)]

mod validate_blocks;

use criterion::{criterion_group, criterion_main, Criterion};
use validate_blocks::StateValidateBlocks;

fn validate_blocks(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime");

    let mut group = c.benchmark_group("validate_blocks");
    group.significance_level(0.1).sample_size(10);
    group.bench_function("validate_blocks", |b| {
        b.iter_batched(
            || StateValidateBlocks::setup(rt.handle()),
            StateValidateBlocks::measure,
            criterion::BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(state, validate_blocks);
criterion_main!(state);
