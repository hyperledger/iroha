#![allow(missing_docs)]

mod validate_blocks;

use criterion::{criterion_group, criterion_main, Criterion};
use validate_blocks::WsvValidateBlocks;

fn validate_blocks(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime");

    let mut group = c.benchmark_group("validate_blocks");
    group.significance_level(0.1).sample_size(10);
    group.bench_function("validate_blocks", |b| {
        b.iter_batched(
            || WsvValidateBlocks::setup(rt.handle()).expect("Failed to setup benchmark"),
            |bench| {
                WsvValidateBlocks::measure(bench).expect("Failed to execute benchmark");
            },
            criterion::BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(wsv, validate_blocks);
criterion_main!(wsv);
