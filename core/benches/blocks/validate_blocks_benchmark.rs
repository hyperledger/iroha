#![allow(missing_docs, clippy::restriction)]

mod validate_blocks;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use validate_blocks::WsvValidateBlocks;

fn validate_blocks(c: &mut Criterion) {
    let bench = WsvValidateBlocks::setup().expect("Failed to setup benchmark");

    let mut group = c.benchmark_group("validate_blocks");
    group.significance_level(0.1).sample_size(10);
    group.bench_function("validate_blocks", |b| {
        b.iter(|| {
            WsvValidateBlocks::measure(black_box(bench.clone()))
                .expect("Failed to execute benchmark");
        });
    });
    group.finish();
}

criterion_group!(wsv, validate_blocks);
criterion_main!(wsv);
