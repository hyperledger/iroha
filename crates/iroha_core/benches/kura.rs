//! Canonical storage benchmarks using an originally executed native certified chain.
use criterion::{BatchSize, Criterion};
use iroha_core::{
    kura::BlockStore,
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use std::hint::black_box;

fn native_canonical_storage(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("benchmark runtime");
    let _entered = runtime.enter();
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::default(), 1_000))
        .expect("original executed genesis");
    chain.commit(Vec::new());
    let genesis = chain.genesis();
    let committed = chain.committed(2);
    let block = committed.block();
    c.bench_function("kura_native_canonical_wire", |b| {
        b.iter(|| black_box(block.encode_wire().expect("canonical executed block")));
    });
    c.bench_function("kura_native_append_canonical_block", |b| {
        b.iter_batched(
            || {
                let directory = tempfile::tempdir().expect("benchmark storage directory");
                let mut store = BlockStore::new(directory.path());
                store
                    .create_files_if_they_do_not_exist()
                    .expect("create storage");
                store
                    .append_block_to_chain(genesis)
                    .expect("original genesis prefix");
                (directory, store)
            },
            |(_directory, mut store)| {
                store
                    .append_block_to_chain(block)
                    .expect("append original executed block");
            },
            BatchSize::SmallInput,
        );
    });
}

fn main() {
    // Fixture execution uses the same stack allowance as native runtime tests.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let mut criterion = Criterion::default().configure_from_args();
            native_canonical_storage(&mut criterion);
            criterion.final_summary();
        })
        .expect("benchmark worker")
        .join()
        .expect("benchmark worker completed");
}
