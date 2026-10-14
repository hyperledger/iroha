//! Criterion benchmark driver for validating blocks.

mod validate_blocks;
use criterion::Criterion;
use validate_blocks::StateValidateBlocks;
fn validate_blocks(c: &mut Criterion) {
    // Ensure instruction registry is initialized for (de)serialization in benches
    iroha_data_model::isi::set_instruction_registry(
        iroha_data_model::instruction_registry::default(),
    );
    let mut group = c.benchmark_group("validate_blocks");
    group.significance_level(0.1).sample_size(10);
    group.bench_function("validate_blocks", |b| {
        b.iter_batched_ref(
            StateValidateBlocks::setup,
            StateValidateBlocks::measure,
            criterion::BatchSize::SmallInput,
        );
    });
    group.finish();
}
/// Entry point for the benchmark binary.
fn main() {
    // Silence IVM banner for block-validation benches.
    #[allow(unused_imports)]
    {
        use ivm::set_banner_enabled;
        set_banner_enabled(false);
    }
    let mut c = Criterion::default().configure_from_args();
    validate_blocks(&mut c);
    c.final_summary();
}
