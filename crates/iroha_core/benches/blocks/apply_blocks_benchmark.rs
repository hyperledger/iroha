//! Criterion benchmark driver for applying blocks.

mod apply_blocks;
use apply_blocks::common::{generate_ids, generated_asset_definition_name};
use apply_blocks::{CertifiedBlocks, StateApplyBlocks};
use criterion::{BatchSize, Criterion};
use iroha_core::state::World;
use iroha_data_model::{Registrable, account::Account, asset::AssetDefinition, domain::Domain};
use std::rc::Rc;
fn apply_blocks(c: &mut Criterion) {
    // Ensure instruction registry is initialized for benches using InstructionBox
    iroha_data_model::isi::set_instruction_registry(
        iroha_data_model::instruction_registry::default(),
    );
    let mut group = c.benchmark_group("apply_blocks");
    group.significance_level(0.1).sample_size(10);
    // The certified source blocks are built once, only when this benchmark is selected.
    let mut blocks = None;
    group.bench_function("apply_blocks", |b| {
        let blocks: &Rc<CertifiedBlocks> = blocks.get_or_insert_with(CertifiedBlocks::setup);
        b.iter_batched_ref(
            || StateApplyBlocks::setup(blocks),
            StateApplyBlocks::measure,
            BatchSize::SmallInput,
        );
    });
    group.finish();
}
fn large_world() -> World {
    let (domain_ids, account_ids, asset_definition_ids) = generate_ids(10, 100, 100);
    let authority = account_ids
        .first()
        .expect("benchmark fixture has accounts")
        .clone();
    let domain_count = domain_ids.len();
    let domains = domain_ids
        .into_iter()
        .map(|id| Domain::new(id).build(&authority));
    let accounts = account_ids
        .into_iter()
        .map(|id| Account::new(id).build(&authority));
    let asset_definition_count = asset_definition_ids.len();
    let asset_definitions = asset_definition_ids
        .into_iter()
        .enumerate()
        .map(|(index, id)| {
            let name = generated_asset_definition_name(domain_count, asset_definition_count, index);
            AssetDefinition::numeric(
                id,
                name,
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&authority)
        });
    World::with(domains, accounts, asset_definitions)
}
fn state_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_commit");
    group.significance_level(0.1).sample_size(30);
    let execution_budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    group.bench_function("world_commit_noop_large_world", |b| {
        b.iter_batched(
            large_world,
            |world| {
                let block = world
                    .try_block(&execution_budget)
                    .expect("benchmark World admission");
                block.commit();
            },
            BatchSize::SmallInput,
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
    apply_blocks(&mut c);
    state_commit(&mut c);
    c.final_summary();
}
