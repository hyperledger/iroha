use iroha_core::wsv::{World, WorldStateView};
use iroha_telemetry_derive::metrics;

#[metrics(+"test_query", "another_test_query_without_timing")]
fn execute(_wsv: &WorldStateView) -> iroha_core::RESULT {
    Ok(())
}

fn main() {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let _something: World = World::default();
    let _world = WorldStateView::new(_something, kura);
}

