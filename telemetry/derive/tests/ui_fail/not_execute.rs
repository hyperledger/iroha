use iroha_core::wsv::{World, WorldStateView};
use iroha_telemetry_derive::metrics;

#[metrics(+"test_query", "another_test_query_without_timing")]
fn exequte(wsv: &WorldStateView) -> Result<(), ()> {
    Ok(())
}

fn main() {
    let (kura, _kth, _dir) = iroha_core::kura::Kura::blank_kura_for_testing();
    let _something: World = World::default();
    let _world = WorldStateView::new(_something, kura);
}
