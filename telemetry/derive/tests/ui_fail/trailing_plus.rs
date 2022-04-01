use iroha_core::wsv::{World, WorldStateView};
use iroha_telemetry_derive::metrics;

#[metrics(+"test_query", "another_test_query_without_timing"+)]
fn execute(wsv: &iroha_core::wsv::WorldStateView<World>) -> Result<(), ()> {
    Ok(())
}

fn main() {
    let _world = WorldStateView::<World>::default();
}
