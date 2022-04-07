use iroha_core::wsv::{World, WorldStateView};
use iroha_telemetry_derive::metrics;

#[metrics(+"test_query", "another_test_query_without_timing")]
fn exequte(wsv: &WorldStateView<World>) -> Result<(), ()> {
    Ok(())
}

fn main() {
    let _something: World = World::default();
    let _something_else = WorldStateView::<World>::default();
}
