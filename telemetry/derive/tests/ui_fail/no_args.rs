use iroha_core::wsv::WorldStateView;
use iroha_telemetry_derive::metrics;

#[metrics(+"test_query", "another_test_query_without_timing")]
fn execute() -> Result<(), ()> {
    Ok(())
}

fn main() {
    let _world = WorldStateView::default();
}
