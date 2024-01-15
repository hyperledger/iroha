use iroha_telemetry_derive::metrics;
use iroha_core::prelude::WorldStateView;

#[metrics(+"test_query", "another_test_query_without_timing")]
fn execute(wsv: &WorldStateView) {
    Ok::<(), ()>(());
}

fn main() {

}
