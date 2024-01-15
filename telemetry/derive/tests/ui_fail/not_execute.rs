use iroha_telemetry_derive::metrics;
use iroha_core::prelude::WorldStateView;

#[metrics(+"test_query", "another_test_query_without_timing")]
fn exequte(wsv: &WorldStateView) -> Result<(), ()> {
    Ok(())
}

fn main() {

}
