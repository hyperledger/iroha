#![allow(unused_imports)]
use iroha_core::wsv::{World, WorldStateView};
use iroha_telemetry_derive::metrics;

#[metrics(+"test query", "another_test_query_without_timing")]
fn execute(wsv: &WorldStateView<World>) -> Result<(), ()> {
    Ok(())
}

fn main() {

}
