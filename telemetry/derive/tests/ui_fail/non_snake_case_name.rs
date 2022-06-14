#![allow(unused_imports)] // Unused because macro will no generate anything
use iroha_core::wsv::WorldStateView;
use iroha_telemetry_derive::metrics;

#[metrics(+"test query", "another_test_query_without_timing")]
fn execute(wsv: &WorldStateView) -> Result<(), ()> {
    Ok(())
}

fn main() {

}
