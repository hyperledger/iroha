use iroha_telemetry_derive::metrics;
use iroha_core::prelude::WorldStateView;

type MyNotResult = Option<i32>;

#[metrics(+"test_query", "another_test_query_without_timing")]
fn execute(_wsv: &WorldStateView) -> MyNotResult {
    None
}

fn main() {

}

