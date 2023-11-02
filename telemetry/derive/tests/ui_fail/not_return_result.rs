use iroha_telemetry_derive::metrics;
use iroha_core::state::StateTransaction;

type MyNotResult = Option<i32>;

#[metrics(+"test_query", "another_test_query_without_timing")]
fn execute(_state_transaction: &StateTransaction) -> MyNotResult {
    None
}

fn main() {

}

