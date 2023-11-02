use iroha_telemetry_derive::metrics;
use iroha_core::state::StateTransaction;

#[metrics(+"test_query", "another_test_query_without_timing")]
fn execute(state_transaction: &StateTransaction) {
    Ok::<(), ()>(());
}

fn main() {

}
