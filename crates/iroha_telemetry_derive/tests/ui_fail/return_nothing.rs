use iroha_telemetry_derive::metrics;

struct StateTransaction;

#[metrics(+"test_query", "another_test_query_without_timing")]
fn execute(_state_transaction: &StateTransaction) {
    Ok::<(), ()>(());
}

fn main() {}
