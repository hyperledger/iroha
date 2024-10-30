use iroha_telemetry_derive::metrics;

type MyNotResult = Option<i32>;

struct StateTransaction;

#[metrics(+"test_query", "another_test_query_without_timing")]
fn execute(_state_transaction: &StateTransaction) -> MyNotResult {
    None
}

fn main() {

}

