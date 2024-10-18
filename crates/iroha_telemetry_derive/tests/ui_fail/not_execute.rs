use iroha_telemetry_derive::metrics;

struct StateTransaction;

#[metrics(+"test_query", "another_test_query_without_timing")]
fn exequte(_state_transaction: &StateTransaction) -> Result<(), ()> {
    Ok(())
}

fn main() {}
