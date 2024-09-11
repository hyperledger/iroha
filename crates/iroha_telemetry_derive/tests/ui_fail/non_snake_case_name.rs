use iroha_telemetry_derive::metrics;

#[metrics(+"test query", "another_test_query_without_timing")]
fn execute(state_transaction: &StateTransaction) -> Result<(), ()> {
    Ok(())
}

fn main() {

}
