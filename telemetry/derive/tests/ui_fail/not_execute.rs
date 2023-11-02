use iroha_telemetry_derive::metrics;
use iroha_core::state::StateTransaction;

#[metrics(+"test_query", "another_test_query_without_timing")]
fn exequte(state_transaction: &StateTransaction) -> Result<(), ()> {
    Ok(())
}

fn main() {

}
