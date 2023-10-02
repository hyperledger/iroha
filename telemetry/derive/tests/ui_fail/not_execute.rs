use iroha_telemetry_derive::metrics;

#[metrics(+"test_query", "another_test_query_without_timing")]
fn exequte(wsv: &WorldStateView) -> Result<(), ()> {
    Ok(())
}

fn main() {

}
