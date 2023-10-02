use iroha_telemetry_derive::metrics;

#[metrics(+"test_query", ++"another_test_query_without_timing")]
fn execute(wsv: &WorldStateView) -> Result<(), ()> {
    Ok(())
}

fn main() {

}
