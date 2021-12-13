use iroha_core::wsv::{World, WorldStateView};
use iroha_telemetry_derive::metrics;

#[metrics(+"test query", "another_test_query_without_timing")]
fn execute(wsv: &WorldStateView<World>) -> Result<(), ()> {
	// TODO: AFAIK prometheus is fine with spaces in names, but
	// enforcing a consistent style might be a good idea long-term.

	// Uncomment this, when the test can be un-ignored
	
	// Ok(())
}

fn main() {
	
}
