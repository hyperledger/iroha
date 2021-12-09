use iroha_core::wsv::{World, WorldStateView};
use iroha_data_model_derive::metrics;

#[metrics(+"test_query", +"another_test_query")]
fn execute(wsv: &WorldStateView<World>) -> Result<(), ()> {
    Ok(())
}
