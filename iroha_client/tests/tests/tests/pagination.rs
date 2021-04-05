use std::thread;

use iroha::config::Configuration;
use iroha_client::client::asset;
use iroha_data_model::prelude::*;
use test_network::Peer as TestPeer;
use test_network::*;

#[test]
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount() {
    let (_, mut iroha_client) = TestPeer::start_test();
    let pipeline_time = Configuration::pipeline_time();

    let register = ('a'..'z')
        .map(|c| c.to_string())
        .map(|name| AssetDefinitionId::new(&name, "wonderland"))
        .map(AssetDefinition::new_quantity)
        .map(IdentifiableBox::from)
        .map(RegisterBox::new)
        .map(Instruction::Register)
        .collect();
    iroha_client
        .submit_all(register)
        .expect("Failed to prepare state.");

    thread::sleep(pipeline_time);
    //When

    let result = iroha_client
        .request_with_pagination(
            &asset::all_definitions(),
            Pagination {
                start: Some(5),
                limit: Some(5),
            },
        )
        .expect("Failed to get assets");
    if let QueryResult(Value::Vec(vec)) = result {
        assert_eq!(vec.len(), 5)
    } else {
        panic!("Expected vector of assets")
    }
}
