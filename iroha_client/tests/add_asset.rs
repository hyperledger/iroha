#![allow(clippy::module_inception, unused_results, clippy::restriction)]

use std::ops::Not;
use std::thread;

use iroha::config::Configuration;
use iroha_client::client;
use iroha_data_model::prelude::*;
use iroha_error::Result;
use test_network::Peer as TestPeer;
use test_network::*;

#[test]
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount() -> Result<()> {
    let (_, mut test_client) = TestPeer::start_test();
    let pipeline_time = Configuration::pipeline_time();

    // Given
    thread::sleep(pipeline_time);

    let account_id = AccountId::new("alice", "wonderland");
    let asset_definition_id = AssetDefinitionId::new("xor", "wonderland");
    let create_asset = RegisterBox::new(IdentifiableBox::from(AssetDefinition::new_quantity(
        asset_definition_id.clone(),
    )));

    test_client.submit(create_asset)?;
    thread::sleep(pipeline_time * 2);

    //When
    let quantity: u32 = 200;
    let mint = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    test_client.submit_till(mint, &client::asset::by_account_id(account_id), |result| {
        result
            .find_asset_by_id(&asset_definition_id)
            .map_or(false, |asset| asset.value == AssetValue::Quantity(quantity))
    });
    Ok(())
}

#[test]
fn client_add_asset_with_name_length_more_than_limit_should_not_commit_transaction() -> Result<()> {
    let (_, mut test_client) = TestPeer::start_test();
    let pipeline_time = Configuration::pipeline_time();

    // Given
    thread::sleep(pipeline_time);

    let normal_asset_definition_id = AssetDefinitionId::new("xor", "wonderland");
    let create_asset = RegisterBox::new(IdentifiableBox::from(AssetDefinition::new_quantity(
        normal_asset_definition_id.clone(),
    )));
    test_client.submit(create_asset)?;

    let too_long_asset_name = "0".repeat(2_usize.pow(14));
    let incorrect_asset_definition_id = AssetDefinitionId::new(&too_long_asset_name, "wonderland");
    let create_asset = RegisterBox::new(IdentifiableBox::from(AssetDefinition::new_quantity(
        incorrect_asset_definition_id.clone(),
    )));
    test_client.submit(create_asset)?;
    thread::sleep(pipeline_time * 2);

    let result = test_client
        .request(&client::asset::all_definitions())
        .expect("Failed to execute request.");

    if let QueryResult(Value::Vec(assets)) = result {
        let asset_definition_ids: Vec<AssetDefinitionId> = assets
            .into_iter()
            .filter_map(|asset| {
                if let Value::Identifiable(IdentifiableBox::AssetDefinition(asset_definition)) =
                    asset
                {
                    return Some(asset_definition.id);
                }
                None
            })
            .collect();
        assert!(asset_definition_ids.contains(&normal_asset_definition_id));
        assert!(asset_definition_ids
            .contains(&incorrect_asset_definition_id)
            .not());
    } else {
        panic!("Wrong Query Result Type.");
    };
    Ok(())
}
