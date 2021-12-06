#![allow(clippy::restriction)]

use std::thread;

use eyre::Result;
use iroha_client::client;
use iroha_core::config::Configuration;
use iroha_data_model::{fixed::Fixed, prelude::*};
use test_network::{Peer as TestPeer, *};

#[test]
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount() -> Result<()> {
    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(vec![test_client.clone()], 0);
    let pipeline_time = Configuration::pipeline_time();

    // Given
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
    test_client.submit_till(mint, client::asset::by_account_id(account_id), |result| {
        result.iter().any(|asset| {
            asset.id.definition_id == asset_definition_id
                && asset.value == AssetValue::Quantity(quantity)
        })
    });
    Ok(())
}

#[test]
fn client_add_big_asset_quantity_to_existing_asset_should_increase_asset_amount() -> Result<()> {
    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    let pipeline_time = Configuration::pipeline_time();

    // Given
    thread::sleep(pipeline_time);

    let account_id = AccountId::new("alice", "wonderland");
    let asset_definition_id = AssetDefinitionId::new("xor", "wonderland");
    let create_asset = RegisterBox::new(IdentifiableBox::from(AssetDefinition::new_big_quantity(
        asset_definition_id.clone(),
    )));

    test_client.submit(create_asset)?;
    thread::sleep(pipeline_time * 2);

    //When
    let quantity: u128 = 0x0001_0000_0000_0000_0000; // 2^64
    let mint = MintBox::new(
        Value::U128(quantity),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    test_client.submit_till(mint, client::asset::by_account_id(account_id), |result| {
        result.iter().any(|asset| {
            asset.id.definition_id == asset_definition_id
                && asset.value == AssetValue::BigQuantity(quantity)
        })
    });
    Ok(())
}

#[test]
fn client_add_asset_with_decimal_should_increase_asset_amount() -> Result<()> {
    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    let pipeline_time = Configuration::pipeline_time();

    // Given
    thread::sleep(pipeline_time);

    let account_id = AccountId::new("alice", "wonderland");
    let asset_definition_id = AssetDefinitionId::new("xor", "wonderland");
    let identifiable_box =
        IdentifiableBox::from(AssetDefinition::with_precision(asset_definition_id.clone()));
    let create_asset = RegisterBox::new(identifiable_box);

    test_client.submit(create_asset)?;
    thread::sleep(pipeline_time * 2);

    //When
    let quantity: Fixed = Fixed::try_from(123.45_f64).unwrap();
    let mint = MintBox::new(
        Value::Fixed(quantity),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    test_client.submit_till(
        mint,
        client::asset::by_account_id(account_id.clone()),
        |result| {
            result.iter().any(|asset| {
                asset.id.definition_id == asset_definition_id
                    && asset.value == AssetValue::Fixed(quantity)
            })
        },
    );

    // Add some fractional part
    let quantity2: Fixed = Fixed::try_from(0.55_f64).unwrap();
    let mint = MintBox::new(
        Value::Fixed(quantity2),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    // and check that it is added without errors
    let sum = Fixed::try_from(124.00_f64).unwrap();
    test_client.submit_till(mint, client::asset::by_account_id(account_id), |result| {
        result.iter().any(|asset| {
            asset.id.definition_id == asset_definition_id && asset.value == AssetValue::Fixed(sum)
        })
    });
    Ok(())
}

#[test]
fn client_add_asset_with_name_length_more_than_limit_should_not_commit_transaction() -> Result<()> {
    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    let pipeline_time = Configuration::pipeline_time();

    // Given
    thread::sleep(pipeline_time);

    let normal_asset_definition_id = AssetDefinitionId::new("xor", "wonderland");
    let create_asset = RegisterBox::new(IdentifiableBox::from(AssetDefinition::new_quantity(
        normal_asset_definition_id.clone(),
    )));
    test_client.submit(create_asset)?;
    iroha_logger::info!("Creating asset");

    let too_long_asset_name = "0".repeat(2_usize.pow(14));
    let incorrect_asset_definition_id = AssetDefinitionId::new(&too_long_asset_name, "wonderland");
    let create_asset = RegisterBox::new(IdentifiableBox::from(AssetDefinition::new_quantity(
        incorrect_asset_definition_id.clone(),
    )));

    test_client.submit(create_asset)?;
    iroha_logger::info!("Creating another asset");
    thread::sleep(pipeline_time * 4);

    let asset_definition_ids = test_client
        .request(client::asset::all_definitions())
        .expect("Failed to execute request.")
        .into_iter()
        .map(|asset| asset.id)
        .collect::<Vec<_>>();
    dbg!(&asset_definition_ids);

    assert!(asset_definition_ids.contains(&normal_asset_definition_id));
    assert!(!asset_definition_ids.contains(&incorrect_asset_definition_id));

    Ok(())
}
