#![allow(clippy::restriction)]

use std::str::FromStr as _;

use eyre::Result;
use iroha_client::client;
use iroha_data_model::{metadata::UnlimitedMetadata, prelude::*};
use test_network::*;

#[test]
fn non_mintable_asset_can_be_minted_once_but_not_twice() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    // Given
    let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset =
        RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()).mintable_once());

    let metadata = UnlimitedMetadata::default();

    let mint = MintBox::new(
        Value::U32(200_u32),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );

    let instructions: [Instruction; 2] = [create_asset.into(), mint.clone().into()];
    let tx = test_client.build_transaction(instructions.into(), metadata)?;

    // We can register and mint the non-mintable token
    test_client.submit_transaction(tx)?;
    test_client.poll_request(client::asset::by_account_id(account_id.clone()), |result| {
        result.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Quantity(200_u32)
        })
    })?;

    // We can submit the request to mint again.
    test_client.submit_all([mint.into()])?;

    // However, this will fail
    assert!(test_client
        .poll_request(client::asset::by_account_id(account_id), |result| {
            result.iter().any(|asset| {
                asset.id().definition_id == asset_definition_id
                    && *asset.value() == AssetValue::Quantity(400_u32)
            })
        })
        .is_err());
    Ok(())
}

#[test]
fn non_mintable_asset_cannot_be_minted_if_registered_with_non_zero_value() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    // Given
    let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset =
        RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()).mintable_once());

    let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
    let register_asset = RegisterBox::new(Asset::new(asset_id.clone(), 1_u32));

    // We can register the non-mintable token
    test_client.submit_all([create_asset.into(), register_asset.clone().into()])?;
    test_client.poll_request(client::asset::by_account_id(account_id), |result| {
        result.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Quantity(1_u32)
        })
    })?;

    // But only once
    assert!(test_client.submit_blocking(register_asset).is_err());

    // And can't be minted
    let mint = MintBox::new(Value::U32(1_u32), IdBox::AssetId(asset_id));
    assert!(test_client.submit_blocking(mint).is_err());

    Ok(())
}

#[test]
fn non_mintable_asset_can_be_minted_if_registered_with_zero_value() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    // Given
    let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset =
        RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()).mintable_once());

    let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
    let register_asset = RegisterBox::new(Asset::new(asset_id.clone(), 0_u32));
    let mint = MintBox::new(Value::U32(1_u32), IdBox::AssetId(asset_id));

    // We can register the non-mintable token wih zero value and then mint it
    test_client.submit_all([create_asset.into(), register_asset.into(), mint.into()])?;
    test_client.poll_request(client::asset::by_account_id(account_id), |result| {
        result.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Quantity(1_u32)
        })
    })?;
    Ok(())
}
