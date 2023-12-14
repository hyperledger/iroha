use std::str::FromStr as _;

use eyre::Result;
use iroha_client::{
    client::{self, QueryResult},
    data_model::{metadata::UnlimitedMetadata, prelude::*},
};
use test_network::*;

#[test]
fn non_mintable_asset_can_be_minted_once_but_not_twice() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_625).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    // Given
    let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset =
        RegisterExpr::new(AssetDefinition::quantity(asset_definition_id.clone()).mintable_once());

    let metadata = UnlimitedMetadata::default();

    let mint = MintExpr::new(
        200_u32.to_value(),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );

    let instructions: [InstructionExpr; 2] = [create_asset.into(), mint.clone().into()];
    let tx = test_client.build_transaction(instructions, metadata)?;

    // We can register and mint the non-mintable token
    test_client.submit_transaction(&tx)?;
    test_client.poll_request(client::asset::by_account_id(account_id.clone()), |result| {
        let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");
        assets.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Quantity(200_u32)
        })
    })?;

    // We can submit the request to mint again.
    test_client.submit_all([mint])?;

    // However, this will fail
    assert!(test_client
        .poll_request(client::asset::by_account_id(account_id), |result| {
            let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");
            assets.iter().any(|asset| {
                asset.id().definition_id == asset_definition_id
                    && *asset.value() == AssetValue::Quantity(400_u32)
            })
        })
        .is_err());
    Ok(())
}

#[test]
fn non_mintable_asset_cannot_be_minted_if_registered_with_non_zero_value() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_610).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    // Given
    let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset =
        RegisterExpr::new(AssetDefinition::quantity(asset_definition_id.clone()).mintable_once());

    let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
    let register_asset = RegisterExpr::new(Asset::new(asset_id.clone(), 1_u32));

    // We can register the non-mintable token
    test_client.submit_all([create_asset, register_asset.clone()])?;
    test_client.poll_request(client::asset::by_account_id(account_id), |result| {
        let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");
        assets.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Quantity(1_u32)
        })
    })?;

    // But only once
    assert!(test_client.submit_blocking(register_asset).is_err());

    // And can't be minted
    let mint = MintExpr::new(1_u32.to_value(), IdBox::AssetId(asset_id));
    assert!(test_client.submit_blocking(mint).is_err());

    Ok(())
}

#[test]
fn non_mintable_asset_can_be_minted_if_registered_with_zero_value() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_630).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    // Given
    let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset =
        RegisterExpr::new(AssetDefinition::quantity(asset_definition_id.clone()).mintable_once());

    let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
    let register_asset = RegisterExpr::new(Asset::new(asset_id.clone(), 0_u32));
    let mint = MintExpr::new(1_u32.to_value(), IdBox::AssetId(asset_id));

    // We can register the non-mintable token wih zero value and then mint it
    let instructions: [InstructionExpr; 3] =
        [create_asset.into(), register_asset.into(), mint.into()];
    test_client.submit_all(instructions)?;
    test_client.poll_request(client::asset::by_account_id(account_id), |result| {
        let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");
        assets.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Quantity(1_u32)
        })
    })?;
    Ok(())
}
