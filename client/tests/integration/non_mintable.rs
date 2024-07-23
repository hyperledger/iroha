use std::str::FromStr as _;

use eyre::Result;
use iroha::{
    client,
    data_model::{isi::InstructionBox, prelude::*},
};
use test_network::*;
use test_samples::ALICE_ID;

#[test]
fn non_mintable_asset_can_be_minted_once_but_not_twice() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_625).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    // Given
    let account_id = ALICE_ID.clone();
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset = Register::asset_definition(
        AssetDefinition::numeric(asset_definition_id.clone()).mintable_once(),
    );

    let metadata = Metadata::default();

    let mint = Mint::asset_numeric(
        200_u32,
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
    );

    let instructions: [InstructionBox; 2] = [create_asset.into(), mint.clone().into()];
    let tx = test_client.build_transaction(instructions, metadata);

    // We can register and mint the non-mintable token
    test_client.submit_transaction(&tx)?;
    test_client.poll(|client| {
        let assets = client
            .query(client::asset::all())
            .filter_with(|asset| asset.id.account.eq(account_id.clone()))
            .execute_all()?;
        Ok(assets.iter().any(|asset| {
            *asset.id().definition() == asset_definition_id
                && *asset.value() == AssetValue::Numeric(numeric!(200))
        }))
    })?;

    // We can submit the request to mint again.
    test_client.submit_all([mint])?;

    // However, this will fail
    assert!(test_client
        .poll(|client| {
            let assets = client
                .query(client::asset::all())
                .filter_with(|asset| asset.id.account.eq(account_id.clone()))
                .execute_all()?;
            Ok(assets.iter().any(|asset| {
                *asset.id().definition() == asset_definition_id
                    && *asset.value() == AssetValue::Numeric(numeric!(400))
            }))
        })
        .is_err());
    Ok(())
}

#[test]
fn non_mintable_asset_cannot_be_minted_if_registered_with_non_zero_value() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_610).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    // Given
    let account_id = ALICE_ID.clone();
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset = Register::asset_definition(
        AssetDefinition::numeric(asset_definition_id.clone()).mintable_once(),
    );

    let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
    let register_asset = Register::asset(Asset::new(asset_id.clone(), 1_u32));

    // We can register the non-mintable token
    test_client
        .submit_all::<InstructionBox>([create_asset.into(), register_asset.clone().into()])?;
    test_client.poll(|client| {
        let assets = client
            .query(client::asset::all())
            .filter_with(|asset| asset.id.account.eq(account_id.clone()))
            .execute_all()?;
        Ok(assets.iter().any(|asset| {
            *asset.id().definition() == asset_definition_id
                && *asset.value() == AssetValue::Numeric(numeric!(1))
        }))
    })?;

    // But only once
    assert!(test_client.submit_blocking(register_asset).is_err());

    // And can't be minted
    let mint = Mint::asset_numeric(1u32, asset_id);
    assert!(test_client.submit_blocking(mint).is_err());

    Ok(())
}

#[test]
fn non_mintable_asset_can_be_minted_if_registered_with_zero_value() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_630).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    // Given
    let account_id = ALICE_ID.clone();
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset = Register::asset_definition(
        AssetDefinition::numeric(asset_definition_id.clone()).mintable_once(),
    );

    let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
    let register_asset = Register::asset(Asset::new(asset_id.clone(), 0_u32));
    let mint = Mint::asset_numeric(1u32, asset_id);

    // We can register the non-mintable token wih zero value and then mint it
    test_client.submit_all::<InstructionBox>([
        create_asset.into(),
        register_asset.into(),
        mint.into(),
    ])?;
    test_client.poll(|client| {
        let assets = client
            .query(client::asset::all())
            .filter_with(|asset| asset.id.account.eq(account_id.clone()))
            .execute_all()?;

        Ok(assets.iter().any(|asset| {
            *asset.id().definition() == asset_definition_id
                && *asset.value() == AssetValue::Numeric(numeric!(1))
        }))
    })?;
    Ok(())
}
