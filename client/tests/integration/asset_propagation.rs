#![allow(clippy::restriction)]

use std::{str::FromStr as _, thread};

use eyre::Result;
use iroha_client::client;
use iroha_crypto::KeyPair;
use iroha_data_model::{
    parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
    prelude::*,
};
use test_network::*;

use super::Configuration;

#[test]
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount_on_another_peer(
) -> Result<()> {
    // Given
    let (_rt, network, client) = <Network>::start_test_with_runtime(4, Some(10_450));
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Configuration::pipeline_time();

    client.submit_blocking(
        ParametersBuilder::new()
            .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, 1u32)?
            .into_set_parameters(),
    )?;

    let create_domain = RegisterBox::new(Domain::new(DomainId::from_str("domain")?));
    let account_id = AccountId::from_str("account@domain")?;
    let (public_key, _) = KeyPair::generate()?.into();
    let create_account = RegisterBox::new(Account::new(account_id.clone(), [public_key]));
    let asset_definition_id = AssetDefinitionId::from_str("xor#domain")?;
    let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()));
    client.submit_all(vec![
        create_domain.into(),
        create_account.into(),
        create_asset.into(),
    ])?;
    thread::sleep(pipeline_time * 3);
    //When
    let quantity: u32 = 200;
    client.submit(MintBox::new(
        quantity.to_value(),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    ))?;
    thread::sleep(pipeline_time);

    //Then
    let peer = network.peers.values().last().unwrap();
    client::Client::test(&peer.api_address, &peer.telemetry_address).poll_request(
        client::asset::by_account_id(account_id),
        |result| {
            result.iter().any(|asset| {
                asset.id().definition_id == asset_definition_id
                    && *asset.value() == AssetValue::Quantity(quantity)
            })
        },
    )?;
    Ok(())
}
