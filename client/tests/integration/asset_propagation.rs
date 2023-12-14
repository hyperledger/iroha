use std::{str::FromStr as _, thread};

use eyre::Result;
use iroha_client::{
    client::{self, QueryResult},
    crypto::KeyPair,
    data_model::{
        parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
        prelude::*,
    },
};
use iroha_config::iroha::Configuration;
use test_network::*;

#[test]
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount_on_another_peer(
) -> Result<()> {
    // Given
    let (_rt, network, client) = Network::start_test_with_runtime(4, Some(10_450));
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Configuration::pipeline_time();

    client.submit_blocking(
        ParametersBuilder::new()
            .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, 1u32)?
            .into_set_parameters(),
    )?;

    let create_domain = RegisterExpr::new(Domain::new(DomainId::from_str("domain")?));
    let account_id = AccountId::from_str("account@domain")?;
    let (public_key, _) = KeyPair::generate()?.into();
    let create_account = RegisterExpr::new(Account::new(account_id.clone(), [public_key]));
    let asset_definition_id = AssetDefinitionId::from_str("xor#domain")?;
    let create_asset = RegisterExpr::new(AssetDefinition::quantity(asset_definition_id.clone()));
    client.submit_all([create_domain, create_account, create_asset])?;
    thread::sleep(pipeline_time * 3);
    //When
    let quantity: u32 = 200;
    client.submit(MintExpr::new(
        quantity.to_value(),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    ))?;
    thread::sleep(pipeline_time);

    //Then
    let peer = network.peers.values().last().unwrap();
    client::Client::test(&peer.api_address).poll_request(
        client::asset::by_account_id(account_id),
        |result| {
            let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");

            assets.iter().any(|asset| {
                asset.id().definition_id == asset_definition_id
                    && *asset.value() == AssetValue::Quantity(quantity)
            })
        },
    )?;
    Ok(())
}
