#![allow(clippy::restriction)]

use std::thread;

use eyre::Result;
use iroha_client::client::{self, Client};
use iroha_crypto::KeyPair;
use iroha_data_model::{
    parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
    prelude::*,
};
use test_network::*;

use super::Configuration;

const N_BLOCKS: usize = 510;

#[ignore = "Takes a lot of time."]
#[test]
fn long_multiple_blocks_created() -> Result<()> {
    // Given
    let (_rt, network, client) = <Network>::start_test_with_runtime(4, Some(10_965));
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Configuration::pipeline_time();

    client.submit_blocking(
        ParametersBuilder::new()
            .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, 1u32)?
            .into_set_parameters(),
    )?;

    let create_domain = RegisterBox::new(Domain::new("domain".parse()?));
    let account_id: AccountId = "account@domain".parse()?;
    let (public_key, _) = KeyPair::generate()?.into();
    let create_account = RegisterBox::new(Account::new(account_id.clone(), [public_key]));
    let asset_definition_id: AssetDefinitionId = "xor#domain".parse()?;
    let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()));

    client.submit_all(vec![
        create_domain.into(),
        create_account.into(),
        create_asset.into(),
    ])?;

    thread::sleep(pipeline_time);

    let mut account_has_quantity = 0;
    //When
    for _ in 0..N_BLOCKS {
        let quantity: u32 = 1;
        let mint_asset = MintBox::new(
            quantity.to_value(),
            IdBox::AssetId(AssetId::new(
                asset_definition_id.clone(),
                account_id.clone(),
            )),
        );
        client.submit(mint_asset)?;
        account_has_quantity += quantity;
        thread::sleep(pipeline_time / 4);
    }

    thread::sleep(pipeline_time * 5);

    //Then
    let peer = network.peers().last().unwrap();
    Client::test(&peer.api_address, &peer.telemetry_address).poll_request(
        client::asset::by_account_id(account_id),
        |result| {
            result.iter().any(|asset| {
                asset.id().definition_id == asset_definition_id
                    && *asset.value() == AssetValue::Quantity(account_has_quantity)
            })
        },
    )?;
    Ok(())
}
