use std::thread;

use eyre::Result;
use iroha_client::{
    client::{self, Client, QueryResult},
    crypto::KeyPair,
    data_model::{
        parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
        prelude::*,
    },
};
use iroha_config::iroha::Configuration;
use test_network::*;

const N_BLOCKS: usize = 510;

#[ignore = "Takes a lot of time."]
#[test]
fn long_multiple_blocks_created() -> Result<()> {
    // Given
    let (_rt, network, client) = Network::start_test_with_runtime(4, Some(10_965));
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Configuration::pipeline_time();

    client.submit_blocking(
        ParametersBuilder::new()
            .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, 1u32)?
            .into_set_parameters(),
    )?;

    let create_domain = RegisterExpr::new(Domain::new("domain".parse()?));
    let account_id: AccountId = "account@domain".parse()?;
    let (public_key, _) = KeyPair::generate()?.into();
    let create_account = RegisterExpr::new(Account::new(account_id.clone(), [public_key]));
    let asset_definition_id: AssetDefinitionId = "xor#domain".parse()?;
    let create_asset = RegisterExpr::new(AssetDefinition::quantity(asset_definition_id.clone()));

    client.submit_all([create_domain, create_account, create_asset])?;

    thread::sleep(pipeline_time);

    let mut account_has_quantity = 0;
    //When
    for _ in 0..N_BLOCKS {
        let quantity: u32 = 1;
        let mint_asset = MintExpr::new(
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
    Client::test(&peer.api_address).poll_request(
        client::asset::by_account_id(account_id),
        |result| {
            let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");

            assets.iter().any(|asset| {
                asset.id().definition_id == asset_definition_id
                    && *asset.value() == AssetValue::Quantity(account_has_quantity)
            })
        },
    )?;
    Ok(())
}
