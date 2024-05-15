use std::{str::FromStr as _, thread};

use eyre::Result;
use iroha_client::{
    client::{self, QueryResult},
    data_model::{
        parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
        prelude::*,
    },
};
use iroha_config::parameters::actual::Root as Config;
use test_network::*;
use test_samples::gen_account_in;

#[test]
// This test is also covered at the UI level in the iroha_client_cli tests
// in test_mint_asset.py
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount_on_another_peer(
) -> Result<()> {
    // Given
    let (_rt, network, client) = Network::start_test_with_runtime(4, Some(10_450));
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Config::pipeline_time();

    client.submit_all_blocking(
        ParametersBuilder::new()
            .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, 1u32)?
            .into_set_parameters(),
    )?;

    let create_domain: InstructionBox =
        Register::domain(Domain::new(DomainId::from_str("domain")?)).into();
    let (account_id, _account_keypair) = gen_account_in("domain");
    let create_account = Register::account(Account::new(account_id.clone())).into();
    let asset_definition_id = AssetDefinitionId::from_str("xor#domain")?;
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone())).into();
    client.submit_all([create_domain, create_account, create_asset])?;
    thread::sleep(pipeline_time * 3);
    //When
    let quantity = numeric!(200);
    client.submit(Mint::asset_numeric(
        quantity,
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
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
                    && *asset.value() == AssetValue::Numeric(quantity)
            })
        },
    )?;
    Ok(())
}
