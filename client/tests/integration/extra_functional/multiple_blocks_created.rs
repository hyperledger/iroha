use std::thread;

use eyre::Result;
use iroha_client::{
    client::{self, Client, QueryResult},
    data_model::{
        parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
        prelude::*,
    },
};
use iroha_config::parameters::actual::Root as Config;
use test_network::*;
use test_samples::gen_account_in;

const N_BLOCKS: usize = 510;

#[ignore = "Takes a lot of time."]
#[test]
fn long_multiple_blocks_created() -> Result<()> {
    // Given
    let (_rt, network, client) = Network::start_test_with_runtime(4, Some(10_965));
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Config::pipeline_time();

    client.submit_all_blocking(
        ParametersBuilder::new()
            .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, 1u32)?
            .into_set_parameters(),
    )?;

    let create_domain: InstructionBox = Register::domain(Domain::new("domain".parse()?)).into();
    let (account_id, _account_keypair) = gen_account_in("domain");
    let create_account = Register::account(Account::new(account_id.clone())).into();
    let asset_definition_id: AssetDefinitionId = "xor#domain".parse()?;
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone())).into();

    client.submit_all([create_domain, create_account, create_asset])?;

    thread::sleep(pipeline_time);

    let mut account_has_quantity = Numeric::ZERO;
    let quantity = numeric!(1);
    //When
    for _ in 0..N_BLOCKS {
        let mint_asset = Mint::asset_numeric(
            quantity,
            AssetId::new(asset_definition_id.clone(), account_id.clone()),
        );
        client.submit(mint_asset)?;
        account_has_quantity = account_has_quantity.checked_add(quantity).unwrap();
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
                    && *asset.value() == AssetValue::Numeric(account_has_quantity)
            })
        },
    )?;
    Ok(())
}
