use std::thread;

use eyre::Result;
use iroha::{
    client::{self, Client},
    data_model::{parameter::BlockParameter, prelude::*},
};
use iroha_config::parameters::actual::Root as Config;
use nonzero_ext::nonzero;
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

    client.submit_blocking(SetParameter::new(Parameter::Block(
        BlockParameter::MaxTransactions(nonzero!(1_u64)),
    )))?;

    let create_domain = Register::domain(Domain::new("domain".parse()?));
    let (account_id, _account_keypair) = gen_account_in("domain");
    let create_account = Register::account(Account::new(account_id.clone()));
    let asset_definition_id: AssetDefinitionId = "xor#domain".parse()?;
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));

    client.submit_all::<InstructionBox>([
        create_domain.into(),
        create_account.into(),
        create_asset.into(),
    ])?;

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
    Client::test(&peer.api_address).poll(|client| {
        let assets = client
            .query(client::asset::all())
            .filter_with(|asset| asset.id.account.eq(account_id))
            .execute_all()?;

        Ok(assets.iter().any(|asset| {
            *asset.id().definition() == asset_definition_id
                && *asset.value() == AssetValue::Numeric(account_has_quantity)
        }))
    })?;
    Ok(())
}
