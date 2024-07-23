use std::{str::FromStr as _, thread};

use eyre::Result;
use iroha::{
    client,
    data_model::{parameter::BlockParameter, prelude::*},
};
use iroha_config::parameters::actual::Root as Config;
use nonzero_ext::nonzero;
use test_network::*;
use test_samples::gen_account_in;

#[test]
// This test is also covered at the UI level in the iroha_cli tests
// in test_mint_asset.py
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount_on_another_peer(
) -> Result<()> {
    // Given
    let (_rt, network, client) = Network::start_test_with_runtime(4, Some(10_450));
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Config::pipeline_time();

    client.submit_blocking(SetParameter::new(Parameter::Block(
        BlockParameter::MaxTransactions(nonzero!(1_u64)),
    )))?;

    let create_domain = Register::domain(Domain::new(DomainId::from_str("domain")?));
    let (account_id, _account_keypair) = gen_account_in("domain");
    let create_account = Register::account(Account::new(account_id.clone()));
    let asset_definition_id = AssetDefinitionId::from_str("xor#domain")?;
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    client.submit_all::<InstructionBox>([
        create_domain.into(),
        create_account.into(),
        create_asset.into(),
    ])?;
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
    client::Client::test(&peer.api_address).poll(|client| {
        let assets = client
            .query(client::asset::all())
            .filter_with(|asset| asset.id.account.eq(account_id))
            .execute_all()?;

        Ok(assets.iter().any(|asset| {
            *asset.id().definition() == asset_definition_id
                && *asset.value() == AssetValue::Numeric(quantity)
        }))
    })?;
    Ok(())
}
