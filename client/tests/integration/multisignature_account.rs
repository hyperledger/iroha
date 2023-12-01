use std::thread;

use eyre::Result;
use iroha_client::{
    client::{self, Client, QueryResult},
    crypto::KeyPair,
    data_model::prelude::*,
};
use iroha_config::iroha::Configuration;
use test_network::*;

#[test]
fn transaction_signed_by_new_signatory_of_account_should_pass() -> Result<()> {
    let (_rt, peer, client) = <PeerBuilder>::new().with_port(10_605).start_with_runtime();
    wait_for_genesis_committed(&[client.clone()], 0);
    let pipeline_time = Configuration::pipeline_time();

    // Given
    let account_id: AccountId = "alice@wonderland".parse().expect("Valid");
    let asset_definition_id: AssetDefinitionId = "xor#wonderland".parse().expect("Valid");
    let create_asset = RegisterExpr::new(AssetDefinition::quantity(asset_definition_id.clone()));
    let key_pair = KeyPair::generate()?;
    let add_signatory = MintExpr::new(
        key_pair.public_key().clone(),
        IdBox::AccountId(account_id.clone()),
    );

    let instructions: [InstructionExpr; 2] = [create_asset.into(), add_signatory.into()];
    client.submit_all(instructions)?;
    thread::sleep(pipeline_time * 2);
    //When
    let quantity: u32 = 200;
    let mint_asset = MintExpr::new(
        quantity.to_value(),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    Client::test_with_key(&peer.api_address, key_pair).submit_till(
        mint_asset,
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
