#![allow(clippy::restriction)]

use std::thread;

use eyre::Result;
use iroha_client::client::{self, Client};
use iroha_core::prelude::*;
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

use super::Configuration;

#[test]
fn transaction_signed_by_new_signatory_of_account_should_pass() -> Result<()> {
    let (_rt, peer, mut iroha_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![iroha_client.clone()], 0);
    let pipeline_time = Configuration::pipeline_time();

    // Given
    let account_id: AccountId = "alice@wonderland".parse().expect("Valid");
    let asset_definition_id: AssetDefinitionId = "xor#wonderland".parse().expect("Valid");
    let create_asset = RegisterBox::new(AssetDefinition::new_quantity(asset_definition_id.clone()));
    let key_pair = KeyPair::generate()?;
    let add_signatory = MintBox::new(
        key_pair.public_key.clone(),
        IdBox::AccountId(account_id.clone()),
    );

    iroha_client.submit_all(vec![create_asset.into(), add_signatory.into()])?;
    thread::sleep(pipeline_time * 2);
    //When
    let quantity: u32 = 200;
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    Client::test_with_key(&peer.api_address, &peer.telemetry_address, key_pair).submit_till(
        mint_asset,
        client::asset::by_account_id(account_id),
        |result| {
            result.iter().any(|asset| {
                asset.id().definition_id == asset_definition_id
                    && *asset.value() == AssetValue::Quantity(quantity)
            })
        },
    );
    Ok(())
}
