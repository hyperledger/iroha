#![allow(clippy::restriction, clippy::pedantic)]

use std::thread;

use iroha_client::client;
use iroha_core::prelude::*;
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

use super::Configuration;

#[test]
fn client_can_transfer_asset_to_another_account() {
    let (_rt, _peer, mut iroha_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![iroha_client.clone()], 0);
    let pipeline_time = Configuration::pipeline_time();

    let create_domain = RegisterBox::new(Domain::new("domain".parse().expect("Valid")));
    let account1_id: AccountId = "account1@domain".parse().expect("Valid");
    let account2_id: AccountId = "account2@domain".parse().expect("Valid");
    let (public_key1, _) = KeyPair::generate()
        .expect("Failed to generate KeyPair")
        .into();
    let (public_key2, _) = KeyPair::generate()
        .expect("Failed to generate KeyPair")
        .into();
    let create_account1 = RegisterBox::new(Account::new(account1_id.clone(), [public_key1]));
    let create_account2 = RegisterBox::new(Account::new(account2_id.clone(), [public_key2]));
    let asset_definition_id: AssetDefinitionId = "xor#domain".parse().expect("Valid");
    let quantity: u32 = 200;
    let create_asset =
        RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()).build());
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account1_id.clone(),
        )),
    );

    iroha_client
        .submit_all(vec![
            create_domain.into(),
            create_account1.into(),
            create_account2.into(),
            create_asset.into(),
            mint_asset.into(),
        ])
        .expect("Failed to prepare state.");

    thread::sleep(pipeline_time * 2);

    //When
    let quantity = 20;
    let transfer_asset = TransferBox::new(
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), account1_id)),
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account2_id.clone(),
        )),
    );
    iroha_client
        .submit_till(
            transfer_asset,
            client::asset::by_account_id(account2_id.clone()),
            |result| {
                result.iter().any(|asset| {
                    asset.id().definition_id == asset_definition_id
                        && *asset.value() == AssetValue::Quantity(quantity)
                        && asset.id().account_id == account2_id
                })
            },
        )
        .expect("Test case failure.");
}
