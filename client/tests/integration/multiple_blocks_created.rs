#![allow(clippy::restriction)]

use std::thread;

use iroha_client::client::{self, Client};
use iroha_core::prelude::*;
use iroha_data_model::prelude::*;
use test_network::*;

use super::Configuration;

const N_BLOCKS: usize = 510;

#[ignore = "Takes a lot of time."]
#[test]
fn long_multiple_blocks_created() {
    // Given
    let (_rt, network, mut iroha_client) = <Network>::start_test_with_runtime(4, 1);
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Configuration::pipeline_time();

    let create_domain = RegisterBox::new(Domain::new("domain".parse().expect("Valid")));
    let account_id: AccountId = "account@domain".parse().expect("Valid");
    let create_account = RegisterBox::new(Account::new(
        account_id.clone(),
        [KeyPair::generate()
            .expect("Failed to generate KeyPair.")
            .public_key],
    ));
    let asset_definition_id: AssetDefinitionId = "xor#domain".parse().expect("Valid");
    let create_asset = RegisterBox::new(AssetDefinition::new_quantity(asset_definition_id.clone()));

    iroha_client
        .submit_all(vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ])
        .expect("Failed to prepare state.");

    thread::sleep(pipeline_time);

    let mut account_has_quantity = 0;
    //When
    for _ in 0..N_BLOCKS {
        let quantity: u32 = 1;
        let mint_asset = MintBox::new(
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(
                asset_definition_id.clone(),
                account_id.clone(),
            )),
        );
        iroha_client
            .submit(mint_asset)
            .expect("Failed to create asset.");
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
    );
}
