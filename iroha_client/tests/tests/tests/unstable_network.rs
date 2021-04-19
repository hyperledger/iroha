use std::thread;

use iroha::config::Configuration;
use iroha_client::client;
use iroha_data_model::prelude::*;
use test_network::*;

const MAXIMUM_TRANSACTIONS_IN_BLOCK: u32 = 1;

#[test]
fn unstable_network_4_peers_1_fault() {
    unstable_network(4, 1, 20, 10);
}

#[test]
fn unstable_network_7_peers_1_fault() {
    unstable_network(7, 1, 20, 20);
}

#[test]
#[ignore = "This test does not guarantee to have positive outcome given a fixed time."]
fn unstable_network_7_peers_2_faults() {
    unstable_network(7, 2, 5, 50);
}

fn unstable_network(
    n_peers: usize,
    n_offline_peers: usize,
    n_transactions: usize,
    multiplier: u32,
) {
    // Given
    let (_, mut iroha_client) =
        Network::start_test_with_offline(n_peers, MAXIMUM_TRANSACTIONS_IN_BLOCK, n_offline_peers);
    let pipeline_time = Configuration::pipeline_time();

    thread::sleep(pipeline_time * multiplier);

    let account_id = AccountId::new("alice", "wonderland");
    let asset_definition_id = AssetDefinitionId::new("rose", "wonderland");
    // Initially there are 13 roses.
    let mut account_has_quantity = 13;

    //When
    for _ in 0..n_transactions {
        let quantity = 1;
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
        thread::sleep(pipeline_time * 2);
    }

    thread::sleep(pipeline_time);

    //Then
    iroha_client.poll_request_with_multiplier(
        &client::asset::by_account_id(account_id),
        multiplier,
        |result| {
            result
                .find_asset_by_id(&asset_definition_id)
                .map_or(false, |asset| {
                    *asset.value.read() == AssetValue::Quantity(account_has_quantity)
                })
        },
    );
}
