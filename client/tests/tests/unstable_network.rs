#![allow(clippy::restriction)]

use std::{thread, time::Duration};

use iroha_client::client;
use iroha_core::config::Configuration;
use iroha_data_model::prelude::*;
use test_network::*;
use tokio::runtime::Runtime;

const MAXIMUM_TRANSACTIONS_IN_BLOCK: u32 = 1;

#[test]
fn unstable_network_4_peers_1_fault() {
    let n_peers = 4;
    let n_transactions = 20;
    // Given that the topology will resolve view changes by shift for `n_peers` consequent times
    // and having only 1 faulty peer guarantees us that at maximum in `n_peers` tries the block will be committed.
    // So for the worst case scenario for `n_transactions` given 1 transaction per block
    // the network will commit all of them in `n_peers * n_transactions` tries.
    let polling_max_attempts = n_peers * n_transactions;
    unstable_network(
        n_peers,
        1,
        n_transactions as usize,
        polling_max_attempts,
        Configuration::pipeline_time(),
    );
}

#[test]
fn unstable_network_7_peers_1_fault() {
    let n_peers = 7;
    let n_transactions = 20;
    let polling_max_attempts = n_peers * n_transactions;
    unstable_network(
        n_peers,
        1,
        n_transactions as usize,
        polling_max_attempts,
        Configuration::pipeline_time(),
    );
}

#[test]
#[ignore = "This test does not guarantee to have positive outcome given a fixed time."]
fn unstable_network_7_peers_2_faults() {
    unstable_network(7, 2, 5, 100, Configuration::pipeline_time());
}

fn unstable_network(
    n_peers: u32,
    n_offline_peers: u32,
    n_transactions: usize,
    polling_max_attempts: u32,
    polling_period: Duration,
) {
    drop(iroha_logger::install_panic_hook());
    let rt = Runtime::test();
    // Given
    let (_network, mut iroha_client) =
        rt.block_on(<Network>::start_test_with_offline_and_set_n_shifts(
            n_peers,
            MAXIMUM_TRANSACTIONS_IN_BLOCK,
            n_offline_peers,
            u64::from(n_peers),
        ));

    let pipeline_time = Configuration::pipeline_time();
    thread::sleep(pipeline_time * n_peers);

    let account_id = AccountId::new("alice", "wonderland");
    let asset_definition_id = AssetDefinitionId::new("rose", "wonderland");
    // Initially there are 13 roses.
    let mut account_has_quantity = 13;

    //When
    for _i in 0..n_transactions {
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
        thread::sleep(pipeline_time);
    }

    thread::sleep(pipeline_time);

    //Then
    iroha_client.poll_request_with_period(
        client::asset::by_account_id(account_id),
        polling_period,
        polling_max_attempts,
        |result| {
            result.iter().any(|asset| {
                asset.id.definition_id == asset_definition_id
                    && asset.value == AssetValue::Quantity(account_has_quantity)
            })
        },
    );
}
