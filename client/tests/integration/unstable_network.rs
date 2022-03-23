#![allow(clippy::restriction)]

use std::{thread, time::Duration};

use iroha_client::client::{self, Client};
use iroha_config::logger;
use iroha_data_model::prelude::*;
use iroha_logger::Level;
use test_network::*;
use tokio::runtime::Runtime;

use super::Configuration;

const MAXIMUM_TRANSACTIONS_IN_BLOCK: u32 = 5;

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
    let (network, mut iroha_client) = rt.block_on(async {
        let mut configuration = Configuration::test();
        configuration.queue.maximum_transactions_in_block = MAXIMUM_TRANSACTIONS_IN_BLOCK;
        configuration.sumeragi.n_topology_shifts_before_reshuffle = u64::from(n_peers);
        configuration.logger.max_log_level = Level(logger::Level::ERROR).into();
        let network =
            <Network>::new_with_offline_peers(Some(configuration), n_peers, n_offline_peers)
                .await
                .expect("Failed to init peers");
        let client = Client::test(
            &network.genesis.api_address,
            &network.genesis.telemetry_address,
        );
        (network, client)
    });
    wait_for_genesis_committed(&network.clients(), n_offline_peers);

    let pipeline_time = Configuration::pipeline_time();

    let account_id: AccountId = "alice@wonderland".parse().expect("Valid");
    let asset_definition_id: AssetDefinitionId = "rose#wonderland".parse().expect("Valid");
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
                asset.id().definition_id == asset_definition_id
                    && *asset.value() == AssetValue::Quantity(account_has_quantity)
            })
        },
    );
}
