use core::sync::atomic::Ordering;
use std::thread;

use iroha_client::{
    client::{self, Client, QueryResult},
    data_model::{prelude::*, Level},
};
use iroha_config::iroha::Configuration;
use rand::seq::SliceRandom;
use test_network::*;
use tokio::runtime::Runtime;

const MAX_TRANSACTIONS_IN_BLOCK: u32 = 5;

#[test]
fn unstable_network_4_peers_1_fault() {
    let n_peers = 4;
    let n_transactions = 20;
    unstable_network(n_peers, 1, n_transactions, false, 10_805);
}

#[test]
fn soft_fork() {
    let n_peers = 4;
    let n_transactions = 20;
    unstable_network(n_peers, 0, n_transactions, true, 10_830);
}

#[test]
fn unstable_network_7_peers_1_fault() {
    let n_peers = 7;
    let n_transactions = 20;
    unstable_network(n_peers, 1, n_transactions, false, 10_850);
}

#[test]
#[ignore = "This test does not guarantee to have positive outcome given a fixed time."]
fn unstable_network_7_peers_2_faults() {
    unstable_network(7, 2, 5, false, 10_890);
}

fn unstable_network(
    n_peers: u32,
    n_offline_peers: u32,
    n_transactions: usize,
    force_soft_fork: bool,
    port: u16,
) {
    if let Err(error) = iroha_logger::install_panic_hook() {
        eprintln!("Installing panic hook failed: {error}");
    }
    let rt = Runtime::test();
    // Given
    let (network, iroha_client) = rt.block_on(async {
        let mut configuration = Configuration::test();
        configuration.sumeragi.max_transactions_in_block = MAX_TRANSACTIONS_IN_BLOCK;
        configuration.logger.max_log_level = Level::INFO.into();
        #[cfg(debug_assertions)]
        {
            configuration.sumeragi.debug_force_soft_fork = force_soft_fork;
        }
        let network = Network::new_with_offline_peers(
            Some(configuration),
            n_peers + n_offline_peers,
            0,
            Some(port),
        )
        .await
        .expect("Failed to init peers");
        let client = Client::test(&network.genesis.api_address);
        (network, client)
    });
    wait_for_genesis_committed(&network.clients(), n_offline_peers);

    let pipeline_time = Configuration::pipeline_time();

    let account_id: AccountId = "alice@wonderland".parse().expect("Valid");
    let asset_definition_id: AssetDefinitionId = "camomile#wonderland".parse().expect("Valid");
    let register_asset = RegisterExpr::new(AssetDefinition::quantity(asset_definition_id.clone()));
    iroha_client
        .submit_blocking(register_asset)
        .expect("Failed to register asset");
    // Initially there are 0 camomile
    let mut account_has_quantity = 0;

    let mut rng = rand::thread_rng();
    let freezers = {
        let mut freezers = network.get_freeze_status_handles();
        freezers.remove(0); // remove genesis peer
        freezers
    };

    //When
    for _i in 0..n_transactions {
        // Make random peers faulty.
        for f in freezers.choose_multiple(&mut rng, n_offline_peers as usize) {
            f.store(true, Ordering::SeqCst);
        }

        let quantity = 1;
        let mint_asset = MintExpr::new(
            quantity.to_value(),
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

        iroha_client
            .poll_request_with_period(
                client::asset::by_account_id(account_id.clone()),
                Configuration::pipeline_time(),
                4,
                |result| {
                    let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");

                    assets.iter().any(|asset| {
                        asset.id().definition_id == asset_definition_id
                            && *asset.value() == AssetValue::Quantity(account_has_quantity)
                    })
                },
            )
            .expect("Test case failure.");

        // Return all peers to normal function.
        for f in &freezers {
            f.store(false, Ordering::SeqCst);
        }
    }
}
