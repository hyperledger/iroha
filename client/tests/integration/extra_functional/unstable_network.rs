use std::time::Duration;

use iroha::{
    client,
    data_model::{
        parameter::{BlockParameter, Parameter},
        prelude::*,
    },
};
use iroha_config::parameters::actual::Root as Config;
use nonzero_ext::nonzero;
use rand::seq::SliceRandom;
use test_network::*;
use test_samples::ALICE_ID;

#[test]
fn unstable_network_5_peers_1_fault() {
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
fn unstable_network_8_peers_1_fault() {
    let n_peers = 7;
    let n_transactions = 20;
    unstable_network(n_peers, 1, n_transactions, false, 10_850);
}

#[test]
#[ignore = "This test does not guarantee to have positive outcome given a fixed time."]
fn unstable_network_9_peers_2_faults() {
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

    // Given
    let mut configuration = Config::test();
    #[cfg(debug_assertions)]
    {
        configuration.sumeragi.debug_force_soft_fork = force_soft_fork;
    }
    let (rt, network, mut iroha) = NetworkBuilder::new(n_peers + n_offline_peers, Some(port))
        .with_config(configuration)
        // Note: it is strange that we have `n_offline_peers` but don't set it as offline
        .with_offline_peers(0)
        .create_with_runtime();
    rt.block_on(wait_for_genesis_committed_async(
        &network.clients(),
        n_offline_peers,
    ));
    // Set ttl to max to prevent the case when transaction got expired before end up in the block
    iroha.transaction_ttl = Some(Duration::from_millis(u64::MAX));
    iroha
        .submit_blocking(SetParameter::new(Parameter::Block(
            BlockParameter::MaxTransactions(nonzero!(5_u64)),
        )))
        .unwrap();

    let account_id = ALICE_ID.clone();
    let asset_definition_id: AssetDefinitionId = "camomile#wonderland".parse().expect("Valid");
    let register_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    iroha
        .submit_blocking(register_asset)
        .expect("Failed to register asset");
    // Initially there are 0 camomile
    let mut account_has_quantity = Numeric::ZERO;

    let mut rng = rand::thread_rng();
    let freezers = network.get_freeze_status_handles();

    //When
    for _i in 0..n_transactions {
        // Make random peers faulty.
        for f in freezers.choose_multiple(&mut rng, n_offline_peers as usize) {
            f.freeze();
        }

        let quantity = Numeric::ONE;
        let mint_asset = Mint::asset_numeric(
            quantity,
            AssetId::new(asset_definition_id.clone(), account_id.clone()),
        );
        iroha
            .submit_blocking(mint_asset)
            .expect("Failed to mint asset.");

        account_has_quantity = account_has_quantity.checked_add(quantity).unwrap();

        let assets = iroha
            .query(client::asset::all())
            .filter_with(|asset| asset.id.account.eq(account_id.clone()))
            .execute_all()
            .expect("failed to query assets");

        assert!(assets.iter().any(|asset| {
            *asset.id().definition() == asset_definition_id
                && *asset.value() == AssetValue::Numeric(account_has_quantity)
        }));

        // Return all peers to normal function.
        for f in &freezers {
            f.unfreeze();
        }
    }
}
