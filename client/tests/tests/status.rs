#![allow(clippy::pedantic, clippy::restriction)]

use std::thread;

use iroha_client::client::Client;
use iroha_core::{config::Configuration, torii::Status};
use iroha_crypto::KeyPair;
use iroha_data_model::prelude::*;
use test_network::{Network as TestNetwork, TestConfiguration};

fn status(client: &Client) -> Status {
    serde_json::from_value(client.get_status().unwrap()).unwrap()
}

fn ready_for_mint(client: &mut Client) -> MintBox {
    let create_domain = RegisterBox::new(IdentifiableBox::Domain(Domain::new("domain").into()));
    let account_id = AccountId::new("account", "domain");
    let create_account = RegisterBox::new(IdentifiableBox::NewAccount(
        NewAccount::with_signatory(
            account_id.clone(),
            KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        )
        .into(),
    ));
    let asset_definition_id = AssetDefinitionId::new("asset", "domain");
    let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new_quantity(asset_definition_id.clone()).into(),
    ));

    client
        .submit_all(vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ])
        .expect("Failed to prepare state.");

    MintBox::new(
        Value::U32(1),
        IdBox::AssetId(AssetId::new(asset_definition_id, account_id)),
    )
}

#[test]
fn connected_peers() {
    const N_PEERS: u64 = 4;

    let (rt, network, mut client) = <TestNetwork>::start_test_with_runtime(N_PEERS as u32, 1);
    client.status_url.insert_str(0, "http://");

    // Confirm all peers connected
    assert_eq!(status(&client).peers, N_PEERS - 1);

    // Add a peer then #peers should be incremented
    let (mut peer, _) = rt.block_on(network.add_peer());
    thread::sleep(std::time::Duration::from_millis(5_000));
    // FIXME 'assertion failed: `(left == right)` left: `3`, right: `4`'
    assert_eq!(status(&client).peers, N_PEERS);

    // Drop the peer then #peers should be decremented
    peer.stop();
    assert_eq!(status(&client).peers, N_PEERS - 1);
}

#[test]
fn committed_blocks() {
    const N_BLOCKS: u64 = 10;
    const MAX_TXS_IN_BLOCK: u32 = 1;

    let (_, _, mut client) = <TestNetwork>::start_test_with_runtime(4, MAX_TXS_IN_BLOCK);
    client.status_url.insert_str(0, "http://");
    let pipeline_time = Configuration::pipeline_time();
    thread::sleep(pipeline_time * 2);

    // Confirm only the genesis block committed
    assert_eq!(status(&client).blocks, 1);

    // Send transactions then #blocks should be increased
    // FIXME Not sending message to myself
    let mint = ready_for_mint(&mut client);
    thread::sleep(pipeline_time);
    let n_txs = N_BLOCKS * MAX_TXS_IN_BLOCK as u64;
    for _ in 0..n_txs {
        client.submit(mint.clone()).unwrap();
        thread::sleep(pipeline_time / 4);
    }
    thread::sleep(pipeline_time * 5);
    assert_eq!(status(&client).blocks, 1 + N_BLOCKS)
}
