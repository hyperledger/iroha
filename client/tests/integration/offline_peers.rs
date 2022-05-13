#![allow(clippy::restriction)]

use iroha_client::client;
use iroha_data_model::prelude::*;
use test_network::*;
use tokio::runtime::Runtime;

#[test]
fn genesis_block_is_commited_with_some_offline_peers() {
    // Given
    let rt = Runtime::test();

    let (network, iroha_client) = rt.block_on(<Network>::start_test_with_offline(4, 1, 1));
    wait_for_genesis_committed(&network.clients(), 1);

    //When
    let alice_id: AccountId = "alice@wonderland".parse().expect("Valid");
    let alice_has_roses = 13;

    //Then
    let assets = iroha_client
        .request(client::asset::by_account_id(alice_id))
        .expect("Failed to execute request.");
    let asset = assets
        .iter()
        .find(|asset| asset.id().definition_id == "rose#wonderland".parse().expect("Valid"))
        .unwrap();
    assert_eq!(AssetValue::Quantity(alice_has_roses), *asset.value());
}
