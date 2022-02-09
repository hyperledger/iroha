#![allow(clippy::restriction)]

use iroha_core::config::Configuration;
use test_network::{Peer as TestPeer, *};

#[test]
fn get_config() {
    // The underscored variables must not be dropped until end of closure.
    let (_dont_drop, _dont_drop_either, test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(vec![test_client.clone()], 0);

    let field = test_client.get_config_docs(&["torii"]).unwrap().unwrap();
    assert!(field.contains("IROHA_TORII"));

    let cfg: Configuration =
        serde_json::from_value(test_client.get_config_value().unwrap()).unwrap();
    let test = Configuration::test();
    assert_eq!(cfg.block_sync, test.block_sync);
    assert_eq!(cfg.network, test.network);
    assert_eq!(cfg.telemetry, test.telemetry);
}
