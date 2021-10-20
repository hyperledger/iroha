#![allow(clippy::restriction)]

use iroha_core::config::Configuration;
use test_network::{Peer as TestPeer, *};

#[test]
fn get_config() {
    let (_rt, _peer, cl) = <TestPeer>::start_test_with_runtime();

    let field = cl.get_config_docs(&["torii"]).unwrap().unwrap();
    assert!(field.contains("IROHA_TORII"));

    let cfg: Configuration = serde_json::from_value(cl.get_config_value().unwrap()).unwrap();
    let test = Configuration::test();
    assert_eq!(cfg.block_sync, test.block_sync);
    assert_eq!(cfg.network, test.network);
    assert_eq!(cfg.telemetry, test.telemetry);
}
