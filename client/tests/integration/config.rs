#![allow(clippy::restriction)]

use test_network::*;

use super::{Builder, Configuration, ConfigurationProxy};

#[test]
fn get_config() {
    // The underscored variables must not be dropped until end of closure.
    let (_dont_drop, _dont_drop_either, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let field = test_client.get_config_docs(&["torii"]).unwrap().unwrap();
    assert!(field.contains("IROHA_TORII"));

    let test = Configuration::test();
    let cfg_proxy: ConfigurationProxy =
        serde_json::from_value(test_client.get_config_value().unwrap()).unwrap();
    assert_eq!(
        cfg_proxy.block_sync.unwrap().build().unwrap(),
        test.block_sync
    );
    assert_eq!(cfg_proxy.network.unwrap().build().unwrap(), test.network);
    assert_eq!(
        cfg_proxy.telemetry.unwrap().build().unwrap(),
        test.telemetry
    );
}
