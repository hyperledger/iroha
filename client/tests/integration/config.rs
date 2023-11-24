use iroha_data_model::Level;
use test_network::*;

use super::Configuration;

#[test]
fn config_endpoints() {
    // The underscored variables must not be dropped until end of closure.
    let (_dont_drop, _dont_drop_either, test_client) =
        <PeerBuilder>::new().with_port(10_685).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);
    let test_cfg = Configuration::test();
    const NEW_LOG_LEVEL: Level = Level::TRACE;

    // Just to be sure this test suite is not useless
    assert_ne!(test_cfg.logger.max_log_level.value(), NEW_LOG_LEVEL);

    // Retrieving through API
    let mut dto = test_client.get_config().unwrap();
    assert_eq!(
        dto.logger.max_log_level,
        test_cfg.logger.max_log_level.value()
    );

    // Updating the log level
    dto.logger.max_log_level = NEW_LOG_LEVEL;
    test_client.set_config(dto).unwrap();

    // FIXME: The updated value is not reflected
    //        https://github.com/hyperledger/iroha/issues/4079

    // // Checking the updated value
    // let dto = test_client.get_config().unwrap();
    // assert_eq!(dto.logger.max_log_level, NEW_LOG_LEVEL);
}
