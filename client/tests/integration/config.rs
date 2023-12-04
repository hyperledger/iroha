use iroha_data_model::Level;
use test_network::*;

#[tokio::test]
async fn config_endpoints() {
    const NEW_LOG_LEVEL: Level = Level::ERROR;

    // The underscored variables must not be dropped until end of closure.
    let (_dont_drop, peer, test_client) =
        <PeerBuilder>::new().with_port(10_685).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);
    let init_log_level = peer
        .iroha
        .as_ref()
        .unwrap()
        .kiso
        .get_dto()
        .await
        .unwrap()
        .logger
        .level;

    // Just to be sure this test suite is not useless
    assert_ne!(init_log_level, NEW_LOG_LEVEL);

    // Retrieving through API
    let mut dto = test_client.get_config().expect("Client can always get it");
    assert_eq!(dto.logger.level, init_log_level);

    // Updating the log level
    dto.logger.level = NEW_LOG_LEVEL;
    test_client.set_config(dto).expect("New config is valid");

    // Checking the updated value
    dto = test_client.get_config().unwrap();
    assert_eq!(dto.logger.level, NEW_LOG_LEVEL);

    // Restoring value
    dto.logger.level = init_log_level;
    test_client.set_config(dto).expect("Also valid DTO");
}
