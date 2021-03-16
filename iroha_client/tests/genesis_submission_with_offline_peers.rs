#[cfg(test)]
mod tests {
    use iroha::config::Configuration;
    use iroha_client::{
        client::{self, Client},
        config::Configuration as ClientConfiguration,
    };
    use iroha_data_model::prelude::*;
    use std::{thread, time::Duration};

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
    const N_PEERS: usize = 4;
    const MAX_FAULTS: u32 = 1;
    const OFFLINE_PEERS: usize = 1;
    const MAXIMUM_TRANSACTIONS_IN_BLOCK: u32 = 1;

    #[test]
    fn genesis_block_is_commited_with_some_offline_peers() {
        // Given
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration
            .queue_configuration
            .maximum_transactions_in_block = MAXIMUM_TRANSACTIONS_IN_BLOCK;
        configuration.sumeragi_configuration.max_faulty_peers = MAX_FAULTS;

        let pipeline_time =
            Duration::from_millis(configuration.sumeragi_configuration.pipeline_time_ms());

        let network = test_network::Network::new_with_offline_peers(
            Some(configuration),
            N_PEERS,
            OFFLINE_PEERS,
        )
        .expect("Failed to init peers");

        thread::sleep(pipeline_time * 3);

        let mut client_configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        client_configuration.torii_api_url = network.genesis.api_address;
        //When
        let mut iroha_client = Client::new(&client_configuration);
        let alice_id = AccountId::new("alice", "wonderland");
        let alice_has_roses = 13;
        //Then
        let request = client::asset::by_account_id(alice_id);
        let query_result = iroha_client
            .request(&request)
            .expect("Failed to execute request.");
        if let QueryResult(Value::Vec(assets)) = query_result {
            assert!(!assets.is_empty());
            if let Value::Identifiable(IdentifiableBox::Asset(asset)) =
                assets.first().expect("Asset should exist.")
            {
                assert_eq!(AssetValue::Quantity(alice_has_roses), asset.value);
            } else {
                panic!("Wrong Query Result Type.")
            }
        } else {
            panic!("Wrong Query Result Type.");
        }
    }
}
