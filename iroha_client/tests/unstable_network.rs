#[cfg(test)]
mod tests {
    use iroha::config::Configuration;
    use iroha_client::{
        client::{self, Client},
        config::Configuration as ClientConfiguration,
    };
    use iroha_data_model::prelude::*;
    use std::thread;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const TRUSTED_PEERS_PATH: &str = "tests/test_trusted_peers.json";
    const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
    const MAXIMUM_TRANSACTIONS_IN_BLOCK: u32 = 1;

    #[test]
    fn unstable_network_4_peers_1_fault() {
        unstable_network(4, 1, 1, 20, 5);
    }

    #[test]
    fn unstable_network_7_peers_1_fault() {
        unstable_network(7, 2, 1, 20, 10);
    }

    #[test]
    #[ignore = "This test does not guarantee to have positive outcome given a fixed time."]
    fn unstable_network_7_peers_2_faults() {
        unstable_network(7, 2, 2, 5, 40);
    }

    fn unstable_network(
        n_peers: usize,
        max_faults: u32,
        n_offline_peers: usize,
        n_transactions: usize,
        wait_multiplier: u32,
    ) {
        // Given
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration
            .load_trusted_peers_from_path(TRUSTED_PEERS_PATH)
            .expect("Failed to load trusted peers.");
        configuration
            .queue_configuration
            .maximum_transactions_in_block = MAXIMUM_TRANSACTIONS_IN_BLOCK;
        configuration.sumeragi_configuration.max_faulty_peers = max_faults;

        let pipeline_time = std::time::Duration::from_millis(
            configuration.sumeragi_configuration.pipeline_time_ms(),
        );

        let network = test_network::Network::new_with_offline_peers(
            Some(configuration),
            n_peers,
            n_offline_peers,
        )
        .expect("Failed to init peers");

        thread::sleep(pipeline_time * 5);
        let domain_name = "wonderland";
        let account_name = "alice";
        let account_id = AccountId::new(account_name, domain_name);
        let asset_definition_id = AssetDefinitionId::new("rose", domain_name);
        let mut client_configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        client_configuration.torii_api_url = network.genesis.api_address;
        let mut iroha_client = Client::new(&client_configuration);
        // Initially there are 13 roses.
        let mut account_has_quantity = 13;

        //When
        for _ in 0..n_transactions {
            let quantity = 1;
            let mint_asset = MintBox::new(
                Value::U32(quantity),
                IdBox::AssetId(AssetId::new(
                    asset_definition_id.clone(),
                    account_id.clone(),
                )),
            );
            let _ = iroha_client
                .submit(mint_asset.into())
                .expect("Failed to create asset.");
            account_has_quantity += quantity;
            thread::sleep(pipeline_time * 2);
        }

        thread::sleep(pipeline_time * wait_multiplier);
        //Then
        let mut iroha_client = Client::new(&client_configuration);
        let request = client::asset::by_account_id(account_id);
        let query_result = iroha_client
            .request(&request)
            .expect("Failed to execute request.");

        if let QueryResult(Value::Vec(assets)) = query_result {
            if let Some(Value::Identifiable(IdentifiableBox::Asset(asset))) = assets.first() {
                assert_eq!(AssetValue::Quantity(account_has_quantity), asset.value);
                return;
            }
        }

        panic!("Wrong Query Result Type.");
    }
}
