#[cfg(test)]
mod tests {
    use iroha::config::Configuration;
    use iroha_client::{
        client::{self, Client},
        config::Configuration as ClientConfiguration,
    };
    use iroha_data_model::prelude::*;
    use std::{thread, time::Duration};
    use test_network::Peer as TestPeer;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
    const GENESIS_PATH: &str = "tests/genesis.json";

    #[test]
    //TODO: use cucumber_rust to write `gherkin` instead of code.
    fn client_sends_transaction_with_invalid_instruction_should_not_see_any_changes() {
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration.genesis_configuration.genesis_block_path = Some(GENESIS_PATH.to_string());
        let peer = TestPeer::new().expect("Failed to create peer");
        configuration.sumeragi_configuration.trusted_peers.peers =
            std::iter::once(peer.id.clone()).collect();

        let pipeline_time =
            Duration::from_millis(configuration.sumeragi_configuration.pipeline_time_ms());

        // Given
        peer.start_with_config(configuration.clone());
        thread::sleep(pipeline_time);

        //When
        let domain_name = "wonderland";
        let account_name = "alice";
        let account_id = AccountId::new(account_name, domain_name);
        let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
        let wrong_asset_definition_id = AssetDefinitionId::new("ksor", domain_name);
        let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
            AssetDefinition::new(asset_definition_id).into(),
        ));
        let quantity: u32 = 200;
        let mint_asset = MintBox::new(
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(
                wrong_asset_definition_id.clone(),
                account_id.clone(),
            )),
        );
        let mut client_config = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        client_config.torii_api_url = peer.api_address;
        let mut iroha_client = Client::new(&client_config);
        iroha_client
            .submit_all(vec![create_asset.into(), mint_asset.into()])
            .expect("Failed to prepare state.");
        thread::sleep(Duration::from_millis(
            &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
        ));
        //Then
        let request = client::asset::by_account_id(account_id);
        let query_result = iroha_client
            .request(&request)
            .expect("Failed to execute request.");
        if let QueryResult(Value::Vec(assets)) = query_result {
            assert_eq!(
                assets
                    .iter()
                    .filter(|asset| {
                        if let Value::Identifiable(IdentifiableBox::Asset(asset)) = asset {
                            asset.id.definition_id == wrong_asset_definition_id
                        } else {
                            false
                        }
                    })
                    .count(),
                0
            );
        } else {
            panic!("Wrong Query Result Type.");
        }
        let definition_query_result = iroha_client
            .request(&client::asset::all_definitions())
            .expect("Failed to execute request.");
        if let QueryResult(Value::Vec(asset_definitions)) = definition_query_result {
            assert_eq!(
                asset_definitions
                    .iter()
                    .filter(|asset_definition| {
                        if let Value::Identifiable(IdentifiableBox::AssetDefinition(
                            asset_definition,
                        )) = asset_definition
                        {
                            asset_definition.id == wrong_asset_definition_id
                        } else {
                            false
                        }
                    })
                    .count(),
                0
            );
        } else {
            panic!("Wrong Query Result Type.");
        }
    }
}
