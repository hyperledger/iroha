#[cfg(test)]
mod tests {
    use async_std::task;
    use iroha::{config::Configuration, prelude::*};
    use iroha_client::{
        client::{self, Client},
        config::Configuration as ClientConfiguration,
    };
    use iroha_data_model::prelude::*;
    use std::{thread, time::Duration};
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";

    #[test]
    //TODO: use cucumber_rust to write `gherkin` instead of code.
    fn client_sends_transaction_with_invalid_instruction_should_not_see_any_changes() {
        // Given
        thread::spawn(create_and_start_iroha);
        thread::sleep(std::time::Duration::from_millis(300));
        let configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        //When
        let domain_name = "global";
        let account_name = "root";
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
        let mut iroha_client = Client::new(
            &ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
                .expect("Failed to load configuration."),
        );
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

    fn create_and_start_iroha() {
        let temp_dir = TempDir::new().expect("Failed to create TempDir.");
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration
            .kura_configuration
            .kura_block_store_path(temp_dir.path());
        let iroha = Iroha::new(configuration, AllowAll.into());
        task::block_on(iroha.start()).expect("Failed to start Iroha.");
        //Prevents temp_dir from clean up untill the end of the tests.
        #[allow(clippy::empty_loop)]
        loop {}
    }
}
