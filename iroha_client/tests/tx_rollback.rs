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
        let create_asset = Register::<Domain, AssetDefinition>::new(
            AssetDefinition::new(asset_definition_id.clone()),
            domain_name.to_string(),
        );
        let quantity: u32 = 200;
        let mint_asset = Mint::<Asset, u32>::new(
            quantity,
            AssetId::new(wrong_asset_definition_id.clone(), account_id.clone()),
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
        if let QueryResult::FindAssetsByAccountId(result) = query_result {
            assert!(result
                .assets
                .iter()
                .filter(|asset| asset.id.definition_id == wrong_asset_definition_id)
                .collect::<Vec<&Asset>>()
                .is_empty());
        } else {
            panic!("Wrong Query Result Type.");
        }
        let definition_query_result = iroha_client
            .request(&client::asset::all_definitions())
            .expect("Failed to execute request.");
        if let QueryResult::FindAllAssetsDefinitions(result) = definition_query_result {
            assert!(result
                .assets_definitions_entries
                .iter()
                .filter(
                    |asset_definition| asset_definition.definition.id == wrong_asset_definition_id
                )
                .collect::<Vec<&AssetDefinitionEntry>>()
                .is_empty());
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
