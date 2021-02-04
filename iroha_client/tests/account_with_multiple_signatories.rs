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
    const TRUSTED_PEERS_PATH: &str = "tests/test_trusted_peers.json";
    const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";

    #[test]
    fn transaction_signed_by_new_signatory_of_account_should_pass() -> Result<(), String> {
        // Given
        thread::spawn(create_and_start_iroha);
        thread::sleep(std::time::Duration::from_millis(300));
        let configuration = Configuration::from_path(CONFIGURATION_PATH)?;
        let domain_name = "global";
        let account_name = "root";
        let account_id = AccountId::new(account_name, domain_name);
        let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
        let create_asset = RegisterBox::new(
            IdentifiableBox::AssetDefinition(
                AssetDefinition::new(asset_definition_id.clone()).into(),
            ),
            IdBox::DomainName(domain_name.to_string()),
        );
        let key_pair = KeyPair::generate()?;
        let add_signatory = MintBox::new(
            key_pair.public_key.clone(),
            IdBox::AccountId(account_id.clone()),
        );
        let mut iroha_client =
            Client::new(&ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)?);
        iroha_client.submit_all(vec![create_asset.into(), add_signatory.into()])?;
        thread::sleep(Duration::from_millis(
            &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
        ));
        //When
        let quantity: u32 = 200;
        let mint_asset = MintBox::new(
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(asset_definition_id, account_id.clone())),
        );
        let mut client_configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)?;
        client_configuration.public_key = key_pair.public_key;
        client_configuration.private_key = key_pair.private_key;
        let mut iroha_client = Client::new(&client_configuration);
        iroha_client.submit(mint_asset.into())?;
        thread::sleep(Duration::from_millis(
            &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
        ));
        //Then
        let request = client::asset::by_account_id(account_id);
        let query_result = iroha_client.request(&request)?;
        if let QueryResult(Value::Vec(assets)) = query_result {
            assert!(!assets.is_empty());
            if let Value::Identifiable(IdentifiableBox::Asset(asset)) =
                assets.first().expect("Asset should exist.")
            {
                assert_eq!(quantity, asset.quantity);
            } else {
                panic!("Wrong Query Result Type.")
            }
        } else {
            panic!("Wrong Query Result Type.");
        }
        Ok(())
    }

    fn create_and_start_iroha() {
        let temp_dir = TempDir::new().expect("Failed to create TempDir.");
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration
            .load_trusted_peers_from_path(TRUSTED_PEERS_PATH)
            .expect("Failed to load trusted peers.");
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
