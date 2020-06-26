#[cfg(test)]
mod tests {
    use async_std::task;
    use iroha::{config::Configuration, isi, prelude::*};
    use iroha_client::{
        client::{self, Client},
        config::Configuration as ClientConfiguration,
    };
    use std::thread;
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";

    #[async_std::test]
    //TODO: use cucumber to write `gherkin` instead of code.
    async fn client_can_transfer_asset_to_another_account() {
        // Given
        thread::spawn(create_and_start_iroha);
        thread::sleep(std::time::Duration::from_millis(100));
        let configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let mut iroha_client = Client::new(&ClientConfiguration::from_iroha_configuration(
            &configuration,
        ));
        let domain_name = "domain";
        let create_domain = isi::Add {
            object: Domain::new(domain_name.to_string()),
            destination_id: PeerId::new(
                &configuration.torii_configuration.torii_url,
                &configuration.public_key,
            ),
        };
        let account1_name = "account1";
        let account2_name = "account2";
        let account1_id = AccountId::new(account1_name, domain_name);
        let account2_id = AccountId::new(account2_name, domain_name);
        let (public_key, _) = configuration.key_pair();
        let create_account1 = isi::Register {
            object: Account::with_signatory(account1_name, domain_name, public_key),
            destination_id: String::from(domain_name),
        };
        let create_account2 = isi::Register {
            object: Account::with_signatory(account2_name, domain_name, public_key),
            destination_id: String::from(domain_name),
        };
        let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
        let quantity: u32 = 200;
        let create_asset = isi::Register {
            object: AssetDefinition::new(asset_definition_id.clone()),
            destination_id: domain_name.to_string(),
        };
        let mint_asset = isi::Mint {
            object: quantity,
            destination_id: AssetId {
                definition_id: asset_definition_id.clone(),
                account_id: account1_id.clone(),
            },
        };
        iroha_client
            .submit_all(vec![
                create_domain.into(),
                create_account1.into(),
                create_account2.into(),
                create_asset.into(),
                mint_asset.into(),
            ])
            .await
            .expect("Failed to prepare state.");
        std::thread::sleep(std::time::Duration::from_millis(
            &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
        ));
        //When
        let quantity = 20;
        let transfer_asset = isi::Transfer {
            source_id: account1_id.clone(),
            destination_id: account2_id.clone(),
            object: Asset::with_quantity(
                AssetId {
                    definition_id: asset_definition_id.clone(),
                    account_id: account1_id.clone(),
                },
                quantity,
            ),
        };
        iroha_client
            .submit(transfer_asset.into())
            .await
            .expect("Failed to submit instruction.");
        std::thread::sleep(std::time::Duration::from_millis(
            &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
        ));
        //Then
        let request = client::assets::by_account_id(account2_id.clone());
        let query_result = iroha_client
            .request(&request)
            .await
            .expect("Failed to execute request.");
        if let QueryResult::GetAccountAssets(result) = query_result {
            let asset = result.assets.first().expect("Asset should exist.");
            assert_eq!(quantity, asset.quantity,);
            assert_eq!(account2_id, asset.id.account_id,);
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
        let iroha = Iroha::new(configuration);
        task::block_on(iroha.start()).expect("Failed to start Iroha.");
        //Prevents temp_dir from clean up untill the end of the tests.
        #[allow(clippy::empty_loop)]
        loop {}
    }
}
