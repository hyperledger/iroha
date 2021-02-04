#[cfg(test)]
mod tests {
    use async_std::task;
    use iroha::{config::Configuration, prelude::*};
    use iroha_client::{
        client::{self, Client},
        config::Configuration as ClientConfiguration,
    };
    use iroha_data_model::prelude::*;
    use std::thread;
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const TRUSTED_PEERS_PATH: &str = "tests/test_trusted_peers.json";
    const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";

    #[test]
    //TODO: use cucumber_rust to write `gherkin` instead of code.
    fn client_can_transfer_asset_to_another_account() {
        // Given
        thread::spawn(create_and_start_iroha);
        thread::sleep(std::time::Duration::from_millis(100));
        let configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        let mut iroha_client = Client::new(&configuration);
        let domain_name = "domain";
        let create_domain = RegisterBox::new(
            IdentifiableBox::Domain(Domain::new(domain_name).into()),
            IdBox::WorldId,
        );
        let account1_name = "account1";
        let account2_name = "account2";
        let account1_id = AccountId::new(account1_name, domain_name);
        let account2_id = AccountId::new(account2_name, domain_name);
        let create_account1 = RegisterBox::new(
            IdentifiableBox::Account(
                Account::with_signatory(
                    account1_id.clone(),
                    KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key,
                )
                .into(),
            ),
            IdBox::DomainName(domain_name.to_string()),
        );
        let create_account2 = RegisterBox::new(
            IdentifiableBox::Account(
                Account::with_signatory(
                    account2_id.clone(),
                    KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key,
                )
                .into(),
            ),
            IdBox::DomainName(domain_name.to_string()),
        );
        let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
        let quantity: u32 = 200;
        let create_asset = RegisterBox::new(
            IdentifiableBox::AssetDefinition(
                AssetDefinition::new(asset_definition_id.clone()).into(),
            ),
            IdBox::DomainName(domain_name.to_string()),
        );
        let mint_asset = MintBox::new(
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(
                asset_definition_id.clone(),
                account1_id.clone(),
            )),
        );
        iroha_client
            .submit_all(vec![
                create_domain.into(),
                create_account1.into(),
                create_account2.into(),
                create_asset.into(),
                mint_asset.into(),
            ])
            .expect("Failed to prepare state.");
        thread::sleep(std::time::Duration::from_millis(200 * 2));
        //When
        let quantity = 20;
        let transfer_asset = TransferBox::new(
            IdBox::AssetId(AssetId::new(asset_definition_id.clone(), account1_id)),
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(asset_definition_id, account2_id.clone())),
        );
        iroha_client
            .submit(transfer_asset.into())
            .expect("Failed to submit instruction.");
        thread::sleep(std::time::Duration::from_millis(200 * 2));
        //Then
        let request = client::asset::by_account_id(account2_id.clone());
        let query_result = iroha_client
            .request(&request)
            .expect("Failed to execute request.");
        if let QueryResult(Value::Vec(assets)) = query_result {
            assert!(!assets.is_empty());
            assert_eq!(
                assets
                    .iter()
                    .filter(|asset| {
                        if let Value::Identifiable(IdentifiableBox::Asset(asset)) = asset {
                            asset.quantity == quantity && asset.id.account_id == account2_id
                        } else {
                            false
                        }
                    })
                    .count(),
                1
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
