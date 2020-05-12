#[cfg(test)]
mod tests {
    use async_std::task;
    use iroha::{isi, prelude::*};
    use iroha_client::client::{self, Client};
    use std::{thread, time::Duration};
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";

    #[async_std::test]
    //TODO: use cucumber to write `gherkin` instead of code.
    async fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount() {
        // Given
        thread::spawn(|| create_and_start_iroha());
        thread::sleep(std::time::Duration::from_millis(300));
        let domain_name = "domain";
        let create_domain = isi::Add {
            object: Domain::new(domain_name.to_string()),
            destination_id: iroha::peer::PeerId::current(),
        };
        let account_name = "account";
        let account_id = AccountId::new(account_name, domain_name);
        let configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let (public_key, _) = configuration.key_pair();
        let create_account = isi::Register {
            object: Account::new(account_name, domain_name, public_key),
            destination_id: String::from(domain_name),
        };
        let asset_id = AssetId::new("xor", domain_name, account_name);
        let create_asset = isi::Register {
            object: Asset::new(asset_id.clone()).with_quantity(0),
            destination_id: domain_name.to_string(),
        };
        let mut iroha_client = Client::new(&configuration);
        iroha_client
            .submit_all(vec![
                create_domain.into(),
                create_account.into(),
                create_asset.into(),
            ])
            .await
            .expect("Failed to prepare state.");
        task::sleep(Duration::from_millis(
            &configuration.block_build_step_ms * 20,
        ))
        .await;
        //When
        let quantity: u128 = 200;
        let mint_asset = isi::Mint {
            object: quantity,
            destination_id: asset_id.clone(),
        };
        iroha_client
            .submit(mint_asset.into())
            .await
            .expect("Failed to create asset.");
        task::sleep(Duration::from_millis(
            &configuration.block_build_step_ms * 20,
        ))
        .await;
        //Then
        let request = client::assets::by_account_id(account_id);
        let query_result = iroha_client
            .request(&request)
            .await
            .expect("Failed to execute request.");
        let QueryResult::GetAccountAssets(result) = query_result;
        assert!(!result.assets.is_empty());
        assert_eq!(
            quantity,
            result.assets.first().expect("Asset should exist.").quantity,
        );
    }

    fn create_and_start_iroha() {
        let temp_dir = TempDir::new().expect("Failed to create TempDir.");
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration.kura_block_store_path(temp_dir.path());
        let iroha = Iroha::new(configuration);
        task::block_on(iroha.start()).expect("Failed to start Iroha.");
        //Prevents temp_dir from clean up untill the end of the tests.
        loop {}
    }
}
