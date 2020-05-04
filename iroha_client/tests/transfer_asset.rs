#[cfg(test)]
mod tests {
    use iroha::{
        account::isi::CreateAccount,
        asset::isi::{AddAssetQuantity, TransferAsset},
        domain::isi::CreateDomain,
        prelude::*,
    };
    use iroha_client::client::{self, Client};
    use std::thread;
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";

    #[async_std::test]
    //TODO: use cucumber to write `gherkin` instead of code.
    async fn client_can_transfer_asset_to_another_account() {
        // Given
        thread::spawn(|| create_and_start_iroha());
        thread::sleep(std::time::Duration::from_millis(100));
        let create_domain = CreateDomain {
            domain_name: "domain".to_string(),
        };
        let account1_id = Id::new("account1", "domain");
        let account2_id = Id::new("account2", "domain");
        let create_account1 = CreateAccount {
            account_id: account1_id.clone(),
            domain_name: "domain".to_string(),
            public_key: [63; 32],
        };
        let create_account2 = CreateAccount {
            account_id: account2_id.clone(),
            domain_name: "domain".to_string(),
            public_key: [63; 32],
        };
        let asset_id = Id::new("xor", "domain");
        let create_asset1 = AddAssetQuantity {
            asset_id: asset_id.clone(),
            account_id: account1_id.clone(),
            amount: 100,
        };
        let create_asset2 = AddAssetQuantity {
            asset_id: asset_id.clone(),
            account_id: account2_id.clone(),
            amount: 0,
        };
        let transfer_amount = 20;
        let transfer_asset = TransferAsset {
            source_account_id: account1_id.clone(),
            destination_account_id: account2_id.clone(),
            asset_id: asset_id.clone(),
            description: "description".to_string(),
            amount: transfer_amount,
        };
        let mut iroha_client = Client::new(
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration."),
        );
        iroha_client
            .submit(create_domain.into())
            .await
            .expect("Failed to create domain.");
        std::thread::sleep(std::time::Duration::from_millis(100));
        iroha_client
            .submit(create_account1.into())
            .await
            .expect("Failed to create account1.");
        std::thread::sleep(std::time::Duration::from_millis(100));
        iroha_client
            .submit(create_account2.into())
            .await
            .expect("Failed to create accoun2.");
        std::thread::sleep(std::time::Duration::from_millis(100));
        iroha_client
            .submit(create_asset1.into())
            .await
            .expect("Failed to create asset.");
        iroha_client
            .submit(create_asset2.into())
            .await
            .expect("Failed to create asset.");
        std::thread::sleep(std::time::Duration::from_millis(100));
        //When
        iroha_client
            .submit(transfer_asset.into())
            .await
            .expect("Failed to submit command.");
        std::thread::sleep(std::time::Duration::from_millis(500));
        //Then
        let request = client::assets::by_account_id(account2_id);
        let query_result = iroha_client
            .request(&request)
            .await
            .expect("Failed to execute request.");
        let QueryResult::GetAccountAssets(result) = query_result;
        assert!(!result.assets.is_empty());
        assert_eq!(
            transfer_amount,
            result.assets.first().expect("Asset should exist.").amount,
        );
    }

    fn create_and_start_iroha() {
        let temp_dir = TempDir::new().expect("Failed to create TempDir.");
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration.kura_block_store_path(temp_dir.path());
        let iroha = Iroha::new(configuration);
        iroha.start().expect("Failed to start Iroha.");
        //Prevents temp_dir from clean up untill the end of the tests.
        loop {}
    }
}
