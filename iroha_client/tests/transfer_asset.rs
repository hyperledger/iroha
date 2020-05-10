#[cfg(test)]
mod tests {
    use async_std::task;
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
        let configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let mut iroha_client = Client::new(&configuration);
        iroha_client
            .submit_all(vec![
                create_domain.into(),
                create_account1.into(),
                create_account2.into(),
                create_asset1.into(),
                create_asset2.into(),
            ])
            .await
            .expect("Failed to create domain.");
        std::thread::sleep(std::time::Duration::from_millis(
            &configuration.block_build_step_ms * 2,
        ));
        //When
        iroha_client
            .submit(transfer_asset.into())
            .await
            .expect("Failed to submit command.");
        std::thread::sleep(std::time::Duration::from_millis(
            &configuration.block_build_step_ms * 2,
        ));
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
        task::block_on(iroha.start()).expect("Failed to start Iroha.");
        //Prevents temp_dir from clean up untill the end of the tests.
        loop {}
    }
}
