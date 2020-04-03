#[cfg(test)]
mod tests {
    use futures::executor;
    use iroha::{
        account::isi::{CreateAccount, CreateRole},
        asset::isi::{AddAssetQuantity, TransferAsset},
        domain::isi::CreateDomain,
        prelude::*,
    };
    use iroha_client::client::{self, Client};
    use std::thread;

    static DEFAULT_BLOCK_STORE_LOCATION: &str = "./blocks/";

    #[async_std::test]
    //TODO: use cucumber to write `gherkin` instead of code.
    async fn client_can_transfer_asset_to_another_account() {
        // Given
        thread::spawn(|| executor::block_on(create_and_start_iroha()));
        thread::sleep(std::time::Duration::from_millis(200));
        let create_role = CreateRole {
            role_name: "user".to_string(),
            permissions: Vec::new(),
        };
        let create_domain = CreateDomain {
            domain_name: "domain".to_string(),
            default_role: "user".to_string(),
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
        let create_asset = AddAssetQuantity {
            asset_id: asset_id.clone(),
            account_id: account1_id.clone(),
            amount: 100,
        };
        let transfer_asset = TransferAsset {
            source_account_id: account1_id.clone(),
            destination_account_id: account2_id.clone(),
            asset_id: asset_id.clone(),
            description: "description".to_string(),
            amount: 20,
        };
        let mut iroha_client = Client::new(
            Configuration::from_path("config.json").expect("Failed to load configuration."),
        );
        iroha_client
            .submit(create_role.into())
            .expect("Failed to create role.");
        thread::sleep(std::time::Duration::from_millis(200));
        iroha_client
            .submit(create_domain.into())
            .expect("Failed to create domain.");
        thread::sleep(std::time::Duration::from_millis(200));
        iroha_client
            .submit(create_account1.into())
            .expect("Failed to create account1.");
        thread::sleep(std::time::Duration::from_millis(200));
        iroha_client
            .submit(create_account2.into())
            .expect("Failed to create accoun2.");
        thread::sleep(std::time::Duration::from_millis(200));
        iroha_client
            .submit(create_asset.into())
            .expect("Failed to create asset.");
        thread::sleep(std::time::Duration::from_millis(2000));
        //When
        iroha_client
            .submit(transfer_asset.into())
            .expect("Failed to submit command.");
        //Then
        let request = client::assets::by_account_id(account2_id);
        let query_result = iroha_client
            .request(&request)
            .expect("Failed to execute request.");
        dbg!(&query_result);
        if let QueryResult::GetAccountAssets(result) = query_result {
            assert!(!result.assets.is_empty());
        } else {
            panic!("QueryResult::GetAccountAssets was expected.");
        }
        let _result = cleanup_default_block_dir().await;
    }

    async fn create_and_start_iroha() {
        println!("Iroha create.");
        let mut iroha = Iroha::new(
            Configuration::from_path("config.json").expect("Failed to load configuration."),
        );
        println!("Iroha start.");
        iroha.start().await.expect("Failed to start Iroha.");
        println!("Iroha started.");
    }

    /// Cleans up default directory of disk storage.
    /// Should be used in tests that may potentially read from disk
    /// to prevent failures due to changes in block structure.
    pub async fn cleanup_default_block_dir() -> Result<(), String> {
        use async_std::fs;

        fs::remove_dir_all(DEFAULT_BLOCK_STORE_LOCATION)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}
