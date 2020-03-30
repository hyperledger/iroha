#[cfg(test)]
mod e2e_tests {
    use futures::executor;
    use iroha::{
        account::isi::{CreateAccount, CreateRole},
        asset::isi::{AddAssetQuantity, TransferAsset},
        domain::isi::CreateDomain,
        prelude::*,
    };
    use iroha_client::client::Client;
    use std::thread;

    static DEFAULT_BLOCK_STORE_LOCATION: &str = "./blocks/";

    #[async_std::test]
    //TODO: use cucumber to write `gherkin` instead of code.
    async fn client_can_transfer_asset_to_another_account() {
        // Given
        let create_role = &CreateRole {
            role_name: "user".to_string(),
            permissions: Vec::new(),
        };
        let create_domain = &CreateDomain {
            domain_name: "domain".to_string(),
            default_role: "user".to_string(),
        };
        let account1_id = Id::new("account1", "domain");
        let account2_id = Id::new("account2", "domain");
        let create_account1 = &CreateAccount {
            account_id: account1_id.clone(),
            domain_name: "domain".to_string(),
            public_key: [63; 32],
        };
        let create_account2 = &CreateAccount {
            account_id: account2_id.clone(),
            domain_name: "domain".to_string(),
            public_key: [63; 32],
        };
        let asset_id = Id::new("xor", "domain");
        let create_asset = &AddAssetQuantity {
            asset_id: asset_id.clone(),
            account_id: account1_id.clone(),
            amount: 100,
        };
        let transfer_asset = &TransferAsset {
            source_account_id: account1_id.clone(),
            destination_account_id: account2_id.clone(),
            asset_id: asset_id.clone(),
            description: "description".to_string(),
            amount: 20,
        };
        let iroha_client = Client::new();
        iroha_client
            .submit(create_role.into())
            .expect("Failed to create role.");
        iroha_client
            .submit(create_domain.into())
            .expect("Failed to create domain.");
        iroha_client
            .submit(create_account1.into())
            .expect("Failed to create account1.");
        iroha_client
            .submit(create_account2.into())
            .expect("Failed to create accoun2.");
        iroha_client
            .submit(create_asset.into())
            .expect("Failed to create asset.");
        thread::spawn(|| executor::block_on(create_and_start_iroha()));
        //When
        iroha_client
            .submit(transfer_asset.into())
            .expect("Failed to submit command.");
        //Then
        //let _query = client::assets::by_id(asset_id);
        //assert_eq!(account2_id, asset.account_id);
        let _result = cleanup_default_block_dir().await;
    }

    async fn create_and_start_iroha() {
        let mut iroha = Iroha::new(
            Configuration::from_path("config.json").expect("Failed to load configuration."),
        )
        .await
        .expect("Failed to create Iroha.");
        iroha.start().await;
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
