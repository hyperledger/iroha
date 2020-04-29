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

    const CONFIGURATION_PATH: &str = "config.json";

    #[async_std::test]
    //TODO: unignore where CI will be powerfull enough.
    #[ignore]
    //TODO: use cucumber to write `gherkin` instead of code.
    async fn client_can_transfer_asset_to_another_account_x100() {
        // Given
        thread::spawn(|| create_and_start_iroha());
        thread::sleep(std::time::Duration::from_millis(200));
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
            amount: 1,
        };
        let mut iroha_client = Client::new(
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration."),
        );
        iroha_client
            .submit(create_domain.into())
            .await
            .expect("Failed to create domain.");
        std::thread::sleep(std::time::Duration::from_millis(1000));
        iroha_client
            .submit(create_account1.into())
            .await
            .expect("Failed to create account1.");
        std::thread::sleep(std::time::Duration::from_millis(1000));
        iroha_client
            .submit(create_account2.into())
            .await
            .expect("Failed to create accoun2.");
        std::thread::sleep(std::time::Duration::from_millis(1000));
        iroha_client
            .submit(create_asset.into())
            .await
            .expect("Failed to create asset.");
        std::thread::sleep(std::time::Duration::from_millis(1000));
        //When
        for _ in 0..400 {
            iroha_client
                .submit(transfer_asset.clone().into())
                .await
                .expect("Failed to submit command.");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        std::thread::sleep(std::time::Duration::from_millis(2000));
        //Then
        let request = client::assets::by_account_id(account2_id);
        iroha_client
            .request(&request)
            .await
            .expect("Failed to execute request.");
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
