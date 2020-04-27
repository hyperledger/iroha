#[cfg(test)]
mod tests {
    use iroha::{
        account::isi::{CreateAccount, CreateRole},
        asset::isi::AddAssetQuantity,
        domain::isi::CreateDomain,
        peer::PeerId,
        prelude::*,
    };
    use iroha_client::client::{self, Client};
    use std::thread;
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "config.json";
    const PEER_URL: &str = "127.0.0.1:8080";
    const ANOTHER_PEER_URL: &str = "127.0.0.1:8081";

    #[async_std::test]
    //TODO: use cucumber to write `gherkin` instead of code.
    async fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount_on_another_peer(
    ) {
        // Given
        thread::spawn(|| {
            let temp_dir = TempDir::new().expect("Failed to create TempDir.");
            let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
                .expect("Failed to load configuration.");
            configuration.torii_url(PEER_URL);
            configuration.kura_block_store_path(temp_dir.path());
            configuration.trusted_peers(vec![PeerId {
                address: ANOTHER_PEER_URL.to_string(),
                public_key: [0; 32],
            }]);
            let iroha = Iroha::new(configuration);
            iroha.start().expect("Failed to start Iroha.");
            //Prevents temp_dir from clean up untill the end of the tests.
            loop {}
        });
        thread::spawn(|| {
            let temp_dir = TempDir::new().expect("Failed to create TempDir.");
            let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
                .expect("Failed to load configuration.");
            configuration.kura_block_store_path(temp_dir.path());
            configuration.torii_url(ANOTHER_PEER_URL);
            configuration.trusted_peers(vec![PeerId {
                address: PEER_URL.to_string(),
                public_key: [0; 32],
            }]);
            let iroha = Iroha::new(configuration);
            iroha.start().expect("Failed to start Iroha Peer.");
            //Prevents temp_dir from clean up untill the end of the tests.
            loop {}
        });
        thread::sleep(std::time::Duration::from_millis(100));
        let create_role = CreateRole {
            role_name: "user".to_string(),
            permissions: Vec::new(),
        };
        let create_domain = CreateDomain {
            domain_name: "domain".to_string(),
            default_role: "user".to_string(),
        };
        let account_id = Id::new("account", "domain");
        let create_account = CreateAccount {
            account_id: account_id.clone(),
            domain_name: "domain".to_string(),
            public_key: [63; 32],
        };
        let asset_id = Id::new("xor", "domain");
        let create_asset = AddAssetQuantity {
            asset_id: asset_id.clone(),
            account_id: account_id.clone(),
            amount: 0,
        };
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration.torii_url(PEER_URL);
        let mut iroha_client = Client::new(configuration);
        iroha_client
            .submit(create_role.into())
            .await
            .expect("Failed to create role.");
        std::thread::sleep(std::time::Duration::from_millis(50));
        iroha_client
            .submit(create_domain.into())
            .await
            .expect("Failed to create domain.");
        std::thread::sleep(std::time::Duration::from_millis(50));
        iroha_client
            .submit(create_account.into())
            .await
            .expect("Failed to create account.");
        std::thread::sleep(std::time::Duration::from_millis(50));
        iroha_client
            .submit(create_asset.into())
            .await
            .expect("Failed to create asset.");
        std::thread::sleep(std::time::Duration::from_millis(50));
        //When
        let add_amount = 200;
        let add_asset_quantity = AddAssetQuantity {
            asset_id: asset_id.clone(),
            account_id: account_id.clone(),
            amount: add_amount,
        };
        iroha_client
            .submit(add_asset_quantity.into())
            .await
            .expect("Failed to create asset.");
        std::thread::sleep(std::time::Duration::from_millis(100));
        //Then
        let mut configuration =
            Configuration::from_path("config.json").expect("Failed to load configuration.");
        configuration.torii_url(ANOTHER_PEER_URL);
        let request = client::assets::by_account_id(account_id);
        let query_result = iroha_client
            .request(&request)
            .await
            .expect("Failed to execute request.");
        let QueryResult::GetAccountAssets(result) = query_result;
        assert!(!result.assets.is_empty());
        assert_eq!(
            add_amount,
            result.assets.first().expect("Asset should exist.").amount,
        );
    }
}
