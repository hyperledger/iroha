#[cfg(test)]
mod tests {
    use async_std::task;
    use iroha::{
        account::isi::CreateAccount, asset::isi::AddAssetQuantity, domain::isi::CreateDomain,
        peer::PeerId, prelude::*,
    };
    use iroha_client::client::{self, Client};
    use std::thread;
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const N_PEERS: usize = 4;
    const MAX_FAULTS: usize = 1;

    #[ignore]
    #[async_std::test]
    //TODO: use cucumber to write `gherkin` instead of code.
    async fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount_on_another_peer(
    ) {
        // Given
        let peers = create_and_start_iroha_peers(N_PEERS);
        thread::sleep(std::time::Duration::from_millis(1000));
        let create_domain = CreateDomain {
            domain_name: "domain".to_string(),
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
        configuration.torii_url(
            peers
                .first()
                .expect("Failed to get first peer.")
                .address
                .as_str(),
        );
        let mut iroha_client = Client::new(&configuration);
        iroha_client
            .submit_all(vec![
                create_domain.into(),
                create_account.into(),
                create_asset.into(),
            ])
            .await
            .expect("Failed to prepare state.");
        std::thread::sleep(std::time::Duration::from_millis(
            &configuration.block_build_step_ms * 2,
        ));
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
        std::thread::sleep(std::time::Duration::from_millis(
            &configuration.block_build_step_ms * 2,
        ));
        //Then
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration.torii_url(
            peers
                .last()
                .expect("Failed to get last peer.")
                .address
                .as_str(),
        );
        let mut iroha_client = Client::new(&configuration);
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

    fn create_and_start_iroha_peers(n_peers: usize) -> Vec<PeerId> {
        let peer_ids: Vec<PeerId> = (0..n_peers)
            .map(|i| PeerId {
                address: format!("127.0.0.1:{}", 1338 + i),
                public_key: [
                    101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117,
                    15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53,
                ],
            })
            .collect();
        for peer_id in peer_ids.clone() {
            let peer_ids = peer_ids.clone();
            thread::spawn(move || {
                let temp_dir = TempDir::new().expect("Failed to create TempDir.");
                let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
                    .expect("Failed to load configuration.");
                configuration.kura_block_store_path(temp_dir.path());
                configuration.torii_url(&peer_id.address);
                configuration.trusted_peers(peer_ids.clone());
                configuration.max_faulty_peers(MAX_FAULTS);
                let iroha = Iroha::new(configuration);
                task::block_on(iroha.start()).expect("Failed to start Iroha.");
                //Prevents temp_dir from clean up untill the end of the tests.
                loop {}
            });
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        peer_ids.clone()
    }
}
