#[cfg(test)]
mod tests {
    use async_std::task;
    use iroha::{isi, peer::PeerId, prelude::*};
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
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let peers = create_and_start_iroha_peers(N_PEERS);
        thread::sleep(std::time::Duration::from_millis(1000));
        let domain_name = "domain";
        let create_domain = isi::Add {
            object: Domain::new(domain_name.to_string()),
            destination_id: configuration.peer_id.clone(),
        };
        configuration.peer_id(peers.first().expect("Failed to get first peer.").clone());
        let account_name = "account";
        let account_id = AccountId::new(account_name, domain_name);
        let (public_key, _) = configuration.key_pair();
        let create_account = isi::Register {
            object: Account::new(account_name, domain_name, public_key),
            destination_id: String::from(domain_name),
        };
        let asset_id = AssetDefinitionId::new("xor", domain_name);
        let create_asset = isi::Register {
            object: AssetDefinition::new(asset_id.clone()),
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
        std::thread::sleep(std::time::Duration::from_millis(
            &configuration.block_build_step_ms * 2,
        ));
        //When
        let quantity: u32 = 200;
        let mint_asset = isi::Mint {
            object: quantity,
            destination_id: AssetId {
                definition_id: asset_id.clone(),
                account_id: account_id.clone(),
            },
        };
        iroha_client
            .submit(mint_asset.into())
            .await
            .expect("Failed to create asset.");
        std::thread::sleep(std::time::Duration::from_millis(
            &configuration.block_build_step_ms * 2,
        ));
        //Then
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration.peer_id(peers.last().expect("Failed to get last peer.").clone());
        let mut iroha_client = Client::new(&configuration);
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
                configuration.peer_id(peer_id.clone());
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
