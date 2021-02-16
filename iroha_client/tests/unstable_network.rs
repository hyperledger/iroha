#[cfg(test)]
mod tests {
    use async_std::task;
    use iroha::{config::Configuration, prelude::*};
    use iroha_client::{
        client::{self, Client},
        config::Configuration as ClientConfiguration,
    };
    use iroha_data_model::prelude::*;
    use rand::seq::SliceRandom;
    use std::{collections::BTreeSet, thread};
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
    const MAXIMUM_TRANSACTIONS_IN_BLOCK: u32 = 2;
    const GENESIS_PATH: &str = "tests/genesis.json";

    #[test]
    fn unstable_network_4_peers_1_fault() {
        unstable_network(4, 1, 1, 20, 5);
    }

    #[test]
    fn unstable_network_7_peers_1_fault() {
        unstable_network(7, 2, 1, 20, 5);
    }

    #[test]
    #[ignore = "This test does not guarantee to have positive outcome given a fixed time."]
    fn unstable_network_7_peers_2_faults() {
        unstable_network(7, 2, 2, 5, 40);
    }

    fn unstable_network(
        n_peers: usize,
        max_faults: u32,
        n_offline_peers: usize,
        n_transactions: usize,
        wait_multiplier: u64,
    ) {
        // Given
        let configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let peers = create_and_start_iroha_peers(n_peers, max_faults, n_offline_peers);
        thread::sleep(std::time::Duration::from_millis(
            configuration.sumeragi_configuration.pipeline_time_ms() * 3,
        ));
        let domain_name = "wonderland";
        let account_name = "alice";
        let account_id = AccountId::new(account_name, domain_name);
        let asset_definition_id = AssetDefinitionId::new("rose", domain_name);
        let mut client_configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        client_configuration.torii_api_url =
            peers.first().expect("Failed to get first peer.").clone();
        let mut iroha_client = Client::new(&client_configuration);
        // Initially there are 13 roses.
        let mut account_has_quantity = 13;
        //When
        for _ in 0..n_transactions {
            let quantity: u32 = 1;
            let mint_asset = MintBox::new(
                Value::U32(quantity),
                IdBox::AssetId(AssetId::new(
                    asset_definition_id.clone(),
                    account_id.clone(),
                )),
            );
            iroha_client
                .submit(mint_asset.into())
                .expect("Failed to create asset.");
            account_has_quantity += quantity;
            thread::sleep(std::time::Duration::from_millis(
                configuration.sumeragi_configuration.pipeline_time_ms() * 2,
            ));
        }
        thread::sleep(std::time::Duration::from_millis(
            configuration.sumeragi_configuration.pipeline_time_ms() * wait_multiplier,
        ));
        //Then
        client_configuration.torii_api_url =
            peers.first().expect("Failed to get last peer.").clone();
        let mut iroha_client = Client::new(&client_configuration);
        let request = client::asset::by_account_id(account_id);
        let query_result = iroha_client
            .request(&request)
            .expect("Failed to execute request.");
        if let QueryResult(Value::Vec(assets)) = query_result {
            assert!(!assets.is_empty());
            if let Value::Identifiable(IdentifiableBox::Asset(asset)) =
                assets.first().expect("Asset should exist.")
            {
                assert_eq!(account_has_quantity, asset.quantity);
            } else {
                panic!("Wrong Query Result Type.")
            }
        } else {
            panic!("Wrong Query Result Type.");
        }
    }

    fn create_and_start_iroha_peers(
        n_peers: usize,
        max_faults: u32,
        n_offline_peers: usize,
    ) -> Vec<String> {
        let peer_keys: Vec<KeyPair> = (0..n_peers)
            .map(|_| KeyPair::generate().expect("Failed to generate key pair."))
            .collect();
        let addresses: Vec<(String, String)> = (0..n_peers)
            .map(|_| {
                (
                    format!(
                        "127.0.0.1:{}",
                        unique_port::get_unique_free_port().expect("Failed to get port")
                    ),
                    format!(
                        "127.0.0.1:{}",
                        unique_port::get_unique_free_port().expect("Failed to get port")
                    ),
                )
            })
            .collect();
        let peer_ids: Vec<PeerId> = peer_keys
            .iter()
            .enumerate()
            .map(|(i, key_pair)| {
                let (p2p_address, _) = &addresses[i];
                PeerId {
                    address: p2p_address.clone(),
                    public_key: key_pair.public_key.clone(),
                }
            })
            .collect();
        let rng = &mut rand::thread_rng();
        let offline_peers: BTreeSet<_> = peer_ids[1..]
            .choose_multiple(rng, n_offline_peers)
            .cloned()
            .collect();
        for i in 0..n_peers {
            let peer_id = peer_ids[i].clone();
            if offline_peers.contains(&peer_id) {
                continue;
            }
            let peer_ids = peer_ids.clone();
            let key_pair = peer_keys[i].clone();
            let (p2p_address, api_address) = addresses[i].clone();
            task::spawn(async move {
                let temp_dir = TempDir::new().expect("Failed to create TempDir.");
                let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
                    .expect("Failed to load configuration.");
                configuration
                    .queue_configuration
                    .maximum_transactions_in_block = MAXIMUM_TRANSACTIONS_IN_BLOCK;
                configuration.sumeragi_configuration.key_pair = key_pair.clone();
                configuration.sumeragi_configuration.peer_id = peer_id.clone();
                configuration
                    .kura_configuration
                    .kura_block_store_path(temp_dir.path());
                configuration.torii_configuration.torii_p2p_url = p2p_address.clone();
                configuration.torii_configuration.torii_api_url = api_address.clone();
                configuration.public_key = key_pair.public_key;
                configuration.private_key = key_pair.private_key.clone();
                configuration
                    .sumeragi_configuration
                    .trusted_peers(peer_ids.clone());
                configuration
                    .sumeragi_configuration
                    .max_faulty_peers(max_faults);
                if i == 0 {
                    configuration.genesis_configuration.genesis_block_path =
                        Some(GENESIS_PATH.to_string());
                }
                let iroha = Iroha::new(configuration, AllowAll.into());
                iroha.start().await.expect("Failed to start Iroha.");
            });
            thread::sleep(std::time::Duration::from_millis(100));
        }
        addresses
            .iter()
            .map(|(_, api_url)| api_url)
            .cloned()
            .collect()
    }
}
