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
    const N_PEERS: usize = 7;
    const MAX_FAULTS: u32 = 2;
    const N_TRANSACTONS: usize = 20;
    const OFFLINE_PEERS: usize = 1;
    const MAXIMUM_TRANSACTIONS_IN_BLOCK: u32 = 1;
    const GENESIS_PATH: &str = "tests/genesis.json";

    #[test]
    fn unstable_network() {
        // Given
        let configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let peers = create_and_start_iroha_peers(N_PEERS);
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
        // Initially there are 15 roses.
        let mut account_has_quantity = 13;
        //When
        for _ in 0..N_TRANSACTONS {
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
            configuration.sumeragi_configuration.pipeline_time_ms() * 5,
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

    fn create_and_start_iroha_peers(n_peers: usize) -> Vec<String> {
        let peer_keys: Vec<KeyPair> = (0..n_peers)
            .map(|_| KeyPair::generate().expect("Failed to generate key pair."))
            .collect();
        let addresses: Vec<(String, String)> = (0..n_peers)
            .map(|i| {
                (
                    format!("127.0.0.1:{}", 7878 + i * 2),
                    format!("127.0.0.1:{}", 7878 + i * 2 + 1),
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
            .choose_multiple(rng, OFFLINE_PEERS)
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
                    .max_faulty_peers(MAX_FAULTS);
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
