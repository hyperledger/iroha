#[cfg(test)]
mod tests {
    use std::thread;

    use async_std::task;
    use iroha::{config::Configuration, prelude::*};
    use iroha_client::{
        client::{self, Client},
        config::Configuration as ClientConfiguration,
    };
    use iroha_data_model::prelude::*;
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
    const N_PEERS: usize = 4;
    const MAX_FAULTS: u32 = 1;
    const N_BLOCKS: usize = 510;
    const MAXIMUM_TRANSACTIONS_IN_BLOCK: u32 = 1;

    #[ignore = "Takes a lot of time."]
    #[test]
    fn long_multiple_blocks_created() {
        // Given
        let configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let peers = create_and_start_test_network(N_PEERS);
        thread::sleep(std::time::Duration::from_millis(1000));
        let domain_name = "domain";
        let create_domain =
            RegisterBox::new(IdentifiableBox::Domain(Domain::new(domain_name).into()));
        let account_name = "account";
        let account_id = AccountId::new(account_name, domain_name);
        let create_account = RegisterBox::new(IdentifiableBox::NewAccount(
            NewAccount::with_signatory(
                account_id.clone(),
                KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            )
            .into(),
        ));
        let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
        let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
            AssetDefinition::new_quantity(asset_definition_id.clone()).into(),
        ));
        let mut client_configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        client_configuration.torii_api_url =
            peers.first().expect("Failed to get first peer.").clone();
        let mut iroha_client = Client::new(&client_configuration);
        let _ = iroha_client
            .submit_all(vec![
                create_domain.into(),
                create_account.into(),
                create_asset.into(),
            ])
            .expect("Failed to prepare state.");
        thread::sleep(std::time::Duration::from_millis(
            configuration.sumeragi_configuration.pipeline_time_ms() * 2,
        ));
        let mut account_has_quantity = 0;
        //When
        for _ in 0..N_BLOCKS {
            let quantity: u32 = 1;
            let mint_asset = MintBox::new(
                Value::U32(quantity),
                IdBox::AssetId(AssetId::new(
                    asset_definition_id.clone(),
                    account_id.clone(),
                )),
            );
            let _ = iroha_client
                .submit(mint_asset.into())
                .expect("Failed to create asset.");
            account_has_quantity += quantity;
            thread::sleep(std::time::Duration::from_millis(1000));
        }
        thread::sleep(std::time::Duration::from_millis(
            configuration.sumeragi_configuration.pipeline_time_ms() * 2,
        ));
        //Then
        client_configuration.torii_api_url =
            peers.last().expect("Failed to get last peer.").clone();
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
                assert_eq!(AssetValue::Quantity(account_has_quantity), asset.value);
            } else {
                panic!("Wrong Query Result Type.")
            }
        } else {
            panic!("Wrong Query Result Type.");
        }
    }

    fn create_and_start_test_network(n_peers: usize) -> Vec<String> {
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
        for i in 0..n_peers {
            let peer_ids = peer_ids.clone();
            let peer_id = peer_ids[i].clone();
            let key_pair = peer_keys[i].clone();
            let (p2p_address, api_address) = addresses[i].clone();
            drop(task::spawn(async move {
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
                let iroha = Iroha::new(&configuration, AllowAll.into());
                iroha.start().await.expect("Failed to start Iroha.");
                //Prevents temp_dir from clean up untill the end of the tests.
                #[allow(clippy::empty_loop)]
                loop {}
            }));
            thread::sleep(std::time::Duration::from_millis(100));
        }
        addresses
            .iter()
            .map(|(_, api_url)| api_url)
            .cloned()
            .collect()
    }
}
