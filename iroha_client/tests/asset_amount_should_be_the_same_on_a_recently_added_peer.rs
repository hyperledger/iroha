#[cfg(test)]
mod tests {
    use async_std::task;
    use iroha::{config::Configuration, prelude::*};
    use iroha_client::{
        client::{self, Client},
        config::Configuration as ClientConfiguration,
    };
    use iroha_data_model::prelude::*;
    use std::{thread, time::Duration};
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
    const N_PEERS: usize = 4;
    const MAX_FAULTS: u32 = 1;

    #[test]
    fn asset_amount_should_be_the_same_on_a_recently_added_peer() {
        // Given
        let configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let (peer_ids, addresses) = create_and_start_iroha_peers(N_PEERS);
        thread::sleep(std::time::Duration::from_millis(1000));
        let domain_name = "domain";
        let create_domain = RegisterBox::new(
            IdentifiableBox::Domain(Domain::new(domain_name).into()),
            IdBox::WorldId,
        );
        let account_name = "account";
        let account_id = AccountId::new(account_name, domain_name);
        let create_account = RegisterBox::new(
            IdentifiableBox::Account(
                Account::with_signatory(
                    account_id.clone(),
                    KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key,
                )
                .into(),
            ),
            IdBox::DomainName(domain_name.to_string()),
        );
        let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
        let create_asset = RegisterBox::new(
            IdentifiableBox::AssetDefinition(
                AssetDefinition::new(asset_definition_id.clone()).into(),
            ),
            IdBox::DomainName(domain_name.to_string()),
        );
        let mut client_configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        client_configuration.torii_api_url = addresses
            .first()
            .expect("Failed to get first peer.")
            .clone();
        let mut iroha_client = Client::new(&client_configuration);
        iroha_client
            .submit_all(vec![
                create_domain.into(),
                create_account.into(),
                create_asset.into(),
            ])
            .expect("Failed to prepare state.");
        thread::sleep(Duration::from_millis(
            configuration.sumeragi_configuration.pipeline_time_ms() * 2,
        ));
        //When
        let quantity: u32 = 200;
        let mint_asset = MintBox::new(
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(asset_definition_id, account_id.clone())),
        );
        iroha_client
            .submit(mint_asset.into())
            .expect("Failed to create asset.");
        thread::sleep(Duration::from_millis(
            configuration.sumeragi_configuration.pipeline_time_ms() * 2,
        ));
        let key_pair = KeyPair::generate().expect("Failed to generate key pair.");
        let p2p_address = format!("127.0.0.1:{}", 1337 + N_PEERS * 3);
        let api_address = format!("127.0.0.1:{}", 1337 + N_PEERS * 3 + 1);
        let new_peer = PeerId::new(&p2p_address, &key_pair.public_key);
        let temp_dir = TempDir::new().expect("Failed to create TempDir.");
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration.sumeragi_configuration.key_pair = key_pair.clone();
        configuration.sumeragi_configuration.peer_id = new_peer.clone();
        configuration
            .kura_configuration
            .kura_block_store_path(temp_dir.path());
        configuration.torii_configuration.torii_p2p_url = p2p_address;
        configuration.torii_configuration.torii_api_url = api_address.clone();
        configuration.public_key = key_pair.public_key;
        configuration.private_key = key_pair.private_key;
        configuration.sumeragi_configuration.trusted_peers(peer_ids);
        configuration
            .sumeragi_configuration
            .max_faulty_peers(MAX_FAULTS);
        let configuration_clone = configuration.clone();
        task::spawn(async move {
            let iroha = Iroha::new(configuration, AllowAll.into());
            iroha.start().await.expect("Failed to start Iroha.");
            //Prevents temp_dir from clean up until the end of the tests.
            #[allow(clippy::empty_loop)]
            loop {}
        });
        thread::sleep(Duration::from_millis(
            configuration_clone
                .sumeragi_configuration
                .pipeline_time_ms()
                * 2,
        ));
        let add_peer = RegisterBox::new(
            IdentifiableBox::Peer(Peer::new(new_peer).into()),
            IdBox::WorldId,
        );
        iroha_client
            .submit(add_peer.into())
            .expect("Failed to add new peer.");
        thread::sleep(Duration::from_millis(
            configuration_clone
                .sumeragi_configuration
                .pipeline_time_ms()
                * 8,
        ));
        //Then
        let mut client_configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        //The address of a new peer.
        client_configuration.torii_api_url = api_address;
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
                assert_eq!(quantity, asset.quantity);
            } else {
                panic!("Wrong Query Result Type.")
            }
        } else {
            panic!("Wrong Query Result Type.");
        }
    }

    fn create_and_start_iroha_peers(n_peers: usize) -> (Vec<PeerId>, Vec<String>) {
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
            task::spawn(async move {
                let temp_dir = TempDir::new().expect("Failed to create TempDir.");
                let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
                    .expect("Failed to load configuration.");
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
                let iroha = Iroha::new(configuration, AllowAll.into());
                iroha.start().await.expect("Failed to start Iroha.");
                //Prevents temp_dir from clean up untill the end of the tests.
                #[allow(clippy::empty_loop)]
                loop {}
            });
            thread::sleep(std::time::Duration::from_millis(100));
        }
        (
            peer_ids,
            addresses
                .iter()
                .map(|(_, api_url)| api_url)
                .cloned()
                .collect(),
        )
    }
}
