#[cfg(test)]
mod tests {
    use async_std::task;
    use iroha::{config::Configuration, peer::PeerId as IrohaPeerId, Iroha};
    use iroha_client_no_std::{
        asset::isi::AssetInstruction,
        client::{self, Client},
        config::Configuration as ClientConfiguration,
        domain::isi::DomainInstruction,
        isi,
        peer::isi::PeerInstruction,
        peer::PeerId,
        prelude::*,
    };
    use iroha_crypto::KeyPair;
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const N_PEERS: usize = 4;
    const MAX_FAULTS: usize = 1;

    #[async_std::test]
    #[ignore]
    //TODO: use cucumber to write `gherkin` instead of code.
    async fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount_on_another_peer(
    ) {
        // Given
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let peers = create_and_start_iroha_peers(N_PEERS).await;
        task::sleep(std::time::Duration::from_millis(1000)).await;
        let domain_name = "domain";
        let create_domain = isi::Instruction::Peer(PeerInstruction::AddDomain(
            domain_name.to_string(),
            PeerId::new(
                &configuration.torii_configuration.torii_url,
                &configuration.public_key,
            ),
        ));
        configuration.torii_configuration.torii_url = peers
            .first()
            .expect("Failed to get first peer.")
            .address
            .clone();
        let account_name = "account";
        let account_id = AccountId::new(account_name, domain_name);
        let (public_key, _) = configuration.key_pair();
        let create_account = isi::Instruction::Domain(DomainInstruction::RegisterAccount(
            String::from(domain_name),
            Account::with_signatory(account_name, domain_name, public_key),
        ));
        let asset_id = AssetDefinitionId::new("xor", domain_name);
        let create_asset = isi::Instruction::Domain(DomainInstruction::RegisterAsset(
            domain_name.to_string(),
            AssetDefinition::new(asset_id.clone()),
        ));
        let mut iroha_client = Client::new(&ClientConfiguration::from_iroha_configuration(
            &configuration,
        ));
        iroha_client
            .submit_all(vec![
                create_domain.into(),
                create_account.into(),
                create_asset.into(),
            ])
            .await
            .expect("Failed to prepare state.");
        task::sleep(std::time::Duration::from_millis(
            configuration.sumeragi_configuration.pipeline_time_ms() * 2,
        ))
        .await;
        //When
        let quantity: u32 = 200;
        let mint_asset = isi::Instruction::Asset(AssetInstruction::MintAsset(
            quantity,
            AssetId {
                definition_id: asset_id.clone(),
                account_id: account_id.clone(),
            },
        ));
        iroha_client
            .submit(mint_asset.into())
            .await
            .expect("Failed to create asset.");
        task::sleep(std::time::Duration::from_millis(
            configuration.sumeragi_configuration.pipeline_time_ms() * 2,
        ))
        .await;
        //Then
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration.torii_configuration.torii_url = peers
            .last()
            .expect("Failed to get last peer.")
            .address
            .clone();
        let mut iroha_client = Client::new(&ClientConfiguration::from_iroha_configuration(
            &configuration,
        ));
        let request = client::assets::by_account_id(account_id);
        let query_result = iroha_client
            .request(&request)
            .await
            .expect("Failed to execute request.");
        if let QueryResult::GetAccountAssets(result) = query_result {
            assert!(!result.assets.is_empty());
            assert_eq!(
                quantity,
                result.assets.first().expect("Asset should exist.").quantity,
            );
        } else {
            panic!("Wrong Query Result Type.");
        }
    }

    async fn create_and_start_iroha_peers(n_peers: usize) -> Vec<PeerId> {
        let peer_keys: Vec<KeyPair> = (0..n_peers)
            .map(|_| KeyPair::generate().expect("Failed to generate key pair."))
            .collect();
        let peer_ids: Vec<PeerId> = peer_keys
            .iter()
            .enumerate()
            .map(|(i, key_pair)| PeerId {
                address: format!("127.0.0.1:{}", 1337 + i),
                public_key: key_pair.public_key.clone(),
            })
            .collect();
        for (peer_id, key_pair) in peer_ids.iter().zip(peer_keys) {
            let peer_ids = peer_ids.clone();
            let peer_id = peer_id.clone();
            task::spawn(async move {
                let temp_dir = TempDir::new().expect("Failed to create TempDir.");
                let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
                    .expect("Failed to load configuration.");
                configuration.sumeragi_configuration.key_pair = key_pair.clone();
                configuration.sumeragi_configuration.peer_id =
                    IrohaPeerId::new(&peer_id.address, &peer_id.public_key);
                configuration
                    .kura_configuration
                    .kura_block_store_path(temp_dir.path());
                configuration.torii_configuration.torii_url = peer_id.address.clone();
                configuration.public_key = key_pair.public_key;
                configuration.private_key = key_pair.private_key.clone();
                configuration.sumeragi_configuration.trusted_peers(
                    peer_ids
                        .iter()
                        .map(|x| IrohaPeerId::new(&x.address, &x.public_key))
                        .collect(),
                );
                configuration
                    .sumeragi_configuration
                    .max_faulty_peers(MAX_FAULTS);
                let iroha = Iroha::new(configuration);
                iroha.start().await.expect("Failed to start Iroha.");
                //Prevents temp_dir from clean up untill the end of the tests.
                #[allow(clippy::empty_loop)]
                loop {}
            });
            task::sleep(std::time::Duration::from_millis(100)).await;
        }
        peer_ids.clone()
    }
}
