#[cfg(test)]
mod tests {
    use iroha::{config::Configuration, prelude::*};
    use iroha_client::{
        client::{self, Client},
        config::Configuration as ClientConfiguration,
    };
    use iroha_data_model::prelude::*;
    use std::{thread, time::Duration};
    use test_network::Peer as TestPeer;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
    const N_PEERS: usize = 4;
    const MAX_FAULTS: u32 = 1;

    #[test]
    fn asset_amount_should_be_the_same_on_a_recently_added_peer() {
        // Given
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration.sumeragi_configuration.max_faulty_peers = MAX_FAULTS;

        let pipeline_time =
            Duration::from_millis(configuration.sumeragi_configuration.pipeline_time_ms());

        let network = test_network::Network::new(Some(configuration.clone()), N_PEERS)
            .expect("Failed to init peers");

        thread::sleep(pipeline_time * 3);

        let domain_name = "domain";
        let create_domain =
            RegisterBox::new(IdentifiableBox::Domain(Domain::new(domain_name).into()));
        let account_name = "account";
        let account_id = AccountId::new(account_name, domain_name);
        let create_account = RegisterBox::new(IdentifiableBox::Account(
            Account::with_signatory(
                account_id.clone(),
                KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            )
            .into(),
        ));
        let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
        let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
            AssetDefinition::new(asset_definition_id.clone()).into(),
        ));
        let mut client_configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        client_configuration.torii_api_url = network.genesis.api_address.clone();
        let mut iroha_client = Client::new(&client_configuration);
        iroha_client
            .submit_all(vec![
                create_domain.into(),
                create_account.into(),
                create_asset.into(),
            ])
            .expect("Failed to prepare state.");
        thread::sleep(pipeline_time * 2);
        //When
        let quantity: u32 = 200;
        let mint_asset = MintBox::new(
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(asset_definition_id, account_id.clone())),
        );
        iroha_client
            .submit(mint_asset.into())
            .expect("Failed to create asset.");
        thread::sleep(pipeline_time * 2);

        let peer = TestPeer::new().expect("Failed to create new peer");
        configuration.sumeragi_configuration.trusted_peers = network.ids().collect();

        peer.start_with_config(configuration);

        thread::sleep(pipeline_time * 2);
        let add_peer = RegisterBox::new(IdentifiableBox::Peer(Peer::new(peer.id).into()));
        iroha_client
            .submit(add_peer.into())
            .expect("Failed to add new peer.");
        thread::sleep(pipeline_time * 8);
        //Then
        let mut client_configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        //The address of a new peer.
        client_configuration.torii_api_url = peer.api_address;
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
}
