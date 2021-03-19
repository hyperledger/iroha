#[cfg(test)]
mod tests {
    use iroha::{config::Configuration, prelude::*};
    use iroha_client::{
        client::{self, Client},
        config::Configuration as ClientConfiguration,
    };
    use iroha_data_model::account::TRANSACTION_SIGNATORIES_VALUE;
    use iroha_data_model::prelude::*;
    use std::{thread, time::Duration};

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
    const N_PEERS: usize = 4;
    const MAX_FAULTS: u32 = 1;

    #[allow(clippy::too_many_lines)]
    #[test]
    //TODO: use cucumber_rust to write `gherkin` instead of code.
    fn multisignature_transactions_should_wait_for_all_signatures() {
        // Given
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration.sumeragi_configuration.max_faulty_peers = MAX_FAULTS;

        let pipeline_time = std::time::Duration::from_millis(
            configuration.sumeragi_configuration.pipeline_time_ms(),
        );

        let network =
            test_network::Network::new(Some(configuration), N_PEERS).expect("Failed to init peers");

        thread::sleep(pipeline_time * 3);
        let domain_name = "domain";
        let create_domain =
            RegisterBox::new(IdentifiableBox::Domain(Domain::new(domain_name).into()));
        let account_name = "account";
        let account_id = AccountId::new(account_name, domain_name);
        let key_pair_1 = KeyPair::generate().expect("Failed to generate KeyPair.");
        let key_pair_2 = KeyPair::generate().expect("Failed to generate KeyPair.");
        let create_account = RegisterBox::new(IdentifiableBox::Account(
            Account::with_signatory(account_id.clone(), key_pair_1.public_key.clone()).into(),
        ));
        let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
        let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
            AssetDefinition::new(asset_definition_id.clone()).into(),
        ));
        let set_signature_condition = MintBox::new(
            SignatureCheckCondition(
                ContainsAll::new(
                    ContextValue::new(TRANSACTION_SIGNATORIES_VALUE),
                    vec![key_pair_1.public_key.clone(), key_pair_2.public_key.clone()],
                )
                .into(),
            ),
            IdBox::AccountId(account_id.clone()),
        );

        let mut client_configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        client_configuration.torii_api_url = network.genesis.api_address.clone();
        let mut iroha_client = Client::new(&client_configuration);
        let _ = iroha_client
            .submit_all(vec![
                create_domain.into(),
                create_account.into(),
                create_asset.into(),
                set_signature_condition.into(),
            ])
            .expect("Failed to prepare state.");
        thread::sleep(pipeline_time * 2);
        //When
        let quantity: u32 = 200;
        let mint_asset = MintBox::new(
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(asset_definition_id, account_id.clone())),
        );
        client_configuration.account_id = account_id.clone();
        client_configuration.public_key = key_pair_1.public_key;
        client_configuration.private_key = key_pair_1.private_key;
        let mut iroha_client = Client::new(&client_configuration);
        let transaction = iroha_client
            .build_transaction(vec![mint_asset.clone().into()], Metadata::new())
            .expect("Failed to create transaction.");
        let _ = iroha_client
            .submit_transaction(
                iroha_client
                    .sign_transaction(transaction)
                    .expect("Failed to sign transaction."),
            )
            .expect("Failed to submit transaction.");
        thread::sleep(pipeline_time);
        //Then
        client_configuration.torii_api_url = network
            .peers
            .last()
            .expect("Failed to get last peer.")
            .api_address
            .clone();
        let mut iroha_client = Client::new(&client_configuration);
        let request = client::asset::by_account_id(account_id);
        let query_result = iroha_client.request(&request).expect("Query failed.");
        if let QueryResult(Value::Vec(assets)) = query_result {
            assert!(assets.is_empty());
        } else {
            panic!("Wrong Query Result Type.");
        }
        client_configuration.public_key = key_pair_2.public_key;
        client_configuration.private_key = key_pair_2.private_key;
        let mut iroha_client = Client::new(&client_configuration);
        let transaction = iroha_client
            .build_transaction(vec![mint_asset.into()], Metadata::new())
            .expect("Failed to create transaction.");
        let transaction = iroha_client
            .get_original_transaction(&transaction, 3, Duration::from_millis(100))
            .expect("Failed to query pending transactions.")
            .expect("Found no pending transaction for this account.");
        let _ = iroha_client
            .submit_transaction(
                iroha_client
                    .sign_transaction(transaction)
                    .expect("Failed to sign transaction."),
            )
            .expect("Failed to submit transaction.");
        thread::sleep(pipeline_time * 2);
        let query_result = iroha_client.request(&request).expect("Query failed.");
        if let QueryResult(Value::Vec(assets)) = query_result {
            assert!(!assets.is_empty());
            if let Value::Identifiable(IdentifiableBox::Asset(asset)) =
                assets.first().expect("Asset should exist.")
            {
                assert_eq!(AssetValue::Quantity(quantity), asset.value);
            } else {
                panic!("Wrong Query Result Type.")
            }
        } else {
            panic!("Wrong Query Result Type.");
        }
    }
}
