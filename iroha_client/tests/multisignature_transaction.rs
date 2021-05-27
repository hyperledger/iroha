#![allow(clippy::module_inception, unused_results, clippy::restriction)]

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use iroha::config::Configuration;
    use iroha::prelude::*;
    use iroha_client::{
        client::{self, Client},
        config::Configuration as ClientConfiguration,
    };
    use iroha_data_model::account::TRANSACTION_SIGNATORIES_VALUE;
    use iroha_data_model::prelude::*;
    use test_network::*;

    const N_PEERS: u32 = 4;

    #[allow(clippy::too_many_lines)]
    #[test]
    //TODO: use cucumber_rust to write `gherkin` instead of code.
    fn multisignature_transactions_should_wait_for_all_signatures() {
        let (network, _) = Network::start_test(N_PEERS, 1);
        let pipeline_time = Configuration::pipeline_time();

        thread::sleep(pipeline_time * 3);

        let create_domain = RegisterBox::new(IdentifiableBox::Domain(Domain::new("domain").into()));
        let account_id = AccountId::new("account", "domain");
        let key_pair_1 = KeyPair::generate().expect("Failed to generate KeyPair.");
        let key_pair_2 = KeyPair::generate().expect("Failed to generate KeyPair.");
        let create_account = RegisterBox::new(IdentifiableBox::from(NewAccount::with_signatory(
            account_id.clone(),
            key_pair_1.public_key.clone(),
        )));
        let asset_definition_id = AssetDefinitionId::new("xor", "domain");
        let create_asset = RegisterBox::new(IdentifiableBox::from(AssetDefinition::new_quantity(
            asset_definition_id.clone(),
        )));
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

        let mut client_configuration = ClientConfiguration::test(&network.genesis.api_address);
        let mut iroha_client = Client::new(&client_configuration);
        iroha_client
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
            .build_transaction(vec![mint_asset.clone().into()], UnlimitedMetadata::new())
            .expect("Failed to create transaction.");
        iroha_client
            .submit_transaction(
                iroha_client
                    .sign_transaction(transaction)
                    .expect("Failed to sign transaction."),
            )
            .expect("Failed to submit transaction.");
        thread::sleep(pipeline_time);
        //Then
        client_configuration.torii_api_url = network.peers.last().unwrap().api_address.clone();
        let mut iroha_client = Client::new(&client_configuration);
        let request = client::asset::by_account_id(account_id);
        assert!(iroha_client
            .request(request.clone())
            .expect("Query failed.")
            .is_empty());
        client_configuration.public_key = key_pair_2.public_key;
        client_configuration.private_key = key_pair_2.private_key;
        let mut iroha_client = Client::new(&client_configuration);
        let transaction = iroha_client
            .build_transaction(vec![mint_asset.into()], UnlimitedMetadata::new())
            .expect("Failed to create transaction.");
        let transaction = iroha_client
            .get_original_transaction(&transaction, 3, Duration::from_millis(100))
            .expect("Failed to query pending transactions.")
            .expect("Found no pending transaction for this account.");
        iroha_client
            .submit_transaction(
                iroha_client
                    .sign_transaction(transaction)
                    .expect("Failed to sign transaction."),
            )
            .expect("Failed to submit transaction.");
        thread::sleep(pipeline_time * 2);
        let assets = iroha_client.request(request).expect("Query failed.");
        assert!(!assets.is_empty());
        assert_eq!(AssetValue::Quantity(quantity), assets[0].value);
    }
}
