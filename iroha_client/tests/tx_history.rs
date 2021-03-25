#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use iroha::config::Configuration;
    use iroha_client::{
        client::{transaction, Client},
        config::Configuration as ClientConfiguration,
    };
    use iroha_data_model::prelude::*;
    use test_network::Peer as TestPeer;

    const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const GENESIS_PATH: &str = "tests/genesis.json";

    #[test]
    fn client_has_rejected_and_acepted_txs_should_return_tx_history() {
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration.genesis_configuration.genesis_block_path = Some(GENESIS_PATH.to_string());
        let peer = TestPeer::new().expect("Failed to create peer");
        configuration.sumeragi_configuration.trusted_peers.peers =
            std::iter::once(peer.id.clone()).collect();

        let pipeline_time =
            Duration::from_millis(configuration.sumeragi_configuration.pipeline_time_ms());

        // Given
        drop(peer.start_with_config(configuration));
        thread::sleep(pipeline_time);

        let domain_name = "wonderland";
        let account_name = "alice";
        let account_id = AccountId::new(account_name, domain_name);
        let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
        let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
            AssetDefinition::new_quantity(asset_definition_id.clone()).into(),
        ));
        let mut client_config = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        client_config.torii_api_url = peer.api_address;
        let mut iroha_client = Client::new(&client_config);
        let _ = iroha_client
            .submit(create_asset.into())
            .expect("Failed to prepare state.");
        thread::sleep(pipeline_time * 2);
        //When
        let quantity: u32 = 200;

        let asset_id = AssetId::new(asset_definition_id, account_id.clone());

        let mint_existed_asset = MintBox::new(Value::U32(quantity), IdBox::AssetId(asset_id));

        let mint_not_existed_asset = MintBox::new(
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(
                AssetDefinitionId::new("foo", domain_name),
                account_id.clone(),
            )),
        );

        let transactions_count = 100;
        for i in 0..transactions_count {
            let mint_asset = if i % 2 == 0 {
                &mint_existed_asset
            } else {
                &mint_not_existed_asset
            };
            let transaction = iroha_client
                .build_transaction(vec![mint_asset.clone().into()], UnlimitedMetadata::new())
                .expect("Failed to create transaction");
            let hash = iroha_client
                .submit_transaction(transaction)
                .expect("Failed to submit transaction");
            println!("{:?}", hash)
        }
        thread::sleep(pipeline_time * 3);

        let query_result = iroha_client
            .request_with_pagination(
                &transaction::by_account_id(account_id.clone()),
                Pagination {
                    start: Some(1),
                    limit: Some(50),
                },
            )
            .expect("Failed to get transaction history");
        if let QueryResult(Value::Vec(transactions)) = query_result {
            assert_eq!(transactions.len(), 50);
            let mut prev_creation_time = 0;
            for tx in &transactions {
                if let Value::TransactionValue(tx) = tx {
                    assert_eq!(&tx.payload().account_id, &account_id);
                    //check sorted
                    assert!(tx.payload().creation_time >= prev_creation_time);
                    prev_creation_time = tx.payload().creation_time;
                } else {
                    panic!("Wrong Query Result Type.");
                }
            }
        } else {
            panic!("Wrong Query Result Type.");
        }
    }
}
