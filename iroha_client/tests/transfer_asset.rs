#[cfg(test)]
mod tests {
    #![allow(clippy::shadow_unrelated)]

    use std::{thread, time::Duration};

    use iroha::{config::Configuration, prelude::*};
    use iroha_client::{
        client::{self, Client},
        config::Configuration as ClientConfiguration,
    };
    use iroha_data_model::prelude::*;
    use test_network::Peer as TestPeer;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
    const GENESIS_PATH: &str = "tests/genesis.json";

    #[test]
    //TODO: use cucumber_rust to write `gherkin` instead of code.
    fn client_can_transfer_asset_to_another_account() {
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

        let mut client_config = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration.");
        client_config.torii_api_url = peer.api_address;
        let mut iroha_client = Client::new(&client_config);

        let domain_name = "domain";
        let create_domain =
            RegisterBox::new(IdentifiableBox::Domain(Domain::new(domain_name).into()));
        let account1_name = "account1";
        let account2_name = "account2";
        let account1_id = AccountId::new(account1_name, domain_name);
        let account2_id = AccountId::new(account2_name, domain_name);
        let create_account1 = RegisterBox::new(IdentifiableBox::NewAccount(
            NewAccount::with_signatory(
                account1_id.clone(),
                KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            )
            .into(),
        ));
        let create_account2 = RegisterBox::new(IdentifiableBox::NewAccount(
            NewAccount::with_signatory(
                account2_id.clone(),
                KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            )
            .into(),
        ));
        let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
        let quantity: u32 = 200;
        let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
            AssetDefinition::new_quantity(asset_definition_id.clone()).into(),
        ));
        let mint_asset = MintBox::new(
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(
                asset_definition_id.clone(),
                account1_id.clone(),
            )),
        );
        let _ = iroha_client
            .submit_all(vec![
                create_domain.into(),
                create_account1.into(),
                create_account2.into(),
                create_asset.into(),
                mint_asset.into(),
            ])
            .expect("Failed to prepare state.");
        thread::sleep(std::time::Duration::from_millis(200 * 2));
        //When
        let quantity = 20;
        let transfer_asset = TransferBox::new(
            IdBox::AssetId(AssetId::new(asset_definition_id.clone(), account1_id)),
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(asset_definition_id, account2_id.clone())),
        );
        let _ = iroha_client
            .submit(transfer_asset.into())
            .expect("Failed to submit instruction.");
        thread::sleep(pipeline_time * 2);
        //Then
        let request = client::asset::by_account_id(account2_id.clone());
        let query_result = iroha_client
            .request(&request)
            .expect("Failed to execute request.");
        if let QueryResult(Value::Vec(assets)) = query_result {
            assert!(!assets.is_empty());
            assert_eq!(
                assets
                    .iter()
                    .filter(|asset| {
                        if let Value::Identifiable(IdentifiableBox::Asset(asset)) = asset {
                            asset.value == AssetValue::Quantity(quantity)
                                && asset.id.account_id == account2_id
                        } else {
                            false
                        }
                    })
                    .count(),
                1
            );
        } else {
            panic!("Wrong Query Result Type.");
        }
    }
}
