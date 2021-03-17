#[cfg(test)]
mod tests {
    use iroha::{config::Configuration, prelude::*};
    use iroha_client::{
        client::{self, Client},
        config::Configuration as ClientConfiguration,
    };
    use iroha_data_model::prelude::*;
    use iroha_error::Result;
    use std::{iter, thread};
    use test_network::Peer as TestPeer;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
    const GENESIS_PATH: &str = "tests/genesis.json";

    #[test]
    fn transaction_signed_by_new_signatory_of_account_should_pass() -> Result<()> {
        let mut configuration = Configuration::from_path(CONFIGURATION_PATH)?;
        configuration.genesis_configuration.genesis_block_path = Some(GENESIS_PATH.to_string());
        let peer = TestPeer::new()?;
        configuration.sumeragi_configuration.trusted_peers.peers =
            iter::once(peer.id.clone()).collect();

        let pipeline_time = std::time::Duration::from_millis(
            configuration.sumeragi_configuration.pipeline_time_ms(),
        );

        // Given
        peer.start_with_config(configuration);
        thread::sleep(pipeline_time);

        let domain_name = "wonderland";
        let account_name = "alice";
        let account_id = AccountId::new(account_name, domain_name);
        let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
        let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
            AssetDefinition::new(asset_definition_id.clone()).into(),
        ));
        let key_pair = KeyPair::generate()?;
        let add_signatory = MintBox::new(
            key_pair.public_key.clone(),
            IdBox::AccountId(account_id.clone()),
        );

        let mut client_configuration = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)?;
        client_configuration.torii_api_url = peer.api_address;

        let mut iroha_client = Client::new(&client_configuration);
        iroha_client.submit_all(vec![create_asset.into(), add_signatory.into()])?;
        thread::sleep(pipeline_time * 2);
        //When
        let quantity: u32 = 200;
        let mint_asset = MintBox::new(
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(
                asset_definition_id.clone(),
                account_id.clone(),
            )),
        );
        client_configuration.public_key = key_pair.public_key;
        client_configuration.private_key = key_pair.private_key;
        let mut iroha_client = Client::new(&client_configuration);
        iroha_client.submit(mint_asset.into())?;
        thread::sleep(pipeline_time * 2);
        //Then
        let request = client::asset::by_account_id(account_id);
        let query_result = iroha_client.request(&request)?;

        if let QueryResult(Value::Vec(assets)) = query_result {
            let asset = assets
                .iter()
                .find_map(|asset| {
                    if let Value::Identifiable(IdentifiableBox::Asset(ref asset)) = asset {
                        if asset.id.definition_id == asset_definition_id {
                            return Some(asset);
                        }
                    }
                    None
                })
                .expect("Asset should exist.");

            assert_eq!(AssetValue::Quantity(quantity), asset.value);
        } else {
            panic!("Wrong Query Result Type.");
        }
        Ok(())
    }
}
