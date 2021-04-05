#[cfg(test)]
mod tests {
    use std::thread;

    use iroha::config::Configuration;
    use iroha::prelude::*;
    use iroha_client::client::{self, Client};
    use iroha_data_model::prelude::*;
    use iroha_error::Result;
    use test_network::Peer as TestPeer;
    use test_network::*;

    #[test]
    fn transaction_signed_by_new_signatory_of_account_should_pass() -> Result<()> {
        let (peer, mut iroha_client) = TestPeer::start_test();
        let pipeline_time = Configuration::pipeline_time();
        thread::sleep(pipeline_time);

        // Given
        let account_id = AccountId::new("alice", "wonderland");
        let asset_definition_id = AssetDefinitionId::new("xor", "wonderland");
        let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
            AssetDefinition::new_quantity(asset_definition_id.clone()).into(),
        ));
        let key_pair = KeyPair::generate()?;
        let add_signatory = MintBox::new(
            key_pair.public_key.clone(),
            IdBox::AccountId(account_id.clone()),
        );

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
        Client::test_with_key(&peer.api_address, key_pair).submit_till(
            mint_asset,
            &client::asset::by_account_id(account_id),
            |result| {
                result
                    .find_asset_by_id(&asset_definition_id)
                    .map_or(false, |asset| asset.value == AssetValue::Quantity(quantity))
            },
        );
        Ok(())
    }
}
