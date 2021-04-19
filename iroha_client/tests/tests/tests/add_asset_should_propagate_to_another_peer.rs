#[cfg(test)]
mod tests {
    use std::thread;

    use iroha::config::Configuration;
    use iroha::prelude::*;
    use iroha_client::client::{self, Client};
    use iroha_data_model::prelude::*;
    use iroha_error::Result;
    use test_network::Network;
    use test_network::*;

    #[test]
    fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount_on_another_peer(
    ) -> Result<()> {
        // Given
        let (network, mut iroha_client) = Network::start_test(4, 1);
        let pipeline_time = Configuration::pipeline_time();

        thread::sleep(pipeline_time * 3);

        let create_domain = RegisterBox::new(IdentifiableBox::Domain(Domain::new("domain").into()));
        let account_id = AccountId::new("account", "domain");
        let create_account = RegisterBox::new(IdentifiableBox::NewAccount(
            NewAccount::with_signatory(account_id.clone(), KeyPair::generate()?.public_key).into(),
        ));
        let asset_definition_id = AssetDefinitionId::new("xor", "domain");
        let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
            AssetDefinition::new_quantity(asset_definition_id.clone()).into(),
        ));
        iroha_client.submit_all(vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ])?;
        thread::sleep(pipeline_time * 4);
        //When
        let quantity: u32 = 200;
        iroha_client.submit(MintBox::new(
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(
                asset_definition_id.clone(),
                account_id.clone(),
            )),
        ))?;

        //Then
        Client::test(&network.peers.last().unwrap().api_address).poll_request(
            &client::asset::by_account_id(account_id),
            |result| {
                result
                    .find_asset_by_id(&asset_definition_id)
                    .map_or(false, |asset| {
                        *asset.value.read() == AssetValue::Quantity(quantity)
                    })
            },
        );
        Ok(())
    }
}
