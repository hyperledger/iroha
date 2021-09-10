#![allow(clippy::restriction)]

#[cfg(test)]
mod tests {
    use std::thread;

    use eyre::Result;
    use iroha::{config::Configuration, prelude::*};
    use iroha_client::client;
    use iroha_data_model::prelude::*;
    use test_network::*;

    #[test]
    fn asset_amount_should_be_the_same_on_a_recently_added_peer() -> Result<()> {
        // Given
        let (rt, network, mut iroha_client) = <Network>::start_test_with_runtime(4, 1);
        let pipeline_time = Configuration::pipeline_time();

        thread::sleep(pipeline_time * 2);
        iroha_logger::info!("Started");

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
        thread::sleep(pipeline_time * 2);
        iroha_logger::info!("Init");

        //When
        let quantity: u32 = 200;
        let mint_asset = MintBox::new(
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(
                asset_definition_id.clone(),
                account_id.clone(),
            )),
        );
        iroha_client.submit(mint_asset)?;
        thread::sleep(pipeline_time * 5);
        iroha_logger::info!("Mint");

        let (_peer, mut iroha_client) = rt.block_on(network.add_peer());

        //Then
        iroha_client.poll_request_with_period(
            client::asset::by_account_id(account_id),
            Configuration::block_sync_gossip_time(),
            15,
            |result| {
                result.iter().any(|asset| {
                    asset.id.definition_id == asset_definition_id
                        && asset.value == AssetValue::Quantity(quantity)
                })
            },
        );
        Ok(())
    }
}
