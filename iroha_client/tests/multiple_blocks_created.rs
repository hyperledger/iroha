#![allow(clippy::module_inception, unused_results, clippy::restriction)]

#[cfg(test)]
mod tests {
    use std::thread;

    use iroha::config::Configuration;
    use iroha::prelude::*;
    use iroha_client::client::{self, Client};
    use iroha_data_model::prelude::*;
    use test_network::*;

    const N_BLOCKS: usize = 510;

    #[ignore = "Takes a lot of time."]
    #[test]
    fn long_multiple_blocks_created() {
        // Given
        let (network, mut iroha_client) = Network::start_test(4, 1);
        let pipeline_time = Configuration::pipeline_time();

        thread::sleep(pipeline_time);

        let create_domain = RegisterBox::new(IdentifiableBox::Domain(Domain::new("domain").into()));
        let account_id = AccountId::new("account", "domain");
        let create_account = RegisterBox::new(IdentifiableBox::NewAccount(
            NewAccount::with_signatory(
                account_id.clone(),
                KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            )
            .into(),
        ));
        let asset_definition_id = AssetDefinitionId::new("xor", "domain");
        let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
            AssetDefinition::new_quantity(asset_definition_id.clone()).into(),
        ));

        iroha_client
            .submit_all(vec![
                create_domain.into(),
                create_account.into(),
                create_asset.into(),
            ])
            .expect("Failed to prepare state.");

        thread::sleep(pipeline_time);

        let mut account_has_quantity = 0;
        //When
        for _ in 0..N_BLOCKS {
            let quantity: u32 = 1;
            let mint_asset = MintBox::new(
                Value::U32(quantity),
                IdBox::AssetId(AssetId::new(
                    asset_definition_id.clone(),
                    account_id.clone(),
                )),
            );
            iroha_client
                .submit(mint_asset)
                .expect("Failed to create asset.");
            account_has_quantity += quantity;
            thread::sleep(pipeline_time);
        }

        thread::sleep(pipeline_time);

        //Then
        Client::test(&network.ids().last().unwrap().address).poll_request(
            client::asset::by_account_id(account_id),
            |result| {
                result.iter().any(|asset| {
                    asset.id.definition_id == asset_definition_id
                        && asset.value == AssetValue::Quantity(account_has_quantity)
                })
            },
        );
    }
}
