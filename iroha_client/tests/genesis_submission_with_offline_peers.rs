#![allow(clippy::module_inception, unused_results, clippy::restriction)]

#[cfg(test)]
mod tests {
    use std::thread;

    use iroha::config::Configuration;
    use iroha_client::client;
    use iroha_data_model::prelude::*;
    use test_network::*;

    #[test]
    fn genesis_block_is_commited_with_some_offline_peers() {
        // Given
        let (_, mut iroha_client) = Network::start_test_with_offline(4, 1, 1);
        let pipeline_time = Configuration::pipeline_time();

        thread::sleep(pipeline_time * 8);

        //When
        let alice_id = AccountId::new("alice", "wonderland");
        let alice_has_roses = 13;
        //Then
        let request = client::asset::by_account_id(alice_id);
        let query_result = iroha_client
            .request(&request)
            .expect("Failed to execute request.");
        let asset = query_result
            .find_asset_by_id(&AssetDefinitionId::new("rose", "wonderland"))
            .unwrap();
        assert_eq!(AssetValue::Quantity(alice_has_roses), asset.value);
    }
}
