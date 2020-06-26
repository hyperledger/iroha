#[cfg(test)]
mod tests {
    use async_std::{prelude::*, task};
    use iroha::{isi, prelude::*};
    use iroha_client::client::Client;
    use std::{thread, time::Duration};
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";

    #[async_std::test]
    #[ignore]
    async fn client_subscribe_to_changes_request_should_receive_changes() {
        thread::spawn(|| create_and_start_iroha());
        thread::sleep(std::time::Duration::from_millis(300));
        let configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let mut iroha_client = Client::with_maintenance(&configuration);
        let mut stream = iroha_client
            .subscribe_to_block_changes()
            .await
            .expect("Failed to execute request.");
        let domain_name = "global";
        let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
        let create_asset = isi::Register {
            object: AssetDefinition::new(asset_definition_id.clone()),
            destination_id: domain_name.to_string(),
        };
        let mut iroha_client = Client::new(&configuration);
        iroha_client
            .submit(create_asset.into())
            .await
            .expect("Failed to prepare state.");
        task::sleep(Duration::from_millis(&configuration.pipeline_time_ms() * 2)).await;
        if let Some(change) = stream.next().await {
            println!("Change received {:?}", change);
        } else {
            panic!("Failed to receive change.");
        }
    }

    fn create_and_start_iroha() {
        let temp_dir = TempDir::new().expect("Failed to create TempDir.");
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration.kura_block_store_path(temp_dir.path());
        let iroha = Iroha::new(configuration);
        task::block_on(iroha.start()).expect("Failed to start Iroha.");
        //Prevents temp_dir from clean up untill the end of the tests.
        loop {}
    }
}
