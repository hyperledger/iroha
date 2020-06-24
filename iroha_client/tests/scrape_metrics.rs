#[cfg(test)]
mod tests {
    use async_std::task;
    use iroha::prelude::*;
    use iroha_client::client::Client;
    use std::thread;
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";

    #[async_std::test]
    async fn client_scrape_metrics_request_should_receive_iroha_metrics() {
        thread::spawn(|| create_and_start_iroha());
        thread::sleep(std::time::Duration::from_millis(300));
        let configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let mut iroha_client = Client::with_maintenance(&configuration);
        let result = iroha_client
            .scrape_metrics()
            .await
            .expect("Failed to execute request.");
        dbg!(result);
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
