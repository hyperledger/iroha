#[cfg(test)]
mod tests {
    use async_std::task;
    use iroha::{maintenance::*, prelude::*};
    use iroha_client::client::Client;
    use std::thread;
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";

    #[async_std::test]
    //TODO: use cucumber to write `gherkin` instead of code.
    async fn client_check_health_request_should_receive_iroha_status_alive() {
        // Given
        thread::spawn(|| create_and_start_iroha());
        thread::sleep(std::time::Duration::from_millis(300));
        let configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let mut iroha_client = Client::with_maintenance(&configuration);
        //When
        let result = iroha_client
            .health()
            .await
            .expect("Failed to execute request.");
        //Then
        if let Health::Healthy = result {
            println!("Result: {:?}", result);
        } else {
            panic!("Result: {:?} is not in Alive state.", result);
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
