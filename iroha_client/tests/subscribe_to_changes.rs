#[cfg(test)]
mod tests {
    use async_std::{future, task};
    use iroha::{config::Configuration, event::*, isi, prelude::*};
    use iroha_client::{client::Client, config::Configuration as ClientConfiguration, prelude::*};
    use std::time::Duration;
    use tempfile::TempDir;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";

    #[async_std::test]
    async fn client_subscribe_to_block_changes_request_should_receive_block_change() {
        task::spawn(async {
            let temp_dir = TempDir::new().expect("Failed to create TempDir.");
            let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
                .expect("Failed to load configuration.");
            configuration.torii_configuration.torii_url = "127.0.0.1:1337".to_string();
            configuration.torii_configuration.torii_connect_url = "127.0.0.1:8889".to_string();
            configuration
                .kura_configuration
                .kura_block_store_path(temp_dir.path());
            let iroha = Iroha::new(configuration.clone());
            iroha.start().await.expect("Failed to start Iroha.");
            //Prevents temp_dir from clean up untill the end of the tests.
            #[allow(clippy::empty_loop)]
            loop {}
        });
        task::sleep(Duration::from_millis(300)).await;
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration.torii_configuration.torii_connect_url = "127.0.0.1:8889".to_string();
        let mut iroha_client = Client::with_maintenance(
            &ClientConfiguration::from_iroha_configuration(&configuration),
        );
        let mut stream = iroha_client
            .subscribe_to_changes(OccurrenceType::All, EntityType::Block)
            .await
            .expect("Failed to execute request.");
        let domain_name = "global";
        let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
        let create_asset = isi::Register {
            object: AssetDefinition::new(asset_definition_id),
            destination_id: domain_name.to_string(),
        };
        let mut iroha_client = Client::new(&ClientConfiguration::from_iroha_configuration(
            &configuration,
        ));
        task::spawn(async move {
            task::sleep(Duration::from_millis(300)).await;
            iroha_client
                .submit(create_asset.into())
                .await
                .expect("Failed to prepare state.");
        });
        future::timeout(
            Duration::from_millis(1000),
            task::spawn(async move {
                while let Some(change) = stream.next() {
                    println!("Change received {:?}", change);
                    match change {
                        Occurrence::Created(entity)
                        | Occurrence::Updated(entity)
                        | Occurrence::Deleted(entity) => match entity {
                            Entity::Block(_) => {
                                println!("Entity changed: {:?}", entity);
                                return ();
                            }
                            _ => println!("Received not expected change: {:?}", entity),
                        },
                    }
                }
            }),
        )
        .await
        .expect("Changes not received.");
    }

    #[async_std::test]
    async fn client_subscribe_to_transaction_changes_request_should_receive_transaction_change() {
        task::spawn(async {
            let temp_dir = TempDir::new().expect("Failed to create TempDir.");
            let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
                .expect("Failed to load configuration.");
            configuration.torii_configuration.torii_url = "127.0.0.1:1338".to_string();
            configuration.torii_configuration.torii_connect_url = "127.0.0.1:8890".to_string();
            configuration
                .kura_configuration
                .kura_block_store_path(temp_dir.path());
            let iroha = Iroha::new(configuration.clone());
            iroha.start().await.expect("Failed to start Iroha.");
            //Prevents temp_dir from clean up untill the end of the tests.
            #[allow(clippy::empty_loop)]
            loop {}
        });
        task::sleep(Duration::from_millis(300)).await;
        let mut configuration =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        configuration.torii_configuration.torii_url = "127.0.0.1:1338".to_string();
        configuration.torii_configuration.torii_connect_url = "127.0.0.1:8890".to_string();
        let mut iroha_client = Client::with_maintenance(
            &ClientConfiguration::from_iroha_configuration(&configuration),
        );
        let mut stream = iroha_client
            .subscribe_to_changes(OccurrenceType::All, EntityType::Transaction)
            .await
            .expect("Failed to execute request.");
        let domain_name = "global";
        let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
        let create_asset = isi::Register {
            object: AssetDefinition::new(asset_definition_id),
            destination_id: domain_name.to_string(),
        };
        let mut iroha_client = Client::new(&ClientConfiguration::from_iroha_configuration(
            &configuration,
        ));
        task::spawn(async move {
            task::sleep(Duration::from_millis(300)).await;
            iroha_client
                .submit(create_asset.into())
                .await
                .expect("Failed to prepare state.");
        });
        future::timeout(
            Duration::from_millis(1000),
            task::spawn(async move {
                while let Some(change) = stream.next() {
                    println!("Change received {:?}", change);
                    match change {
                        Occurrence::Created(entity)
                        | Occurrence::Updated(entity)
                        | Occurrence::Deleted(entity) => match entity {
                            Entity::Transaction(_) => {
                                println!("Entity changed: {:?}", entity);
                                return ();
                            }
                            _ => println!("Received not expected change: {:?}", entity),
                        },
                    }
                }
            }),
        )
        .await
        .expect("Changes not received.");
    }
}
