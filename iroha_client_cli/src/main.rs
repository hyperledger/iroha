use clap::{App, Arg};

const CONFIG: &str = "config";
const DOMAIN: &str = "domain";
const ACCOUNT: &str = "account";
const ASSET: &str = "asset";
const MAINTENANCE: &str = "maintenance";

fn main() {
    let matches = App::new("Iroha CLI Client")
        .version("0.1.0")
        .author("Nikita Puzankov <puzankov@soramitsu.co.jp>")
        .about("Iroha CLI Client provides an ability to interact with Iroha Peers Web API without direct network usage.")
        .arg(
            Arg::with_name(CONFIG)
            .short("c")
            .long(CONFIG)
            .value_name("FILE")
            .help("Sets a config file path.")
            .takes_value(true)
            .default_value("config.json"),
            )
        .subcommand(
            domain::build_app(),
            )
        .subcommand(
            account::build_app(),
            )
        .subcommand(
            asset::build_app(),
            )
        .subcommand(
            maintenance::build_app(),
            )
        .get_matches();
    if let Some(configuration_path) = matches.value_of(CONFIG) {
        println!("Value for config: {}", configuration_path);
    }
    if let Some(ref matches) = matches.subcommand_matches(DOMAIN) {
        domain::process(matches);
    }
    if let Some(ref matches) = matches.subcommand_matches(ACCOUNT) {
        account::process(matches);
    }
    if let Some(ref matches) = matches.subcommand_matches(ASSET) {
        asset::process(matches);
    }
    if let Some(ref matches) = matches.subcommand_matches(MAINTENANCE) {
        maintenance::process(matches);
    }
}

mod domain {
    use super::*;
    use clap::ArgMatches;
    use futures::executor;
    use iroha::{isi, peer::PeerId, prelude::*};
    use iroha_client::{client::Client, config::Configuration};

    const DOMAIN_NAME: &str = "name";
    const ADD: &str = "add";

    pub fn build_app<'a, 'b>() -> App<'a, 'b> {
        App::new(DOMAIN)
            .about("Use this command to work with Domain Entities in Iroha Peer.")
            .subcommand(
                App::new(ADD).arg(
                    Arg::with_name(DOMAIN_NAME)
                        .long(DOMAIN_NAME)
                        .value_name(DOMAIN_NAME)
                        .help("Domain's name as double-quoted string.")
                        .takes_value(true)
                        .required(true),
                ),
            )
    }

    pub fn process(matches: &ArgMatches<'_>) {
        if let Some(ref matches) = matches.subcommand_matches(ADD) {
            if let Some(domain_name) = matches.value_of(DOMAIN_NAME) {
                println!("Adding a new Domain with a name: {}", domain_name);
                create_domain(domain_name);
            }
        }
    }

    fn create_domain(domain_name: &str) {
        let configuration =
            &Configuration::from_path("config.json").expect("Failed to load configuration.");
        let mut iroha_client = Client::new(&configuration);
        let create_domain = isi::Add {
            object: Domain::new(domain_name.to_string()),
            destination_id: PeerId::new(&configuration.torii_url, &configuration.public_key),
        };
        executor::block_on(iroha_client.submit(create_domain.into()))
            .expect("Failed to create domain.");
    }
}

mod account {
    use super::*;
    use clap::ArgMatches;
    use futures::executor;
    use iroha::{isi, prelude::*};
    use iroha_client::{client::Client, config::Configuration};

    const REGISTER: &str = "register";
    const ACCOUNT_NAME: &str = "name";
    const ACCOUNT_DOMAIN_NAME: &str = "domain";
    const ACCOUNT_KEY: &str = "key";

    pub fn build_app<'a, 'b>() -> App<'a, 'b> {
        App::new(ACCOUNT)
            .about("Use this command to work with Account Entities in Iroha Peer.")
            .subcommand(
                App::new(REGISTER)
                    .about("Use this command to register new Account in existing Iroha Domain.")
                    .arg(
                        Arg::with_name(ACCOUNT_NAME)
                            .long(ACCOUNT_NAME)
                            .value_name(ACCOUNT_NAME)
                            .help("Account's name as double-quoted string.")
                            .takes_value(true)
                            .required(true),
                    )
                    .arg(
                        Arg::with_name(ACCOUNT_DOMAIN_NAME)
                            .long(ACCOUNT_DOMAIN_NAME)
                            .value_name(ACCOUNT_DOMAIN_NAME)
                            .help("Account's Domain's name as double-quoted string.")
                            .takes_value(true)
                            .required(true),
                    )
                    .arg(
                        Arg::with_name(ACCOUNT_KEY)
                            .long(ACCOUNT_KEY)
                            .value_name(ACCOUNT_KEY)
                            .help("Account's public key as double-quoted string.")
                            .takes_value(true)
                            .required(true),
                    ),
            )
    }

    pub fn process(matches: &ArgMatches<'_>) {
        if let Some(ref matches) = matches.subcommand_matches(REGISTER) {
            if let Some(account_name) = matches.value_of(ACCOUNT_NAME) {
                println!("Creating account with a name: {}", account_name);
                if let Some(domain_name) = matches.value_of(ACCOUNT_DOMAIN_NAME) {
                    println!("Creating account with a domain's name: {}", domain_name);
                    if let Some(public_key) = matches.value_of(ACCOUNT_KEY) {
                        println!("Creating account with a public key: {}", public_key);
                        create_account(account_name, domain_name, public_key);
                    }
                }
            }
        }
    }

    fn create_account(account_name: &str, domain_name: &str, _public_key: &str) {
        let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let create_account = isi::Register {
            object: Account::with_signatory(account_name, domain_name, key_pair.public_key),
            destination_id: String::from(domain_name),
        };
        let mut iroha_client = Client::new(
            &Configuration::from_path("config.json").expect("Failed to load configuration."),
        );
        executor::block_on(iroha_client.submit(create_account.into()))
            .expect("Failed to create account.");
    }
}

mod asset {
    use super::*;
    use clap::ArgMatches;
    use futures::executor;
    use iroha::{isi, prelude::*};
    use iroha_client::{
        client::{self, Client},
        config::Configuration,
    };

    const REGISTER: &str = "register";
    const MINT: &str = "mint";
    const GET: &str = "get";
    const ASSET_NAME: &str = "name";
    const ASSET_DOMAIN_NAME: &str = "domain";
    const ASSET_ACCOUNT_ID: &str = "account_id";
    const ASSET_ID: &str = "id";
    const QUANTITY: &str = "quantity";

    pub fn build_app<'a, 'b>() -> App<'a, 'b> {
        App::new(ASSET)
            .about("Use this command to work with Asset and Asset Definition Entities in Iroha Peer.")
            .subcommand(
                App::new(REGISTER)
                .about("Use this command to register new Asset Definition in existing Iroha Domain.")
                .arg(
                    Arg::with_name(ASSET_DOMAIN_NAME)
                    .long(ASSET_DOMAIN_NAME)
                    .value_name(ASSET_DOMAIN_NAME)
                    .help("Asset's domain's name as double-quoted string.")
                    .takes_value(true)
                    .required(true),
                    )
                .arg(
                    Arg::with_name(ASSET_NAME)
                    .long(ASSET_NAME)
                    .value_name(ASSET_NAME)
                    .help("Asset's name as double-quoted string.")
                    .takes_value(true)
                    .required(true),
                    )
                )
            .subcommand(
                App::new(MINT)
                .about("Use this command to Mint Asset in existing Iroha Account.")
                .arg(Arg::with_name(ASSET_ACCOUNT_ID).long(ASSET_ACCOUNT_ID).value_name(ASSET_ACCOUNT_ID).help("Account's id as double-quoted string in the following format `account_name@domain_name`.").takes_value(true).required(true))
                .arg(Arg::with_name(ASSET_ID).long(ASSET_ID).value_name(ASSET_ID).help("Asset's id as double-quoted string in the following format `asset_name#domain_name`.").takes_value(true).required(true))
                .arg(Arg::with_name(QUANTITY).long(QUANTITY).value_name(QUANTITY).help("Asset's quantity as a number.").takes_value(true).required(true))
                )
            .subcommand(
                App::new(GET)
                .about("Use this command to get Asset information from Iroha Account.")
                .arg(Arg::with_name(ASSET_ACCOUNT_ID).long(ASSET_ACCOUNT_ID).value_name(ASSET_ACCOUNT_ID).help("Account's id as double-quoted string in the following format `account_name@domain_name`.").takes_value(true).required(true))
                .arg(Arg::with_name(ASSET_ID).long(ASSET_ID).value_name(ASSET_ID).help("Asset's id as double-quoted string in the following format `asset_name#domain_name`.").takes_value(true).required(true))

                )
    }

    pub fn process(matches: &ArgMatches<'_>) {
        if let Some(ref matches) = matches.subcommand_matches(REGISTER) {
            if let Some(asset_name) = matches.value_of(ASSET_NAME) {
                println!("Registering asset defintion with a name: {}", asset_name);
                if let Some(domain_name) = matches.value_of(ASSET_DOMAIN_NAME) {
                    println!(
                        "Registering asset definition with a domain's name: {}",
                        domain_name
                    );
                    register_asset_definition(asset_name, domain_name);
                }
            }
        }
        if let Some(ref matches) = matches.subcommand_matches(MINT) {
            if let Some(asset_id) = matches.value_of(ASSET_ID) {
                println!("Minting asset with an identification: {}", asset_id);
                if let Some(account_id) = matches.value_of(ASSET_ACCOUNT_ID) {
                    println!(
                        "Minting asset to account with an identification: {}",
                        account_id
                    );
                    if let Some(amount) = matches.value_of(QUANTITY) {
                        println!("Minting asset's quantity: {}", amount);
                        mint_asset(asset_id, account_id, amount);
                    }
                }
            }
        }
        if let Some(ref matches) = matches.subcommand_matches(GET) {
            if let Some(asset_id) = matches.value_of(ASSET_ID) {
                println!("Getting asset with an identification: {}", asset_id);
                if let Some(account_id) = matches.value_of(ASSET_ACCOUNT_ID) {
                    println!("Getting account with an identification: {}", account_id);
                    get_asset(asset_id, account_id);
                }
            }
        }
    }

    fn register_asset_definition(asset_name: &str, domain_name: &str) {
        let mut iroha_client = Client::new(
            &Configuration::from_path("config.json").expect("Failed to load configuration."),
        );
        executor::block_on(
            iroha_client.submit(
                isi::Register {
                    object: AssetDefinition::new(AssetDefinitionId::new(asset_name, domain_name)),
                    destination_id: domain_name.to_string(),
                }
                .into(),
            ),
        )
        .expect("Failed to create account.");
    }

    fn mint_asset(asset_definition_id: &str, account_id: &str, quantity: &str) {
        let quantity: u32 = quantity.parse().expect("Failed to parse Asset quantity.");
        let mint_asset = isi::Mint {
            object: quantity,
            destination_id: AssetId {
                definition_id: AssetDefinitionId::from(asset_definition_id),
                account_id: AccountId::from(account_id),
            },
        };
        let mut iroha_client = Client::new(
            &Configuration::from_path("config.json").expect("Failed to load configuration."),
        );
        executor::block_on(iroha_client.submit(mint_asset.into()))
            .expect("Failed to create account.");
    }

    fn get_asset(_asset_id: &str, account_id: &str) {
        let mut iroha_client = Client::new(
            &Configuration::from_path("config.json").expect("Failed to load configuration."),
        );
        let query_result = executor::block_on(iroha_client.request(
            &client::assets::by_account_id(<Account as Identifiable>::Id::from(account_id)),
        ))
        .expect("Failed to get asset.");
        if let QueryResult::GetAccountAssets(result) = query_result {
            println!("Get Asset result: {:?}", result);
        }
    }
}

mod maintenance {
    use super::*;
    use async_std::prelude::*;
    use clap::ArgMatches;
    use futures::executor;
    use iroha_client::{client::Client, config::Configuration, prelude::*};

    const HEALTH: &str = "health";
    const METRICS: &str = "metrics";
    const CONNECT: &str = "connect";
    const ENTITY_TYPE: &str = "entity";
    const EVENT_TYPE: &str = "event";

    pub fn build_app<'a, 'b>() -> App<'a, 'b> {
        App::new(MAINTENANCE)
            .about("Use this command to use maintenance functionality.")
            .subcommand(App::new(HEALTH).about("Use this command to check peer's health."))
            .subcommand(App::new(METRICS).about("Use this command to scrape peer's metrics."))
            .subcommand(
                App::new(CONNECT)
                    .about("Use this command to connect to the peer and start consuming events.")
                    .arg(
                        Arg::with_name(ENTITY_TYPE)
                            .long(ENTITY_TYPE)
                            .value_name(ENTITY_TYPE)
                            .help("Type of entity to consume events about.")
                            .takes_value(true)
                            .required(true),
                    )
                    .arg(
                        Arg::with_name(EVENT_TYPE)
                            .long(EVENT_TYPE)
                            .value_name(EVENT_TYPE)
                            .help("Type of event to consume.")
                            .takes_value(true)
                            .required(true),
                    ),
            )
    }

    pub fn process(matches: &ArgMatches<'_>) {
        if let Some(ref matches) = matches.subcommand_matches(CONNECT) {
            if let Some(entity_type) = matches.value_of(ENTITY_TYPE) {
                println!("Connecting to consume events for: {}", entity_type);
                if let Some(event_type) = matches.value_of(EVENT_TYPE) {
                    println!("Connecting to consume events: {}", event_type);
                    if let Err(err) = connect(entity_type, event_type) {
                        eprintln!("Failed to connect: {}", err)
                    }
                }
            }
        }
        if matches.subcommand_matches(HEALTH).is_some() {
            println!("Checking peer's health.");
            health();
        }
        if matches.subcommand_matches(METRICS).is_some() {
            println!("Retrieving peer's metrics.");
            metrics();
        }
    }

    fn health() {
        let mut iroha_client = Client::with_maintenance(
            &Configuration::from_path("config.json").expect("Failed to build configuration"),
        );
        executor::block_on(async {
            let result = iroha_client
                .health()
                .await
                .expect("Failed to execute request.");
            println!("Health is {:?}", result);
        });
    }

    fn metrics() {
        let mut iroha_client = Client::with_maintenance(
            &Configuration::from_path("config.json").expect("Failed to build configuration"),
        );
        executor::block_on(async {
            let result = iroha_client
                .scrape_metrics()
                .await
                .expect("Failed to execute request.");
            println!("{:?}", result);
        });
    }

    fn connect(entity_type: &str, event_type: &str) -> Result<(), String> {
        let mut iroha_client = Client::with_maintenance(&Configuration::from_path("config.json")?);
        let event_type: OccurrenceType = event_type.parse()?;
        let entity_type: EntityType = entity_type.parse()?;
        executor::block_on(async {
            let mut stream = iroha_client
                .subscribe_to_changes(event_type, entity_type)
                .await
                .expect("Failed to execute request.");
            while let Some(change) = stream.next().await {
                println!("Change received {:?}", change);
            }
        });
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use async_std::task;
        use iroha::{config::Configuration, isi, prelude::*};
        use iroha_client::{client::Client, config::Configuration as ClientConfiguration};
        use std::time::Duration;
        use tempfile::TempDir;

        const CONFIGURATION_PATH: &str = "tests/test_config.json";

        #[async_std::test]
        async fn cli_check_health_should_work() {
            task::spawn(async {
                let temp_dir = TempDir::new().expect("Failed to create TempDir.");
                let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
                    .expect("Failed to load configuration.");
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
            super::health();
        }

        #[async_std::test]
        async fn cli_scrape_metrics_should_work() {
            task::spawn(async {
                let temp_dir = TempDir::new().expect("Failed to create TempDir.");
                let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
                    .expect("Failed to load configuration.");
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
            super::metrics();
        }

        #[async_std::test]
        async fn cli_connect_to_consume_block_changes_should_work() {
            task::spawn(async {
                let temp_dir = TempDir::new().expect("Failed to create TempDir.");
                let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
                    .expect("Failed to load configuration.");
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
            let connection_future = async_std::future::timeout(
                Duration::from_millis(300),
                task::spawn(async { super::connect("transaction", "all") }),
            );
            let domain_name = "global";
            let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
            let create_asset = isi::Register {
                object: AssetDefinition::new(asset_definition_id),
                destination_id: domain_name.to_string(),
            };
            let mut iroha_client = Client::new(&ClientConfiguration::from_iroha_configuration(
                &Configuration::from_path(CONFIGURATION_PATH)
                    .expect("Failed to load configuration."),
            ));
            iroha_client
                .submit(create_asset.into())
                .await
                .expect("Failed to prepare state.");
            if let Ok(result) = connection_future.await {
                result.expect("Failed to connect.")
            }
        }
    }
}
