use clap::{App, Arg};
use iroha_client::config::Configuration;
use iroha_crypto::prelude::*;
use iroha_dsl::prelude::*;
use std::str::FromStr;

const CONFIG: &str = "config";
const DOMAIN: &str = "domain";
const ACCOUNT: &str = "account";
const ASSET: &str = "asset";

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
        .get_matches();
    let configuration_path = matches
        .value_of(CONFIG)
        .expect("Failed to get configuration path.");
    println!("Value for config: {}", configuration_path);
    let configuration =
        Configuration::from_path(configuration_path).expect("Failed to load configuration");
    if let Some(ref matches) = matches.subcommand_matches(DOMAIN) {
        domain::process(matches, &configuration);
    }
    if let Some(ref matches) = matches.subcommand_matches(ACCOUNT) {
        account::process(matches, &configuration);
    }
    if let Some(ref matches) = matches.subcommand_matches(ASSET) {
        asset::process(matches, &configuration);
    }
}

mod domain {
    use super::*;
    use clap::ArgMatches;
    use futures::executor;
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

    pub fn process(matches: &ArgMatches<'_>, configuration: &Configuration) {
        if let Some(ref matches) = matches.subcommand_matches(ADD) {
            if let Some(domain_name) = matches.value_of(DOMAIN_NAME) {
                println!("Adding a new Domain with a name: {}", domain_name);
                create_domain(domain_name, configuration);
            }
        }
    }

    fn create_domain(domain_name: &str, configuration: &Configuration) {
        let mut iroha_client = Client::new(configuration);
        let create_domain = Register::<Peer, Domain>::new(
            Domain::new(domain_name),
            PeerId::new(&configuration.torii_url, &configuration.public_key),
        );
        executor::block_on(iroha_client.submit(create_domain.into()))
            .expect("Failed to create domain.");
    }
}

mod account {
    use super::*;
    use clap::ArgMatches;
    use futures::executor;
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

    pub fn process(matches: &ArgMatches<'_>, configuration: &Configuration) {
        if let Some(ref matches) = matches.subcommand_matches(REGISTER) {
            if let Some(account_name) = matches.value_of(ACCOUNT_NAME) {
                println!("Creating account with a name: {}", account_name);
                if let Some(domain_name) = matches.value_of(ACCOUNT_DOMAIN_NAME) {
                    println!("Creating account with a domain's name: {}", domain_name);
                    if let Some(public_key) = matches.value_of(ACCOUNT_KEY) {
                        println!("Creating account with a public key: {}", public_key);
                        create_account(account_name, domain_name, public_key, configuration);
                    }
                }
            }
        }
    }

    fn create_account(
        account_name: &str,
        domain_name: &str,
        _public_key: &str,
        configuration: &Configuration,
    ) {
        let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let create_account = Register::<Domain, Account>::new(
            Account::with_signatory(
                AccountId::new(account_name, domain_name),
                key_pair.public_key,
            ),
            Name::from(domain_name),
        );
        let mut iroha_client = Client::new(configuration);
        executor::block_on(iroha_client.submit(create_account.into()))
            .expect("Failed to create account.");
    }
}

mod asset {
    use super::*;
    use clap::ArgMatches;
    use futures::executor;
    use iroha_client::{
        client::{asset, Client},
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

    pub fn process(matches: &ArgMatches<'_>, configuration: &Configuration) {
        if let Some(ref matches) = matches.subcommand_matches(REGISTER) {
            if let Some(asset_name) = matches.value_of(ASSET_NAME) {
                println!("Registering asset defintion with a name: {}", asset_name);
                if let Some(domain_name) = matches.value_of(ASSET_DOMAIN_NAME) {
                    println!(
                        "Registering asset definition with a domain's name: {}",
                        domain_name
                    );
                    register_asset_definition(asset_name, domain_name, configuration);
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
                        mint_asset(asset_id, account_id, amount, configuration);
                    }
                }
            }
        }
        if let Some(ref matches) = matches.subcommand_matches(GET) {
            if let Some(asset_id) = matches.value_of(ASSET_ID) {
                println!("Getting asset with an identification: {}", asset_id);
                if let Some(account_id) = matches.value_of(ASSET_ACCOUNT_ID) {
                    println!("Getting account with an identification: {}", account_id);
                    get_asset(asset_id, account_id, configuration);
                }
            }
        }
    }

    fn register_asset_definition(
        asset_name: &str,
        domain_name: &str,
        configuration: &Configuration,
    ) {
        let mut iroha_client = Client::new(configuration);
        executor::block_on(
            iroha_client.submit(
                Register::<Domain, AssetDefinition>::new(
                    AssetDefinition::new(AssetDefinitionId::new(asset_name, domain_name)),
                    domain_name.to_string(),
                )
                .into(),
            ),
        )
        .expect("Failed to create account.");
    }

    fn mint_asset(
        asset_definition_id: &str,
        account_id: &str,
        quantity: &str,
        configuration: &Configuration,
    ) {
        let quantity: u32 = quantity.parse().expect("Failed to parse Asset quantity.");
        let mint_asset = Mint::<Asset, u32>::new(
            quantity,
            AssetId::new(
                AssetDefinitionId::from_str(asset_definition_id)
                    .expect("Failed to parse Asset Definition Id."),
                AccountId::from_str(account_id).expect("Failed to parse Account Id."),
            ),
        );
        let mut iroha_client = Client::new(configuration);
        executor::block_on(iroha_client.submit(mint_asset.into()))
            .expect("Failed to create account.");
    }

    fn get_asset(_asset_id: &str, account_id: &str, configuration: &Configuration) {
        let mut iroha_client = Client::new(configuration);
        let query_result = executor::block_on(iroha_client.request(&asset::by_account_id(
            AccountId::from_str(account_id).expect("Failed to parse Account Id."),
        )))
        .expect("Failed to get asset.");
        if let QueryResult::FindAssetsByAccountId(result) = query_result {
            println!("Get Asset result: {:?}", result);
        }
    }
}
