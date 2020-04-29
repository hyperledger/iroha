use clap::{App, Arg};

const CONFIG: &str = "config";
const CREATE: &str = "create";
const UPDATE: &str = "update";
const GET: &str = "get";

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
            App::new(CREATE)
                .about("Use this command to request entities creation in Iroha Peer.")
                .subcommand(
                    domain::build_create_app(),
                )
                .subcommand(
                    account::build_create_app(),
                )
                .subcommand(
                    asset::build_create_app(),
                )
        )
        .subcommand(
            App::new(UPDATE)
            .about("Use this command to request entities related modifications in Iroha Peer.")
            .subcommand(
                asset::build_update_app(),
            )
        )
        .subcommand(
            App::new(GET)
            .about("Use this command to request entities related information from Iroha Peer.")
            .subcommand(
                asset::build_get_app(),
            )
        )
        .get_matches();
    if let Some(configuration_path) = matches.value_of(CONFIG) {
        println!("Value for config: {}", configuration_path);
    }
    if let Some(ref matches) = matches.subcommand_matches(CREATE) {
        domain::match_create(matches);
        account::match_create(matches);
        asset::match_create(matches);
    }
    if let Some(ref matches) = matches.subcommand_matches(UPDATE) {
        asset::match_update(matches);
    }
    if let Some(ref matches) = matches.subcommand_matches(GET) {
        asset::match_get(matches);
    }
}

mod domain {
    use super::*;
    use clap::ArgMatches;
    use futures::executor;
    use iroha::{domain::isi::CreateDomain, prelude::*};
    use iroha_client::client::Client;

    const DOMAIN: &str = "domain";
    const DOMAIN_NAME: &str = "name";

    pub fn build_create_app<'a, 'b>() -> App<'a, 'b> {
        App::new(DOMAIN).arg(
            Arg::with_name(DOMAIN_NAME)
                .long(DOMAIN_NAME)
                .value_name(DOMAIN_NAME)
                .help("Domain's name as double-quoted string.")
                .takes_value(true)
                .required(true),
        )
    }

    pub fn match_create(matches: &ArgMatches<'_>) {
        if let Some(ref matches) = matches.subcommand_matches(DOMAIN) {
            if let Some(domain_name) = matches.value_of(DOMAIN_NAME) {
                println!("Creating domain with a name: {}", domain_name);
                create_domain(domain_name);
            }
        }
    }

    fn create_domain(domain_name: &str) {
        let create_domain = CreateDomain {
            domain_name: String::from(domain_name),
        };
        let mut iroha_client = Client::new(
            Configuration::from_path("config.json").expect("Failed to load configuration."),
        );
        executor::block_on(iroha_client.submit(create_domain.into()))
            .expect("Failed to create domain.");
    }
}

mod account {
    use super::*;
    use clap::ArgMatches;
    use futures::executor;
    use iroha::{account::isi::CreateAccount, prelude::*};
    use iroha_client::client::Client;

    const ACCOUNT: &str = "account";
    const ACCOUNT_NAME: &str = "name";
    const ACCOUNT_DOMAIN_NAME: &str = "domain";
    const ACCOUNT_KEY: &str = "key";

    pub fn build_create_app<'a, 'b>() -> App<'a, 'b> {
        App::new(ACCOUNT)
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
            )
    }

    pub fn match_create(matches: &ArgMatches<'_>) {
        if let Some(ref matches) = matches.subcommand_matches(ACCOUNT) {
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
        let create_account = CreateAccount {
            account_id: Id::new(account_name, domain_name),
            domain_name: String::from(domain_name),
            public_key: [63; 32],
        };
        let mut iroha_client = Client::new(
            Configuration::from_path("config.json").expect("Failed to load configuration."),
        );
        executor::block_on(iroha_client.submit(create_account.into()))
            .expect("Failed to create account.");
    }
}

mod asset {
    use super::*;
    use clap::ArgMatches;
    use futures::executor;
    use iroha::{asset::isi::AddAssetQuantity, prelude::*};
    use iroha_client::client::{self, Client};

    const ASSET: &str = "asset";
    const ASSET_ADD: &str = "add";
    const ASSET_NAME: &str = "name";
    const ASSET_DECIMALS: &str = "decimals";
    const ASSET_DOMAIN_NAME: &str = "domain";
    const ASSET_ACCOUNT_ID: &str = "account_id";
    const ASSET_ID: &str = "id";
    const ASSET_AMOUNT: &str = "amount";

    pub fn build_create_app<'a, 'b>() -> App<'a, 'b> {
        App::new(ASSET)
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
            .arg(
                Arg::with_name(ASSET_DECIMALS)
                    .long(ASSET_DECIMALS)
                    .value_name(ASSET_DECIMALS)
                    .help("Asset's quantity of decimals as an integer.")
                    .takes_value(true)
                    .required(true),
            )
    }

    pub fn build_update_app<'a, 'b>() -> App<'a, 'b> {
        App::new(ASSET)
                .about("Use this command to request assets related modifications in Iroha Peer.")
                .subcommand(
                    App::new(ASSET_ADD)
                    .about("Use this command to request Add Asset Quantity Iroha Special Instruction execution in Iroha Peer.")
                    .arg(Arg::with_name(ASSET_ACCOUNT_ID).long(ASSET_ACCOUNT_ID).value_name(ASSET_ACCOUNT_ID).help("Account's id as double-quoted string in the following format `account_name@domain_name`.").takes_value(true).required(true))
                    .arg(Arg::with_name(ASSET_ID).long(ASSET_ID).value_name(ASSET_ID).help("Asset's id as double-quoted string in the following format `asset_name@domain_name`.").takes_value(true).required(true))
                    .arg(Arg::with_name(ASSET_AMOUNT).long(ASSET_AMOUNT).value_name(ASSET_AMOUNT).help("Asset's amount as a number.").takes_value(true).required(true))
                )
    }

    pub fn build_get_app<'a, 'b>() -> App<'a, 'b> {
        App::new(ASSET)
                .about("Use this command to request assets related information from Iroha Peer.")
                    .arg(Arg::with_name(ASSET_ACCOUNT_ID).long(ASSET_ACCOUNT_ID).value_name(ASSET_ACCOUNT_ID).help("Account's id as double-quoted string in the following format `account_name@domain_name`.").takes_value(true).required(true))
                    .arg(Arg::with_name(ASSET_ID).long(ASSET_ID).value_name(ASSET_ID).help("Asset's id as double-quoted string in the following format `asset_name@domain_name`.").takes_value(true).required(true))
    }

    pub fn match_create(matches: &ArgMatches<'_>) {
        if let Some(ref matches) = matches.subcommand_matches(ASSET) {
            if let Some(asset_name) = matches.value_of(ASSET_NAME) {
                println!("Creating asset with a name: {}", asset_name);
            }
            if let Some(domain_name) = matches.value_of(ASSET_DOMAIN_NAME) {
                println!("Creating asset with a domain's name: {}", domain_name);
            }
            if let Some(decimals) = matches.value_of(ASSET_DECIMALS) {
                println!("Creating asset with a decimals: {}", decimals);
            }
        }
    }

    pub fn match_update(matches: &ArgMatches<'_>) {
        if let Some(ref matches) = matches.subcommand_matches(ASSET) {
            if let Some(ref matches) = matches.subcommand_matches(ASSET_ADD) {
                if let Some(asset_id) = matches.value_of(ASSET_ID) {
                    println!("Updating asset with an identification: {}", asset_id);
                    if let Some(account_id) = matches.value_of(ASSET_ACCOUNT_ID) {
                        println!("Updating account with an identification: {}", account_id);
                        if let Some(amount) = matches.value_of(ASSET_AMOUNT) {
                            println!("Updating asset's amount: {}", amount);
                            add_asset(asset_id, account_id, amount);
                        }
                    }
                }
            }
        }
    }

    pub fn match_get(matches: &ArgMatches<'_>) {
        if let Some(ref matches) = matches.subcommand_matches(ASSET) {
            if let Some(asset_id) = matches.value_of(ASSET_ID) {
                println!("Getting asset with an identification: {}", asset_id);
                if let Some(account_id) = matches.value_of(ASSET_ACCOUNT_ID) {
                    println!("Getting account with an identification: {}", account_id);
                    get_asset(asset_id, account_id);
                }
            }
        }
    }

    fn add_asset(asset_id: &str, account_id: &str, amount: &str) {
        let add_asset = AddAssetQuantity {
            asset_id: Id::from(asset_id),
            account_id: Id::from(account_id),
            amount: amount.parse().expect("Asset amount should be a number."),
        };
        let mut iroha_client = Client::new(
            Configuration::from_path("config.json").expect("Failed to load configuration."),
        );
        executor::block_on(iroha_client.submit(add_asset.into()))
            .expect("Failed to create account.");
    }

    fn get_asset(_asset_id: &str, account_id: &str) {
        let mut iroha_client = Client::new(
            Configuration::from_path("config.json").expect("Failed to load configuration."),
        );
        let query_result = executor::block_on(
            iroha_client.request(&client::assets::by_account_id(Id::from(account_id))),
        )
        .expect("Failed to get asset.");
        let QueryResult::GetAccountAssets(result) = query_result;
        println!("Get Asset result: {:?}", result);
    }
}
