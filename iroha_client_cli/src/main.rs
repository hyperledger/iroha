//! iroha client command line

#![allow(missing_docs)]

use clap::{App, Arg};
use dialoguer::Confirm;
use iroha_client::{client::Client, config::Configuration};
use iroha_crypto::prelude::*;
use iroha_dsl::prelude::*;
use iroha_error::{Result, WrapErr};
use std::{str::FromStr, time::Duration};

const CONFIG: &str = "config";
const DOMAIN: &str = "domain";
const ACCOUNT: &str = "account";
const ASSET: &str = "asset";
const EVENTS: &str = "listen";

// TODO: move into config.
const RETRY_COUNT_MST: u32 = 1;
const RETRY_IN_MST_MS: u64 = 100;

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
        .subcommand(domain::build_app())
        .subcommand(account::build_app())
        .subcommand(asset::build_app())
        .subcommand(events::build_app())
        .get_matches();
    let configuration_path = matches
        .value_of(CONFIG)
        .expect("Failed to get configuration path.");
    println!("Value for config: {}", configuration_path);
    let configuration =
        Configuration::from_path(configuration_path).expect("Failed to load configuration");
    if let Some(matches) = matches.subcommand_matches(DOMAIN) {
        domain::process(matches, &configuration);
    }
    if let Some(matches) = matches.subcommand_matches(ACCOUNT) {
        account::process(matches, &configuration);
    }
    if let Some(matches) = matches.subcommand_matches(ASSET) {
        asset::process(matches, &configuration);
    }
    if let Some(matches) = matches.subcommand_matches(EVENTS) {
        events::process(matches, &configuration);
    }
}

pub fn submit(instruction: Instruction, configuration: &Configuration) {
    let mut iroha_client = Client::new(configuration);
    let transaction = iroha_client
        .build_transaction(vec![instruction])
        .expect("Failed to build transaction.");
    if let Ok(Some(original_transaction)) = iroha_client.get_original_transaction(
        &transaction,
        RETRY_COUNT_MST,
        Duration::from_millis(RETRY_IN_MST_MS),
    ) {
        if Confirm::new()
            .with_prompt("There is a similar transaction from your account waiting for more signatures. Do you want to sign it instead of submitting a new transaction?")
            .interact()
            .expect("Failed to show interactive prompt.") 
        {
            let _ = iroha_client
                .submit_transaction(iroha_client.sign_transaction(original_transaction).expect("Failed to sign transaction."))
                .expect("Failed to submit transaction.")
                ;
        } else {
            let _ =iroha_client
            .submit_transaction(transaction)
            .expect("Failed to submit transaction.");
        }
    } else {
        let _ = iroha_client
            .submit_transaction(transaction)
            .expect("Failed to submit transaction.");
    }
}

mod events {
    use super::*;
    use clap::ArgMatches;
    use iroha_client::{client::Client, config::Configuration};

    const PIPELINE: &str = "pipeline";
    const DATA: &str = "data";

    pub fn build_app<'a, 'b>() -> App<'a, 'b> {
        App::new(EVENTS)
            .about("Use this command to listen to Iroha events over the streaming API.")
            .subcommand(App::new(PIPELINE).about("Listen to pipeline events."))
            .subcommand(App::new(DATA).about("Listen to data events."))
    }

    pub fn process(matches: &ArgMatches<'_>, configuration: &Configuration) {
        // TODO: let the user to setup the filter arguments.
        if matches.subcommand_matches(PIPELINE).is_some() {
            listen(
                EventFilter::Pipeline(PipelineEventFilter::identity()),
                configuration,
            )
        }
        if matches.subcommand_matches(DATA).is_some() {
            listen(EventFilter::Data(DataEventFilter), configuration)
        }
    }

    pub fn listen(filter: EventFilter, configuration: &Configuration) {
        let mut iroha_client = Client::new(configuration);
        println!("Listening to events with filter: {:?}", filter);
        for event in iroha_client
            .listen_for_events(filter)
            .expect("Failed to listen to events.")
        {
            match event {
                Ok(event) => println!("{:#?}", event),
                Err(err) => println!("{:#?}", err),
            };
        }
    }
}

mod domain {
    use super::*;
    use clap::ArgMatches;
    use iroha_client::config::Configuration;

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
        if let Some(matches) = matches.subcommand_matches(ADD) {
            if let Some(domain_name) = matches.value_of(DOMAIN_NAME) {
                println!("Adding a new Domain with a name: {}", domain_name);
                create_domain(domain_name, configuration);
            }
        }
    }

    fn create_domain(domain_name: &str, configuration: &Configuration) {
        let create_domain = RegisterBox::new(IdentifiableBox::from(Domain::new(domain_name)));
        submit(create_domain.into(), configuration);
    }
}

mod account {
    use super::*;
    use clap::ArgMatches;
    use iroha_client::config::Configuration;
    use std::{fmt::Debug, fs::File, io::BufReader, path::Path};

    const REGISTER: &str = "register";
    const SET: &str = "set";
    const ACCOUNT_NAME: &str = "name";
    const ACCOUNT_DOMAIN_NAME: &str = "domain";
    const ACCOUNT_KEY: &str = "key";
    const ACCOUNT_SIGNATURE_CONDITION: &str = "signature_condition";
    const ACCOUNT_SIGNATURE_CONDITION_FILE: &str = "file";

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
            .subcommand(
                App::new(SET)
                    .about("Use this command to set Account Parameters in Iroha Peer.")
                    .subcommand(
                        App::new(ACCOUNT_SIGNATURE_CONDITION)
                            .about("Use this command to set Signature Condition for Account in Iroha Peer.")
                            .arg(
                                Arg::with_name(ACCOUNT_SIGNATURE_CONDITION_FILE)
                                    .long(ACCOUNT_SIGNATURE_CONDITION_FILE)
                                    .value_name("FILE")
                                    .help("A JSON file with Iroha Expression that represents signature condition.")
                                    .takes_value(true)
                                    .required(true),
                            )
                    ),
            )
    }

    pub fn process(matches: &ArgMatches<'_>, configuration: &Configuration) {
        process_create_account(matches, configuration);
        process_set_account_signature_condition(matches, configuration);
    }

    fn process_create_account(matches: &ArgMatches<'_>, configuration: &Configuration) {
        if let Some(matches) = matches.subcommand_matches(REGISTER) {
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

    fn process_set_account_signature_condition(
        matches: &ArgMatches<'_>,
        configuration: &Configuration,
    ) {
        if let Some(matches) = matches.subcommand_matches(SET) {
            if let Some(matches) = matches.subcommand_matches(ACCOUNT_SIGNATURE_CONDITION) {
                if let Some(file) = matches.value_of(ACCOUNT_SIGNATURE_CONDITION_FILE) {
                    println!("Setting account signature condition from file: {}", file);
                    set_account_signature_condition(file, configuration);
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
        let create_account = RegisterBox::new(IdentifiableBox::from(Account::with_signatory(
            AccountId::new(account_name, domain_name),
            key_pair.public_key,
        )));
        submit(create_account.into(), configuration);
    }

    fn signature_condition_from_file(
        path: impl AsRef<Path> + Debug,
    ) -> Result<SignatureCheckCondition> {
        let file = File::open(path).wrap_err("Failed to open a file")?;
        let reader = BufReader::new(file);
        let condition: Box<Expression> =
            serde_json::from_reader(reader).wrap_err("Failed to deserialize json from reader")?;
        Ok(SignatureCheckCondition(condition.into()))
    }

    fn set_account_signature_condition(file: &str, configuration: &Configuration) {
        let account = Account::new(configuration.account_id.clone());
        let condition = signature_condition_from_file(file)
            .expect("Failed to get signature condition from file");
        submit(MintBox::new(account, condition).into(), configuration);
    }
}

mod asset {
    use super::*;
    use clap::ArgMatches;
    use iroha_client::{
        client::{asset, Client},
        config::Configuration,
    };

    const REGISTER: &str = "register";
    const MINT: &str = "mint";
    const TRANSFER: &str = "transfer";
    const GET: &str = "get";
    const ASSET_NAME: &str = "name";
    const ASSET_DOMAIN_NAME: &str = "domain";
    const ASSET_ACCOUNT_ID: &str = "account_id";
    const DESTINATION_ACCOUNT_ID: &str = "dst_account_id";
    const SOURCE_ACCOUNT_ID: &str = "src_account_id";
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
            App::new(TRANSFER)
                .about("Use this command to Transfer Asset from Account to Account.")
                .arg(Arg::with_name(SOURCE_ACCOUNT_ID).long(SOURCE_ACCOUNT_ID).value_name(SOURCE_ACCOUNT_ID).help("Source Account's id as double-quoted string in the following format `account_name@domain_name`.").takes_value(true).required(true))
                .arg(Arg::with_name(DESTINATION_ACCOUNT_ID).long(DESTINATION_ACCOUNT_ID).value_name(DESTINATION_ACCOUNT_ID).help("Destination Account's id as double-quoted string in the following format `account_name@domain_name`.").takes_value(true).required(true))
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
        if let Some(matches) = matches.subcommand_matches(REGISTER) {
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
        if let Some(matches) = matches.subcommand_matches(MINT) {
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
        if let Some(matches) = matches.subcommand_matches(TRANSFER) {
            if let Some(asset_id) = matches.value_of(ASSET_ID) {
                println!("Transfer asset with an identification: {}", asset_id);
                if let Some(account1_id) = matches.value_of(SOURCE_ACCOUNT_ID) {
                    println!(
                        "Transfer asset from account with an identification: {}",
                        account1_id
                    );
                    if let Some(account2_id) = matches.value_of(DESTINATION_ACCOUNT_ID) {
                        println!(
                            "Transfer asset to account with an identification: {}",
                            account2_id
                        );
                        if let Some(quantity) = matches.value_of(QUANTITY) {
                            println!("Transfer asset's amount: {}", quantity);
                            transfer_asset(
                                account1_id,
                                account2_id,
                                asset_id,
                                quantity,
                                configuration,
                            );
                        }
                    }
                }
            }
        }
        if let Some(matches) = matches.subcommand_matches(GET) {
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
        submit(
            RegisterBox::new(IdentifiableBox::AssetDefinition(
                AssetDefinition::new(AssetDefinitionId::new(asset_name, domain_name)).into(),
            ))
            .into(),
            configuration,
        );
    }

    fn mint_asset(
        asset_definition_id: &str,
        account_id: &str,
        quantity: &str,
        configuration: &Configuration,
    ) {
        let quantity: u32 = quantity.parse().expect("Failed to parse Asset quantity.");
        let mint_asset = MintBox::new(
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(
                AssetDefinitionId::from_str(asset_definition_id)
                    .expect("Failed to parse Asset Definition Id."),
                AccountId::from_str(account_id).expect("Failed to parse Account Id."),
            )),
        );
        submit(mint_asset.into(), configuration);
    }

    fn transfer_asset(
        account1_id: &str,
        account2_id: &str,
        asset_definition_id: &str,
        quantity: &str,
        configuration: &Configuration,
    ) {
        let quantity: u32 = quantity.parse().expect("Failed to parse Asset quantity.");
        let transfer_asset = TransferBox::new(
            IdBox::AssetId(AssetId::new(
                AssetDefinitionId::from_str(asset_definition_id)
                    .expect("Failed to parse Source Definition Id"),
                AccountId::from_str(account1_id).expect("Failed to parse Source Account Id."),
            )),
            Value::U32(quantity),
            IdBox::AssetId(AssetId::new(
                AssetDefinitionId::from_str(asset_definition_id)
                    .expect("Failed to parse Destination Definition Id"),
                AccountId::from_str(account2_id).expect("Failed to parse Destination Account Id."),
            )),
        );
        submit(transfer_asset.into(), configuration);
    }

    fn get_asset(asset_id: &str, account_id: &str, configuration: &Configuration) {
        let mut iroha_client = Client::new(configuration);
        let query_result = iroha_client
            .request(&asset::by_account_id_and_definition_id(
                AccountId::from_str(account_id).expect("Failed to parse Account Id."),
                AssetDefinitionId::from_str(asset_id)
                    .expect("Failed to parse Asset Definition Id."),
            ))
            .expect("Failed to get asset.");
        let QueryResult(value) = query_result;
        println!("Get Asset result: {:?}", value);
    }
}
