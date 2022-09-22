//! This file contains examples from the Rust tutorial.
//! <https://hyperledger.github.io/iroha-2-docs/guide/rust.html#_2-configuring-iroha-2>
#![allow(clippy::restriction, clippy::needless_borrow)]

use std::fs::File;

use eyre::{Error, WrapErr};
// BEGIN FRAGMENT: rust_config_example
use iroha_config::client::Configuration;

fn main() {
    let config_loc = "../configs/client_cli/config.json";
    let file = File::open(config_loc)
        .wrap_err("Unable to load the configuration file at `.....`")
        .expect("Config file is loading normally.");
    let config: Configuration = serde_json::from_reader(file)
        .wrap_err("Failed to parse `../configs/client_cli/config.json`")
        .expect("Verified in tests");
    // Your code goes here…

    // BEGIN ESCAPE
    json_config_client_test(&config)
        .expect("JSON config client example is expected to work correctly");
    domain_registration_test(&config)
        .expect("Domain registration example is expected to work correctly");
    account_definition_test().expect("Account definition example is expected to work correctly");
    account_registration_test(&config)
        .expect("Account registration example is expected to work correctly");
    asset_registration_test(&config)
        .expect("Asset registration example is expected to work correctly");
    println!("Success!");
    // END ESCAPE
}
// END FRAGMENT

fn json_config_client_test(config: &Configuration) -> Result<(), Error> {
    // BEGIN FRAGMENT: rust_client_create
    use iroha_client::client::Client;

    // Initialise a client with a provided config
    let _current_client: Client = Client::new(&config)?;
    // END FRAGMENT
    Ok(())
}

fn domain_registration_test(config: &Configuration) -> Result<(), Error> {
    // BEGIN FRAGMENT: domain_register_example
    use iroha_client::client::Client;
    use iroha_data_model::{
        metadata::UnlimitedMetadata,
        prelude::{Domain, DomainId, Instruction, RegisterBox},
    };

    // Create a domain Id
    let looking_glass: DomainId = "looking_glass".parse()?;

    // Create an ISI
    let create_looking_glass = RegisterBox::new(Domain::new(looking_glass));

    // Create an Iroha client
    let iroha_client: Client = Client::new(&config).unwrap();

    // Prepare a transaction
    let metadata = UnlimitedMetadata::default();
    let instructions: Vec<Instruction> = vec![create_looking_glass.into()];
    let tx = iroha_client
        .build_transaction(instructions.into(), metadata)
        .wrap_err("Error building a domain registration transaction")?;

    // Submit a prepared domain registration transaction
    iroha_client
        .submit_transaction(tx)
        .wrap_err("Failed to submit transaction")?;
    // END FRAGMENT

    // Finish the test successfully
    Ok(())
}

fn account_definition_test() -> Result<(), Error> {
    // BEGIN FRAGMENT: account_definition_comparison
    use iroha_data_model::{account::Id as AccountIdStruct, prelude::AccountId};

    // Create an `iroha_data_model::account::Id` instance
    // with a DomainId instance and a Domain ID for an account
    let longhand_account_id = AccountIdStruct {
        name: "white_rabbit".parse()?,
        domain_id: "looking_glass".parse()?,
    };
    let account_id: AccountId = "white_rabbit@looking_glass"
        .parse::<AccountIdStruct>()
        .expect("Valid, because the string contains no whitespace, has a single '@' character and is not empty after");

    // Check that two ways to define an account match
    assert_eq!(account_id, longhand_account_id);
    // END FRAGMENT

    // Finish the test successfully
    Ok(())
}

fn account_registration_test(config: &Configuration) -> Result<(), Error> {
    // BEGIN FRAGMENT: register_account
    use iroha_client::client::Client;
    use iroha_core::prelude::KeyPair;
    use iroha_data_model::{
        account::Id as AccountIdStruct,
        metadata::UnlimitedMetadata,
        prelude::{Account, AccountId, Instruction, RegisterBox},
    };

    // Create an Iroha client
    let iroha_client: Client = Client::new(&config).unwrap();

    // Create an AccountId instance by providing
    // the account and domain name
    let account_id: AccountId = "white_rabbit@looking_glass"
        .parse::<AccountIdStruct>()
        .expect("Valid, because the string contains no whitespace, has a single '@' character and is not empty after");

    // TODO: consider getting a key from white_rabbit
    // Generate a new public key for a new account
    let (public_key, _) = KeyPair::generate()
        .expect("Failed to generate KeyPair")
        .into();

    // Generate a new account
    let create_account = RegisterBox::new(Account::new(account_id, [public_key]));

    // Prepare a transaction using the
    // Account's RegisterBox
    let metadata = UnlimitedMetadata::new();
    let instructions: Vec<Instruction> = vec![create_account.into()];
    let tx = iroha_client.build_transaction(instructions.into(), metadata)?;

    // Submit a prepared account registration transaction
    iroha_client.submit_transaction(tx)?;

    // END FRAGMENT
    // Finish the test successfully
    Ok(())
}

fn asset_registration_test(config: &Configuration) -> Result<(), Error> {
    // BEGIN FRAGMENT: register_asset
    use std::str::FromStr as _;

    use iroha_client::client::Client;
    use iroha_data_model::{
        account::Id as AccountIdStruct,
        prelude::{
            AccountId, AssetDefinition, AssetDefinitionId, AssetId, IdBox, MintBox, RegisterBox,
            Value,
        },
    };

    // Create an Iroha client
    let iroha_client: Client = Client::new(&config).unwrap();

    // Create an asset
    let asset_def_id = AssetDefinitionId::from_str("time#looking_glass")
        .expect("Valid, because the string contains no whitespace, has a single '#' character and is not empty after");

    // Initialise the registration time
    let register_time =
        RegisterBox::new(AssetDefinition::fixed(asset_def_id.clone()).mintable_once());

    // Submit a registration time
    iroha_client.submit(register_time)?;

    // Create an account using the previously defined asset
    let account_id: AccountId = "white_rabbit@looking_glass"
        .parse::<AccountIdStruct>()
        .expect("Valid, because the string contains no whitespace, has a single '@' character and is not empty after");

    // Create a MintBox using a previous asset and account
    let mint = MintBox::new(
        Value::Fixed(12.34_f64.try_into()?),
        IdBox::AssetId(AssetId::new(asset_def_id, account_id)),
    );
    // Submit a minting transaction
    iroha_client.submit_all([mint.into()])?;
    // END FRAGMENT

    // Finish the test successfully
    Ok(())
}
