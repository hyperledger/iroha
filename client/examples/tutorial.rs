//! This file contains examples from the Rust tutorial.
//! <https://hyperledger.github.io/iroha-2-docs/guide/rust.html#_2-configuring-iroha-2>
use std::fs::File;

use eyre::{Error, WrapErr};
use iroha_client::{config::Configuration, data_model::TryToValue};
// #region rust_config_crates
// #endregion rust_config_crates

fn main() {
    // #region rust_config_load
    let config_loc = "../configs/client/config.json";
    let file = File::open(config_loc)
        .wrap_err("Unable to load the configuration file at `.....`")
        .expect("Config file is loading normally.");
    let config: Configuration = serde_json::from_reader(file)
        .wrap_err("Failed to parse `../configs/client/config.json`")
        .expect("Verified in tests");
    // #endregion rust_config_load

    // Your code goes here…

    json_config_client_test(&config)
        .expect("JSON config client example is expected to work correctly");
    domain_registration_test(&config)
        .expect("Domain registration example is expected to work correctly");
    account_definition_test().expect("Account definition example is expected to work correctly");
    account_registration_test(&config)
        .expect("Account registration example is expected to work correctly");
    asset_registration_test(&config)
        .expect("Asset registration example is expected to work correctly");
    asset_minting_test(&config).expect("Asset minting example is expected to work correctly");
    asset_burning_test(&config).expect("Asset burning example is expected to work correctly");
    // output_visualising_test(&config).expect(msg: "Visualising outputs example is expected to work correctly");
    println!("Success!");
}

fn json_config_client_test(config: &Configuration) -> Result<(), Error> {
    use iroha_client::client::Client;

    // Initialise a client with a provided config
    let _current_client: Client = Client::new(config)?;

    Ok(())
}

fn domain_registration_test(config: &Configuration) -> Result<(), Error> {
    // #region domain_register_example_crates
    use iroha_client::{
        client::Client,
        data_model::{
            metadata::UnlimitedMetadata,
            prelude::{Domain, DomainId, InstructionExpr, RegisterExpr},
        },
    };
    // #endregion domain_register_example_crates

    // #region domain_register_example_create_domain
    // Create a domain Id
    let looking_glass: DomainId = "looking_glass".parse()?;
    // #endregion domain_register_example_create_domain

    // #region domain_register_example_create_isi
    // Create an ISI
    let create_looking_glass = RegisterExpr::new(Domain::new(looking_glass));
    // #endregion domain_register_example_create_isi

    // #region rust_client_create
    // Create an Iroha client
    let iroha_client: Client = Client::new(config)?;
    // #endregion rust_client_create

    // #region domain_register_example_prepare_tx
    // Prepare a transaction
    let metadata = UnlimitedMetadata::default();
    let instructions: Vec<InstructionExpr> = vec![create_looking_glass.into()];
    let tx = iroha_client
        .build_transaction(instructions, metadata)
        .wrap_err("Error building a domain registration transaction")?;
    // #endregion domain_register_example_prepare_tx

    // #region domain_register_example_submit_tx
    // Submit a prepared domain registration transaction
    iroha_client
        .submit_transaction(&tx)
        .wrap_err("Failed to submit transaction")?;
    // #endregion domain_register_example_submit_tx

    // Finish the test successfully
    Ok(())
}

fn account_definition_test() -> Result<(), Error> {
    // #region account_definition_comparison
    use iroha_client::data_model::prelude::AccountId;

    // Create an `iroha_client::data_model::AccountId` instance
    // with a DomainId instance and a Domain ID for an account
    let longhand_account_id = AccountId::new("white_rabbit".parse()?, "looking_glass".parse()?);
    let account_id: AccountId = "white_rabbit@looking_glass"
        .parse()
        .expect("Valid, because the string contains no whitespace, has a single '@' character and is not empty after");

    // Check that two ways to define an account match
    assert_eq!(account_id, longhand_account_id);

    // #endregion account_definition_comparison

    // Finish the test successfully
    Ok(())
}

fn account_registration_test(config: &Configuration) -> Result<(), Error> {
    // #region register_account_crates
    use iroha_client::{
        client::Client,
        crypto::KeyPair,
        data_model::{
            metadata::UnlimitedMetadata,
            prelude::{Account, AccountId, InstructionExpr, RegisterExpr},
        },
    };
    // #endregion register_account_crates

    // Create an Iroha client
    let iroha_client: Client = Client::new(config)?;

    // #region register_account_create
    // Create an AccountId instance by providing the account and domain name
    let account_id: AccountId = "white_rabbit@looking_glass"
        .parse()
        .expect("Valid, because the string contains no whitespace, has a single '@' character and is not empty after");
    // #endregion register_account_create

    // TODO: consider getting a key from white_rabbit
    // Generate a new public key for a new account
    let (public_key, _) = KeyPair::generate()
        .expect("Failed to generate KeyPair")
        .into();

    // #region register_account_generate
    // Generate a new account
    let create_account = RegisterExpr::new(Account::new(account_id, [public_key]));
    // #endregion register_account_generate

    // #region register_account_prepare_tx
    // Prepare a transaction using the
    // Account's RegisterExpr
    let metadata = UnlimitedMetadata::new();
    let instructions: Vec<InstructionExpr> = vec![create_account.into()];
    let tx = iroha_client.build_transaction(instructions, metadata)?;
    // #endregion register_account_prepare_tx

    // #region register_account_submit_tx
    // Submit a prepared account registration transaction
    iroha_client.submit_transaction(&tx)?;
    // #endregion register_account_submit_tx

    // Finish the test successfully
    Ok(())
}

fn asset_registration_test(config: &Configuration) -> Result<(), Error> {
    // #region register_asset_crates
    use std::str::FromStr as _;

    use iroha_client::{
        client::Client,
        data_model::prelude::{
            AccountId, AssetDefinition, AssetDefinitionId, AssetId, IdBox, MintExpr, RegisterExpr,
        },
    };
    // #endregion register_asset_crates

    // Create an Iroha client
    let iroha_client: Client = Client::new(config)?;

    // #region register_asset_create_asset
    // Create an asset
    let asset_def_id = AssetDefinitionId::from_str("time#looking_glass")
        .expect("Valid, because the string contains no whitespace, has a single '#' character and is not empty after");
    // #endregion register_asset_create_asset

    // #region register_asset_init_submit
    // Initialise the registration time
    let register_time =
        RegisterExpr::new(AssetDefinition::fixed(asset_def_id.clone()).mintable_once());

    // Submit a registration time
    iroha_client.submit(register_time)?;
    // #endregion register_asset_init_submit

    // Create an account using the previously defined asset
    let account_id: AccountId = "white_rabbit@looking_glass"
        .parse()
        .expect("Valid, because the string contains no whitespace, has a single '@' character and is not empty after");

    // #region register_asset_mint_submit
    // Create a MintExpr using a previous asset and account
    let mint = MintExpr::new(
        12.34_f64.try_to_value()?,
        IdBox::AssetId(AssetId::new(asset_def_id, account_id)),
    );

    // Submit a minting transaction
    iroha_client.submit_all([mint])?;
    // #endregion register_asset_mint_submit

    // Finish the test successfully
    Ok(())
}

fn asset_minting_test(config: &Configuration) -> Result<(), Error> {
    // #region mint_asset_crates
    use std::str::FromStr;

    use iroha_client::{
        client::Client,
        data_model::{
            prelude::{AccountId, AssetDefinitionId, AssetId, MintExpr, ToValue},
            IdBox,
        },
    };
    // #endregion mint_asset_crates

    // Create an Iroha client
    let iroha_client: Client = Client::new(config)?;

    // Define the instances of an Asset and Account
    // #region mint_asset_define_asset_account
    let roses = AssetDefinitionId::from_str("rose#wonderland")
        .expect("Valid, because the string contains no whitespace, has a single '#' character and is not empty after");
    let alice: AccountId = "alice@wonderland".parse()
        .expect("Valid, because the string contains no whitespace, has a single '@' character and is not empty after");
    // #endregion mint_asset_define_asset_account

    // Mint the Asset instance
    // #region mint_asset_mint
    let mint_roses = MintExpr::new(
        42_u32.to_value(),
        IdBox::AssetId(AssetId::new(roses, alice)),
    );
    // #endregion mint_asset_mint

    // #region mint_asset_submit_tx
    iroha_client
        .submit(mint_roses)
        .wrap_err("Failed to submit transaction")?;
    // #endregion mint_asset_submit_tx

    // #region mint_asset_mint_alt
    // Mint the Asset instance (alternate syntax).
    // The syntax is `asset_name#asset_domain#account_name@account_domain`,
    // or `roses.to_string() + "#" + alice.to_string()`.
    // The `##` is a short-hand for the rose `which belongs to the same domain as the account
    // to which it belongs to.
    let mint_roses_alt = MintExpr::new(
        10_u32.to_value(),
        IdBox::AssetId("rose##alice@wonderland".parse()?),
    );
    // #endregion mint_asset_mint_alt

    // #region mint_asset_submit_tx_alt
    iroha_client
        .submit(mint_roses_alt)
        .wrap_err("Failed to submit transaction")?;
    // #endregion mint_asset_submit_tx_alt

    // Finish the test successfully
    Ok(())
}

fn asset_burning_test(config: &Configuration) -> Result<(), Error> {
    // #region burn_asset_crates
    use std::str::FromStr;

    use iroha_client::{
        client::Client,
        data_model::{
            prelude::{AccountId, AssetDefinitionId, AssetId, BurnExpr, ToValue},
            IdBox,
        },
    };
    // #endregion burn_asset_crates

    // Create an Iroha client
    let iroha_client: Client = Client::new(config)?;

    // #region burn_asset_define_asset_account
    // Define the instances of an Asset and Account
    let roses = AssetDefinitionId::from_str("rose#wonderland")
        .expect("Valid, because the string contains no whitespace, has a single '#' character and is not empty after");
    let alice: AccountId = "alice@wonderland".parse()
        .expect("Valid, because the string contains no whitespace, has a single '@' character and is not empty after");
    // #endregion burn_asset_define_asset_account

    // #region burn_asset_burn
    // Burn the Asset instance
    let burn_roses = BurnExpr::new(
        10_u32.to_value(),
        IdBox::AssetId(AssetId::new(roses, alice)),
    );
    // #endregion burn_asset_burn

    // #region burn_asset_submit_tx
    iroha_client
        .submit(burn_roses)
        .wrap_err("Failed to submit transaction")?;
    // #endregion burn_asset_submit_tx

    // #region burn_asset_burn_alt
    // Burn the Asset instance (alternate syntax).
    // The syntax is `asset_name#asset_domain#account_name@account_domain`,
    // or `roses.to_string() + "#" + alice.to_string()`.
    // The `##` is a short-hand for the rose `which belongs to the same domain as the account
    // to which it belongs to.
    let burn_roses_alt = BurnExpr::new(
        10_u32.to_value(),
        IdBox::AssetId("rose##alice@wonderland".parse()?),
    );
    // #endregion burn_asset_burn_alt

    // #region burn_asset_submit_tx_alt
    iroha_client
        .submit(burn_roses_alt)
        .wrap_err("Failed to submit transaction")?;
    // #endregion burn_asset_submit_tx_alt

    // Finish the test successfully
    Ok(())
}
