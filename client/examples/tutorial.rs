//! This file contains examples from the Rust tutorial.
//! <https://hyperledger.github.io/iroha-2-docs/guide/rust.html#_2-configuring-iroha-2>

use eyre::{Error, WrapErr};
use iroha_client::config::Config;
use iroha_primitives::numeric::Numeric;
// #region rust_config_crates
// #endregion rust_config_crates

fn main() {
    // #region rust_config_load
    let config = Config::load("../configs/swarm/client.toml").unwrap();
    // #endregion rust_config_load

    // Your code goes here…

    domain_registration_test(config.clone())
        .expect("Domain registration example is expected to work correctly");
    account_definition_test().expect("Account definition example is expected to work correctly");
    account_registration_test(config.clone())
        .expect("Account registration example is expected to work correctly");
    asset_registration_test(config.clone())
        .expect("Asset registration example is expected to work correctly");
    asset_minting_test(config.clone())
        .expect("Asset minting example is expected to work correctly");
    asset_burning_test(config.clone())
        .expect("Asset burning example is expected to work correctly");
    // output_visualising_test(&config).expect(msg: "Visualising outputs example is expected to work correctly");
    println!("Success!");
}

fn domain_registration_test(config: Config) -> Result<(), Error> {
    // #region domain_register_example_crates
    use iroha_client::{
        client::Client,
        data_model::{
            metadata::UnlimitedMetadata,
            prelude::{Domain, DomainId, InstructionBox, Register},
        },
    };
    // #endregion domain_register_example_crates

    // #region domain_register_example_create_domain
    // Create a domain Id
    let looking_glass: DomainId = "looking_glass".parse()?;
    // #endregion domain_register_example_create_domain

    // #region domain_register_example_create_isi
    // Create an ISI
    let create_looking_glass = Register::domain(Domain::new(looking_glass));
    // #endregion domain_register_example_create_isi

    // #region rust_client_create
    // Create an Iroha client
    let iroha_client = Client::new(config);
    // #endregion rust_client_create

    // #region domain_register_example_prepare_tx
    // Prepare a transaction
    let metadata = UnlimitedMetadata::default();
    let instructions: Vec<InstructionBox> = vec![create_looking_glass.into()];
    let tx = iroha_client.build_transaction(instructions, metadata);
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
    use iroha_client::{crypto::KeyPair, data_model::prelude::AccountId};

    // Generate a new public key for a new account
    let (public_key, _) = KeyPair::random().into_parts();
    // Create an AccountId instance by providing a DomainId instance and the public key
    let longhand_account_id = AccountId::new("looking_glass".parse()?, public_key.clone());
    // Create an AccountId instance by parsing the serialized format "signatory@domain"
    let account_id: AccountId = format!("{public_key}@looking_glass")
        .parse()
        .expect("Valid, because before @ is a valid public key and after @ is a valid name i.e. a string with no spaces or forbidden chars");

    // Check that two ways to define an account match
    assert_eq!(account_id, longhand_account_id);

    // #endregion account_definition_comparison

    // Finish the test successfully
    Ok(())
}

fn account_registration_test(config: Config) -> Result<(), Error> {
    // #region register_account_crates
    use iroha_client::{
        client::Client,
        crypto::KeyPair,
        data_model::{
            metadata::UnlimitedMetadata,
            prelude::{Account, AccountId, InstructionBox, Register},
        },
    };
    // #endregion register_account_crates

    // Create an Iroha client
    let iroha_client = Client::new(config);

    // #region register_account_create
    // Generate a new public key for a new account
    let (public_key, _) = KeyPair::random().into_parts();
    // Create an AccountId instance by parsing the serialized format "signatory@domain"
    let account_id: AccountId = format!("{public_key}@looking_glass")
        .parse()
        .expect("Valid, because before @ is a valid public key and after @ is a valid name i.e. a string with no spaces or forbidden chars");
    // #endregion register_account_create

    // #region register_account_generate
    // Generate a new account
    let create_account = Register::account(Account::new(account_id));
    // #endregion register_account_generate

    // #region register_account_prepare_tx
    // Prepare a transaction using the
    // Account's RegisterBox
    let metadata = UnlimitedMetadata::new();
    let instructions: Vec<InstructionBox> = vec![create_account.into()];
    let tx = iroha_client.build_transaction(instructions, metadata);
    // #endregion register_account_prepare_tx

    // #region register_account_submit_tx
    // Submit a prepared account registration transaction
    iroha_client.submit_transaction(&tx)?;
    // #endregion register_account_submit_tx

    // Finish the test successfully
    Ok(())
}

fn asset_registration_test(config: Config) -> Result<(), Error> {
    // #region register_asset_crates
    use std::str::FromStr as _;

    use iroha_client::{
        client::Client,
        crypto::KeyPair,
        data_model::prelude::{
            numeric, AccountId, AssetDefinition, AssetDefinitionId, AssetId, Mint, Register,
        },
    };
    // #endregion register_asset_crates

    // Create an Iroha client
    let iroha_client = Client::new(config);

    // #region register_asset_create_asset
    // Create an asset
    let asset_def_id = AssetDefinitionId::from_str("time#looking_glass")
        .expect("Valid, because the string contains no whitespace, has a single '#' character and is not empty after");
    // #endregion register_asset_create_asset

    // #region register_asset_init_submit
    // Initialise the registration time
    let register_time =
        Register::asset_definition(AssetDefinition::numeric(asset_def_id.clone()).mintable_once());

    // Submit a registration time
    iroha_client.submit(register_time)?;
    // #endregion register_asset_init_submit

    // Generate a new public key for a new account
    let (public_key, _) = KeyPair::random().into_parts();
    // Create an AccountId instance by parsing the serialized format "signatory@domain"
    let account_id: AccountId = format!("{public_key}@looking_glass")
        .parse()
        .expect("Valid, because before @ is a valid public key and after @ is a valid name i.e. a string with no spaces or forbidden chars");

    // #region register_asset_mint_submit
    // Create a MintBox using a previous asset and account
    let mint = Mint::asset_numeric(numeric!(12.34), AssetId::new(asset_def_id, account_id));

    // Submit a minting transaction
    iroha_client.submit_all([mint])?;
    // #endregion register_asset_mint_submit

    // Finish the test successfully
    Ok(())
}

fn asset_minting_test(config: Config) -> Result<(), Error> {
    // #region mint_asset_crates
    use std::str::FromStr;

    use iroha_client::{
        client::Client,
        data_model::prelude::{AccountId, AssetDefinitionId, AssetId, Mint},
    };
    // #endregion mint_asset_crates

    // Create an Iroha client
    let iroha_client = Client::new(config);

    // Define the instances of an Asset and Account
    // #region mint_asset_define_asset_account
    let roses = AssetDefinitionId::from_str("rose#wonderland")
        .expect("Valid, because the string contains no whitespace, has a single '#' character and is not empty after");
    let alice: AccountId = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland".parse()
        .expect("Valid, because before @ is a valid public key and after @ is a valid name i.e. a string with no spaces or forbidden chars");
    // #endregion mint_asset_define_asset_account

    // Mint the Asset instance
    // #region mint_asset_mint
    let mint_roses = Mint::asset_numeric(42u32, AssetId::new(roses, alice));
    // #endregion mint_asset_mint

    // #region mint_asset_submit_tx
    iroha_client
        .submit(mint_roses)
        .wrap_err("Failed to submit transaction")?;
    // #endregion mint_asset_submit_tx

    // #region mint_asset_mint_alt
    // Mint the Asset instance (alternate syntax).
    // The syntax is `asset_name#asset_domain#account_signatory@account_domain`,
    // or `roses.to_string() + "#" + alice.to_string()`.
    // The `##` is a short-hand for the rose `which belongs to the same domain as the account
    // to which it belongs to.
    let alice_roses: AssetId =
        "rose##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland"
            .parse()?;
    let mint_roses_alt = Mint::asset_numeric(10u32, alice_roses);
    // #endregion mint_asset_mint_alt

    // #region mint_asset_submit_tx_alt
    iroha_client
        .submit(mint_roses_alt)
        .wrap_err("Failed to submit transaction")?;
    // #endregion mint_asset_submit_tx_alt

    // Finish the test successfully
    Ok(())
}

fn asset_burning_test(config: Config) -> Result<(), Error> {
    // #region burn_asset_crates
    use std::str::FromStr;

    use iroha_client::{
        client::Client,
        data_model::prelude::{AccountId, AssetDefinitionId, AssetId, Burn},
    };
    // #endregion burn_asset_crates

    // Create an Iroha client
    let iroha_client = Client::new(config);

    // #region burn_asset_define_asset_account
    // Define the instances of an Asset and Account
    let roses = AssetDefinitionId::from_str("rose#wonderland")
        .expect("Valid, because the string contains no whitespace, has a single '#' character and is not empty after");
    let alice: AccountId = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland".parse()
        .expect("Valid, because before @ is a valid public key and after @ is a valid name i.e. a string with no spaces or forbidden chars");
    // #endregion burn_asset_define_asset_account

    // #region burn_asset_burn
    // Burn the Asset instance
    let burn_roses = Burn::asset_numeric(10u32, AssetId::new(roses, alice));
    // #endregion burn_asset_burn

    // #region burn_asset_submit_tx
    iroha_client
        .submit(burn_roses)
        .wrap_err("Failed to submit transaction")?;
    // #endregion burn_asset_submit_tx

    // #region burn_asset_burn_alt
    // Burn the Asset instance (alternate syntax).
    // The syntax is `asset_name#asset_domain#account_signatory@account_domain`,
    // or `roses.to_string() + "#" + alice.to_string()`.
    // The `##` is a short-hand for the rose `which belongs to the same domain as the account
    // to which it belongs to.
    let alice_roses: AssetId =
        "rose##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland"
            .parse()?;
    let burn_roses_alt = Burn::asset_numeric(10u32, alice_roses);
    // #endregion burn_asset_burn_alt

    // #region burn_asset_submit_tx_alt
    iroha_client
        .submit(burn_roses_alt)
        .wrap_err("Failed to submit transaction")?;
    // #endregion burn_asset_submit_tx_alt

    // Finish the test successfully
    Ok(())
}
