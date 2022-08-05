//! This file contains examples from the Rust tutorial.
//! https://hyperledger.github.io/iroha-2-docs/guide/rust.html#_2-configuring-iroha-2

use eyre::{Error, WrapErr};

fn json_config_client_test(config_str: &str) -> Result<(), Error> {
    use iroha_config::client::Configuration;
    use iroha_client::client::Client;
    // Parse a config string
    let config: Configuration = serde_json::from_str(config_str)
        .expect("Failed to deserialize json from reader");
    // Alternatively, to parse a config file, use:
    // let config = Configuration::from_path("../configs/peer/config.json").unwrap();
    // Initialise a client with a provided config
    let _current_client : Client = Client::new(&config).unwrap();
    // Finish the test successfully
    Ok(())
}

fn domain_registration_test(config_str: &str) -> Result<(), Error> {
    use iroha_config::client::Configuration;
    use iroha_client::client::Client;
    use iroha_data_model::prelude::{Domain, DomainId, RegisterBox, Instruction};
    use iroha_data_model::metadata::UnlimitedMetadata;
    // Create a domain Id
    let looking_glass: DomainId = "looking_glass".parse()?;
    // Create an ISI
    let create_looking_glass = RegisterBox::new(
        Domain::new(looking_glass.clone())
    );
    // Parse a config string
    let config: Configuration = serde_json::from_str(config_str)
        .expect("Failed to deserialize json from reader");
    // Create an Iroha client
    let iroha_client : Client = Client::new(&config).unwrap();
    // Prepare a transaction
    let metadata = UnlimitedMetadata::default();
    let instructions: Vec<Instruction> = vec![create_looking_glass.into()];
    let _tx = iroha_client
        .build_transaction(instructions.into(), metadata)
        .wrap_err("Error building a domain registration transaction")?;
    // Submit a prepared domain registration transaction
    // iroha_client.submit_transaction(_tx)?;
    // Finish the test successfully
    Ok(())
}

fn account_definition_test() -> Result<(), Error> {
    use iroha_data_model::prelude::{AccountId};
    use iroha_data_model::account::Id as AccountIdStruct;
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
    // Finish the test successfully
    Ok(())
}

fn account_registration_test(config_str: &str) -> Result<(), Error> {
    use iroha_client::client::Client;
    use iroha_config::client::Configuration;
    use iroha_data_model::account::Id as AccountIdStruct;
    use iroha_data_model::metadata::UnlimitedMetadata;
    use iroha_data_model::IdentifiableBox;
    use iroha_data_model::prelude::{Account, AccountId, RegisterBox, Instruction};
    use iroha_core::prelude::KeyPair;
    // Parse a config string
    let config: Configuration = serde_json::from_str(config_str)
        .expect("Failed to deserialize JSON from reader");
    // Create an Iroha client
    let iroha_client : Client = Client::new(&config).unwrap();
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
    let create_account = RegisterBox::new(
        IdentifiableBox::NewAccount(Box::new(
            Account::new(account_id, [public_key])
        ))
    );
    // Prepare a transaction using the
    // Account's RegisterBox
    let metadata = UnlimitedMetadata::new();
    let instructions: Vec<Instruction> = vec![create_account.into()];
    let _tx = iroha_client.build_transaction(
        instructions.into(), metadata
    )?;
    // Submit a prepared account registration transaction
    // iroha_client.submit_transaction(_tx)?;
    // Finish the test successfully
    Ok(())
}

fn asset_registration_test(config_str: &str) -> Result<(), Error> {
    use iroha_config::client::Configuration;
    use iroha_client::client::Client;
    use iroha_data_model::prelude::{
        Value, IdBox, AccountId,
        AssetId, AssetDefinition, AssetDefinitionId,
        MintBox
    };
    use iroha_data_model::prelude::{RegisterBox};
    use iroha_data_model::account::Id as AccountIdStruct;
    use std::str::FromStr;
    // Parse a config string
    let config: Configuration = serde_json::from_str(config_str)
        .expect("Failed to deserialize json from reader");
    // Create an Iroha client
    let _iroha_client : Client = Client::new(&config).unwrap();
    // Create an asset
    let asset_def_id = AssetDefinitionId::from_str("time#looking_glass")
        .expect("Valid, because the string contains no whitespace, has a single '#' character and is not empty after");
    // Initialise the registration time
    let _register_time = RegisterBox::new(
        AssetDefinition::fixed(asset_def_id.clone()
    ).mintable_once());
    // Submit a registration time
    // _iroha_client.submit(_register_time)?;
    // Create an account using the previously defined asset
    let account_id: AccountId = "white_rabbit@looking_glass"
        .parse::<AccountIdStruct>()
        .expect("Valid, because the string contains no whitespace, has a single '@' character and is not empty after");
    // Create a MintBox using a previous asset and account
    let _mint = MintBox::new(
        Value::Fixed(12.34_f64.try_into()?),
        IdBox::AssetId(AssetId::new(
            asset_def_id.clone(),
            account_id.clone()
        ))
    );
    // Submit a minting transaction
    // _iroha_client.submit(_mint)?;
    // Finish the test successfully
    Ok(())
}

fn main() -> Result<(), Error> {
    // An example config
    let example_config = "{
        \"TORII\": {
            \"P2P_ADDR\": \"127.0.0.1:1337\",
            \"API_URL\": \"127.0.0.1:8080\"
        },
        \"SUMERAGI\": {
            \"TRUSTED_PEERS\": [
                {
                  \"address\": \"127.0.0.1:1337\",
                  \"public_key\": \"ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b\"
                },
                {
                  \"address\": \"127.0.0.1:1338\",
                  \"public_key\": \"ed0120cc25624d62896d3a0bfd8940f928dc2abf27cc57cefeb442aa96d9081aae58a1\"
                },
                {
                  \"address\": \"127.0.0.1:1339\",
                  \"public_key\": \"ed0120faca9e8aa83225cb4d16d67f27dd4f93fc30ffa11adc1f5c88fd5495ecc91020\"
                },
                {
                  \"address\": \"127.0.0.1:1340\",
                  \"public_key\": \"ed01208e351a70b6a603ed285d666b8d689b680865913ba03ce29fb7d13a166c4e7f1f\"
                }
            ]
        },
        \"KURA\": {
            \"INIT_MODE\": \"strict\",
            \"BLOCK_STORE_PATH\": \"./blocks\"
        },
        \"BLOCK_SYNC\": {
            \"GOSSIP_PERIOD_MS\": 10000,
            \"BATCH_SIZE\": 4
        },
        \"PUBLIC_KEY\": \"ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b\",
        \"PRIVATE_KEY\": {
            \"digest_function\": \"ed25519\",
            \"payload\": \"282ed9f3cf92811c3818dbc4ae594ed59dc1a2f78e4241e31924e101d6b1fb831c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b\"
        },
        \"GENESIS\": {
            \"ACCOUNT_PUBLIC_KEY\": \"ed01204cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf\",
            \"ACCOUNT_PRIVATE_KEY\": {
                \"digest_function\": \"ed25519\",
                \"payload\": \"d748e18ce60cb30dea3e73c9019b7af45a8d465e3d71bcc9a5ef99a008205e534cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf\"
            }
        }
    }".to_string();
    json_config_client_test(example_config.as_ref())
        .expect("JSON config client example is expected to work correctly");
    domain_registration_test(example_config.as_ref())
        .expect("Domain registration example is expected to work correctly");
    account_definition_test()
        .expect("Account definition example is expected to work correctly");
    account_registration_test(example_config.as_ref())
        .expect("Account registration example is expected to work correctly");
    asset_registration_test(example_config.as_ref())
        .expect("Asset registration example is expected to work correctly");
    Ok(())
}