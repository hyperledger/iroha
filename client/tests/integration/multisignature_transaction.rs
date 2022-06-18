#![allow(clippy::restriction)]

use std::{str::FromStr as _, thread, time::Duration};

use iroha_client::{
    client::{self, Client},
    config::Configuration as ClientConfiguration,
};
use iroha_core::prelude::*;
use iroha_data_model::{account::TRANSACTION_SIGNATORIES_VALUE, prelude::*};
use test_network::*;

use super::Configuration;

#[allow(clippy::too_many_lines)]
#[test]
fn multisignature_transactions_should_wait_for_all_signatures() {
    let (_rt, network, _) = <Network>::start_test_with_runtime(4, 1);
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Configuration::pipeline_time();

    let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
    let alice_key_pair = get_key_pair();
    let key_pair_2 = KeyPair::generate().expect("Failed to generate KeyPair.");
    let asset_definition_id = AssetDefinitionId::from_str("camomile#wonderland").expect("Valid");
    let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()));
    let set_signature_condition = MintBox::new(
        SignatureCheckCondition(
            ContainsAll::new(
                ContextValue::new(TRANSACTION_SIGNATORIES_VALUE),
                vec![
                    alice_key_pair.public_key().clone(),
                    key_pair_2.public_key().clone(),
                ],
            )
            .into(),
        ),
        IdBox::AccountId(alice_id.clone()),
    );

    let mut client_configuration = ClientConfiguration::test(
        &network.genesis.api_address,
        &network.genesis.telemetry_address,
    );
    let iroha_client = Client::new(&client_configuration).expect("Invalid client configuration");
    iroha_client
        .submit_all_blocking(vec![create_asset.into(), set_signature_condition.into()])
        .expect("Failed to prepare state.");

    //When
    let quantity: u32 = 200;
    let asset_id = AssetId::new(asset_definition_id, alice_id.clone());
    let mint_asset = MintBox::new(Value::U32(quantity), IdBox::AssetId(asset_id.clone()));

    let (public_key1, private_key1) = alice_key_pair.into();
    client_configuration.account_id = alice_id.clone();
    client_configuration.public_key = public_key1;
    client_configuration.private_key = private_key1;
    let iroha_client = Client::new(&client_configuration).expect("Invalid client configuration");
    let instructions: Vec<Instruction> = vec![mint_asset.clone().into()];
    let transaction = iroha_client
        .build_transaction(instructions.into(), UnlimitedMetadata::new())
        .expect("Failed to create transaction.");
    iroha_client
        .submit_transaction(
            iroha_client
                .sign_transaction(transaction)
                .expect("Failed to sign transaction."),
        )
        .expect("Failed to submit transaction.");
    thread::sleep(pipeline_time);

    //Then
    client_configuration.torii_api_url = small::SmallStr::from_string(
        "http://".to_owned() + &network.peers.values().last().unwrap().api_address,
    );
    let iroha_client_1 = Client::new(&client_configuration).expect("Invalid client configuration");
    let request = client::asset::by_account_id(alice_id);
    assert_eq!(
        iroha_client_1
            .request(request.clone())
            .expect("Query failed.")
            .len(),
        1 // Alice has roses from Genesis
    );
    let (public_key2, private_key2) = key_pair_2.into();
    client_configuration.public_key = public_key2;
    client_configuration.private_key = private_key2;
    let iroha_client_2 = Client::new(&client_configuration).expect("Invalid client configuration");
    let instructions: Vec<Instruction> = vec![mint_asset.into()];
    let transaction = iroha_client_2
        .build_transaction(instructions.into(), UnlimitedMetadata::new())
        .expect("Failed to create transaction.");
    let transaction = iroha_client_2
        .get_original_transaction(&transaction, 3, Duration::from_millis(100))
        .expect("Failed to query pending transactions.")
        .expect("Found no pending transaction for this account.");
    iroha_client_2
        .submit_transaction(
            iroha_client_2
                .sign_transaction(transaction)
                .expect("Failed to sign transaction."),
        )
        .expect("Failed to submit transaction.");
    thread::sleep(pipeline_time);
    let assets = iroha_client_1.request(request).expect("Query failed.");
    assert!(!assets.is_empty());
    let camomile_asset = assets
        .iter()
        .find(|asset| *asset.id() == asset_id)
        .expect("Failed to find expected asset");
    assert_eq!(AssetValue::Quantity(quantity), *camomile_asset.value());
}
