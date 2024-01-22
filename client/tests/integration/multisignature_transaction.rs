use std::{str::FromStr as _, thread, time::Duration};

use eyre::Result;
use iroha_client::{
    client::{self, Client, QueryResult},
    config::Config as ClientConfiguration,
    crypto::KeyPair,
    data_model::{
        parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
        prelude::*,
    },
};
use iroha_config::parameters::actual::Root as Configuration;
use test_network::*;

#[allow(clippy::too_many_lines)]
#[test]
fn multisignature_transactions_should_wait_for_all_signatures() -> Result<()> {
    let (_rt, network, client) = Network::start_test_with_runtime(4, Some(10_945));
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Configuration::pipeline_time();

    client.submit_all_blocking(
        ParametersBuilder::new()
            .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, 1u32)?
            .into_set_parameters(),
    )?;

    let alice_id = AccountId::from_str("alice@wonderland")?;
    let alice_key_pair = get_key_pair();
    let key_pair_2 = KeyPair::generate();
    let asset_definition_id = AssetDefinitionId::from_str("camomile#wonderland")?;
    let create_asset =
        Register::asset_definition(AssetDefinition::quantity(asset_definition_id.clone()));
    let set_signature_condition = Mint::account_signature_check_condition(
        SignatureCheckCondition::AllAccountSignaturesAnd(
            vec![key_pair_2.public_key().clone()].into(),
        ),
        alice_id.clone(),
    );

    let mut client_configuration = ClientConfiguration::test(&network.genesis.api_address);
    let client = Client::new(client_configuration.clone());
    let instructions: [InstructionBox; 2] = [create_asset.into(), set_signature_condition.into()];
    client.submit_all_blocking(instructions)?;

    //When
    let quantity: u32 = 200;
    let asset_id = AssetId::new(asset_definition_id, alice_id.clone());
    let mint_asset = Mint::asset_quantity(quantity, asset_id.clone());

    client_configuration.account_id = alice_id.clone();
    client_configuration.key_pair = alice_key_pair;
    let client = Client::new(client_configuration.clone());
    let instructions = [mint_asset.clone()];
    let transaction = client.build_transaction(instructions, UnlimitedMetadata::new());
    client.submit_transaction(&client.sign_transaction(transaction))?;
    thread::sleep(pipeline_time);

    //Then
    client_configuration.torii_api_url = format!(
        "http://{}",
        &network.peers.values().last().unwrap().api_address,
    )
    .parse()
    .unwrap();
    let client_1 = Client::new(client_configuration.clone());
    let request = client::asset::by_account_id(alice_id);
    let assets = client_1
        .request(request.clone())?
        .collect::<QueryResult<Vec<_>>>()?;
    assert_eq!(
        assets.len(),
        2, // Alice has roses and cabbage from Genesis, but doesn't yet have camomile
        "Multisignature transaction was committed before all required signatures were added"
    );

    client_configuration.key_pair = key_pair_2;
    let client_2 = Client::new(client_configuration);
    let instructions = [mint_asset];
    let transaction = client_2.build_transaction(instructions, UnlimitedMetadata::new());
    let transaction = client_2
        .get_original_matching_transactions(&transaction, 3, Duration::from_millis(100))?
        .pop()
        .expect("Found no pending transaction for this account.");
    client_2.submit_transaction(&client_2.sign_transaction(transaction))?;
    thread::sleep(pipeline_time);
    let assets = client_1
        .request(request)?
        .collect::<QueryResult<Vec<_>>>()?;
    assert!(!assets.is_empty());
    let camomile_asset = assets
        .iter()
        .find(|asset| *asset.id() == asset_id)
        .expect("Failed to find expected asset");
    assert_eq!(AssetValue::Quantity(quantity), *camomile_asset.value());
    Ok(())
}
