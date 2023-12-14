use std::{str::FromStr as _, thread, time::Duration};

use eyre::Result;
use iroha_client::{
    client::{self, Client, QueryResult},
    crypto::KeyPair,
    data_model::prelude::*,
};
use iroha_genesis::GenesisNetwork;
use serde_json::json;
use test_network::{PeerBuilder, *};

#[test]
fn genesis_transactions_are_validated() {
    const POLL_PERIOD: Duration = Duration::from_millis(1000);
    const MAX_RETRIES: u32 = 3;

    // Setting up genesis

    let mut genesis = GenesisNetwork::test(true).expect("Expected genesis");

    let grant_invalid_token = GrantExpr::new(
        PermissionToken::new("InvalidToken".parse().unwrap(), &json!(null)),
        AccountId::from_str("alice@wonderland").unwrap(),
    );

    let tx_ref = &mut genesis.transactions.last_mut().unwrap().0;
    match &mut tx_ref.payload_mut().instructions {
        Executable::Instructions(instructions) => {
            instructions.push(grant_invalid_token.into());
        }
        Executable::Wasm(_) => panic!("Expected instructions"),
    }

    // Starting peer
    let (_rt, _peer, test_client) = <PeerBuilder>::new()
        .with_genesis(genesis)
        .with_port(11_100)
        .start_with_runtime();

    // Checking that peer contains no blocks multiple times
    // See also `wait_for_genesis_committed()`
    for _ in 0..MAX_RETRIES {
        match test_client.get_status() {
            Ok(status) => {
                assert!(status.blocks == 0);
                thread::sleep(POLL_PERIOD);
            }
            Err(error) => {
                // Connection failed meaning that Iroha panicked on invalid genesis.
                // Not a very good way to check it, but it's the best we can do in the current situation.

                iroha_logger::info!(
                    ?error,
                    "Failed to get status, Iroha probably panicked on invalid genesis, test passed"
                );
                break;
            }
        }
    }
}

fn get_assets(iroha_client: &Client, id: &AccountId) -> Vec<Asset> {
    iroha_client
        .request(client::asset::by_account_id(id.clone()))
        .expect("Failed to execute request.")
        .collect::<QueryResult<Vec<_>>>()
        .expect("Failed to execute request.")
}

#[test]
#[ignore = "ignore, more in #2851"]
fn permissions_disallow_asset_transfer() {
    let (_rt, _peer, iroha_client) = <PeerBuilder>::new().with_port(10_730).start_with_runtime();
    wait_for_genesis_committed(&[iroha_client.clone()], 0);

    // Given
    let alice_id = "alice@wonderland".parse().expect("Valid");
    let bob_id: AccountId = "bob@wonderland".parse().expect("Valid");
    let mouse_id: AccountId = "mouse@wonderland".parse().expect("Valid");
    let asset_definition_id: AssetDefinitionId = "xor#wonderland".parse().expect("Valid");
    let create_asset = RegisterExpr::new(AssetDefinition::quantity(asset_definition_id.clone()));
    let mouse_keypair = KeyPair::generate().expect("Failed to generate KeyPair.");

    let alice_start_assets = get_assets(&iroha_client, &alice_id);
    iroha_client
        .submit_blocking(create_asset)
        .expect("Failed to prepare state.");

    let quantity: u32 = 200;
    let mint_asset = MintExpr::new(
        quantity.to_value(),
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), bob_id.clone())),
    );
    iroha_client
        .submit_blocking(mint_asset)
        .expect("Failed to create asset.");

    //When
    let transfer_asset = TransferExpr::new(
        IdBox::AssetId(AssetId::new(asset_definition_id, bob_id)),
        quantity.to_value(),
        IdBox::AccountId(alice_id.clone()),
    );
    let transfer_tx = TransactionBuilder::new(mouse_id)
        .with_instructions([transfer_asset])
        .sign(mouse_keypair)
        .expect("Failed to sign mouse transaction");
    let err = iroha_client
        .submit_transaction_blocking(&transfer_tx)
        .expect_err("Transaction was not rejected.");
    let rejection_reason = err
        .downcast_ref::<PipelineRejectionReason>()
        .expect("Error {err} is not PipelineRejectionReason");
    //Then
    assert!(matches!(
        rejection_reason,
        &PipelineRejectionReason::Transaction(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(_)
        ))
    ));
    let alice_assets = get_assets(&iroha_client, &alice_id);
    assert_eq!(alice_assets, alice_start_assets);
}

#[test]
#[ignore = "ignore, more in #2851"]
fn permissions_disallow_asset_burn() {
    let (_rt, _peer, iroha_client) = <PeerBuilder>::new().with_port(10_735).start_with_runtime();

    let alice_id = "alice@wonderland".parse().expect("Valid");
    let bob_id: AccountId = "bob@wonderland".parse().expect("Valid");
    let mouse_id: AccountId = "mouse@wonderland".parse().expect("Valid");
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset = RegisterExpr::new(AssetDefinition::quantity(asset_definition_id.clone()));
    let mouse_keypair = KeyPair::generate().expect("Failed to generate KeyPair.");

    let alice_start_assets = get_assets(&iroha_client, &alice_id);

    iroha_client
        .submit_blocking(create_asset)
        .expect("Failed to prepare state.");

    let quantity: u32 = 200;
    let mint_asset = MintExpr::new(
        quantity.to_value(),
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), bob_id)),
    );
    iroha_client
        .submit_blocking(mint_asset)
        .expect("Failed to create asset.");
    let burn_asset = BurnExpr::new(
        quantity.to_value(),
        IdBox::AssetId(AssetId::new(asset_definition_id, mouse_id.clone())),
    );
    let burn_tx = TransactionBuilder::new(mouse_id)
        .with_instructions([burn_asset])
        .sign(mouse_keypair)
        .expect("Failed to sign mouse transaction");

    let err = iroha_client
        .submit_transaction_blocking(&burn_tx)
        .expect_err("Transaction was not rejected.");
    let rejection_reason = err
        .downcast_ref::<PipelineRejectionReason>()
        .expect("Error {err} is not PipelineRejectionReason");

    assert!(matches!(
        rejection_reason,
        &PipelineRejectionReason::Transaction(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(_)
        ))
    ));

    let alice_assets = get_assets(&iroha_client, &alice_id);
    assert_eq!(alice_assets, alice_start_assets);
}

#[test]
#[ignore = "ignore, more in #2851"]
fn account_can_query_only_its_own_domain() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_740).start_with_runtime();
    wait_for_genesis_committed(&[client.clone()], 0);

    // Given
    let domain_id: DomainId = "wonderland".parse()?;
    let new_domain_id: DomainId = "wonderland2".parse()?;
    let register_domain = RegisterExpr::new(Domain::new(new_domain_id.clone()));

    client.submit_blocking(register_domain)?;

    // Alice can query the domain in which her account exists.
    assert!(client.request(client::domain::by_id(domain_id)).is_ok());

    // Alice cannot query other domains.
    assert!(client
        .request(client::domain::by_id(new_domain_id))
        .is_err());
    Ok(())
}

#[test]
fn permissions_differ_not_only_by_names() {
    let (_rt, _not_drop, client) = <PeerBuilder>::new().with_port(10_745).start_with_runtime();

    let alice_id: AccountId = "alice@wonderland".parse().expect("Valid");
    let mouse_id: AccountId = "mouse@wonderland".parse().expect("Valid");
    let mouse_keypair = KeyPair::generate().expect("Failed to generate KeyPair.");

    // Registering `Store` asset definitions
    let hat_definition_id: AssetDefinitionId = "hat#wonderland".parse().expect("Valid");
    let new_hat_definition = AssetDefinition::store(hat_definition_id.clone());
    let shoes_definition_id: AssetDefinitionId = "shoes#wonderland".parse().expect("Valid");
    let new_shoes_definition = AssetDefinition::store(shoes_definition_id.clone());
    client
        .submit_all_blocking([
            RegisterExpr::new(new_hat_definition),
            RegisterExpr::new(new_shoes_definition),
        ])
        .expect("Failed to register new asset definitions");

    // Registering mouse
    let new_mouse_account = Account::new(mouse_id.clone(), [mouse_keypair.public_key().clone()]);
    client
        .submit_blocking(RegisterExpr::new(new_mouse_account))
        .expect("Failed to register mouse");

    // Granting permission to Alice to modify metadata in Mouse's hats
    let mouse_hat_id = AssetId::new(hat_definition_id, mouse_id.clone());
    let allow_alice_to_set_key_value_in_hats = GrantExpr::new(
        PermissionToken::new(
            "CanSetKeyValueInUserAsset".parse().unwrap(),
            &json!({ "asset_id": mouse_hat_id }),
        ),
        alice_id.clone(),
    );

    let grant_hats_access_tx = TransactionBuilder::new(mouse_id.clone())
        .with_instructions([allow_alice_to_set_key_value_in_hats])
        .sign(mouse_keypair.clone())
        .expect("Failed to sign mouse transaction");
    client
        .submit_transaction_blocking(&grant_hats_access_tx)
        .expect("Failed grant permission to modify Mouse's hats");

    // Checking that Alice can modify Mouse's hats ...
    client
        .submit_blocking(SetKeyValueExpr::new(
            mouse_hat_id,
            Name::from_str("color").expect("Valid"),
            "red".to_owned(),
        ))
        .expect("Failed to modify Mouse's hats");

    // ... but not shoes
    let mouse_shoes_id = AssetId::new(shoes_definition_id, mouse_id.clone());
    let set_shoes_color = SetKeyValueExpr::new(
        mouse_shoes_id.clone(),
        Name::from_str("color").expect("Valid"),
        "yellow".to_owned(),
    );
    let _err = client
        .submit_blocking(set_shoes_color.clone())
        .expect_err("Expected Alice to fail to modify Mouse's shoes");

    // Granting permission to Alice to modify metadata in Mouse's shoes
    let allow_alice_to_set_key_value_in_shoes = GrantExpr::new(
        PermissionToken::new(
            "CanSetKeyValueInUserAsset".parse().unwrap(),
            &json!({ "asset_id": mouse_shoes_id }),
        ),
        alice_id,
    );

    let grant_shoes_access_tx = TransactionBuilder::new(mouse_id)
        .with_instructions([allow_alice_to_set_key_value_in_shoes])
        .sign(mouse_keypair)
        .expect("Failed to sign mouse transaction");

    client
        .submit_transaction_blocking(&grant_shoes_access_tx)
        .expect("Failed grant permission to modify Mouse's shoes");

    // Checking that Alice can modify Mouse's shoes
    client
        .submit_blocking(set_shoes_color)
        .expect("Failed to modify Mouse's shoes");
}

#[test]
fn stored_vs_granted_token_payload() -> Result<()> {
    let (_rt, _peer, iroha_client) = <PeerBuilder>::new().with_port(10_730).start_with_runtime();
    wait_for_genesis_committed(&[iroha_client.clone()], 0);

    // Given
    let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");

    // Registering mouse and asset definition
    let asset_definition_id: AssetDefinitionId = "xor#wonderland".parse().expect("Valid");
    let create_asset = RegisterExpr::new(AssetDefinition::store(asset_definition_id.clone()));
    let mouse_id: AccountId = "mouse@wonderland".parse().expect("Valid");
    let mouse_keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let new_mouse_account = Account::new(mouse_id.clone(), [mouse_keypair.public_key().clone()]);
    let instructions: [InstructionExpr; 2] = [
        RegisterExpr::new(new_mouse_account).into(),
        create_asset.into(),
    ];
    iroha_client
        .submit_all_blocking(instructions)
        .expect("Failed to register mouse");

    // Allow alice to mint mouse asset and mint initial value
    let mouse_asset = AssetId::new(asset_definition_id, mouse_id.clone());
    let allow_alice_to_set_key_value_in_mouse_asset = GrantExpr::new(
        PermissionToken::from_str_unchecked(
            "CanSetKeyValueInUserAsset".parse().unwrap(),
            // NOTE: Introduced additional whitespaces in the serialized form
            "{ \"asset_id\" : \"xor#wonderland#mouse@wonderland\" }",
        ),
        alice_id,
    );

    let transaction = TransactionBuilder::new(mouse_id)
        .with_instructions([allow_alice_to_set_key_value_in_mouse_asset])
        .sign(mouse_keypair)
        .expect("Failed to sign mouse transaction");
    iroha_client
        .submit_transaction_blocking(&transaction)
        .expect("Failed to grant permission to alice.");

    // Check that alice can indeed mint mouse asset
    let set_key_value =
        SetKeyValueExpr::new(mouse_asset, Name::from_str("color")?, "red".to_owned());
    iroha_client
        .submit_blocking(set_key_value)
        .expect("Failed to mint asset for mouse.");

    Ok(())
}
