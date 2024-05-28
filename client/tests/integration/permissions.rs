use std::{str::FromStr as _, thread, time::Duration};

use eyre::Result;
use iroha_client::{
    client::{self, Client, QueryResult},
    crypto::KeyPair,
    data_model::prelude::*,
};
use iroha_data_model::{
    permission::Permission, role::RoleId, transaction::error::TransactionRejectionReason,
    JsonString,
};
use iroha_genesis::GenesisNetwork;
use serde_json::json;
use test_network::{PeerBuilder, *};
use test_samples::{gen_account_in, ALICE_ID, BOB_ID};

#[test]
fn genesis_transactions_are_validated() {
    const POLL_PERIOD: Duration = Duration::from_millis(1000);
    const MAX_RETRIES: u32 = 3;

    // Setting up genesis

    let genesis = GenesisNetwork::test_with_instructions([Grant::permission(
        Permission::new("InvalidToken".parse().unwrap(), json!(null)),
        ALICE_ID.clone(),
    )
    .into()]);

    // Starting peer
    let (_rt, _peer, test_client) = <PeerBuilder>::new()
        .with_genesis(genesis)
        .with_port(11_110)
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
    let chain_id = ChainId::from("0");

    let (_rt, _peer, iroha_client) = <PeerBuilder>::new().with_port(10_730).start_with_runtime();
    wait_for_genesis_committed(&[iroha_client.clone()], 0);

    // Given
    let alice_id = ALICE_ID.clone();
    let bob_id = BOB_ID.clone();
    let (mouse_id, _mouse_keypair) = gen_account_in("wonderland");
    let asset_definition_id: AssetDefinitionId = "xor#wonderland".parse().expect("Valid");
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    let mouse_keypair = KeyPair::random();

    let alice_start_assets = get_assets(&iroha_client, &alice_id);
    iroha_client
        .submit_blocking(create_asset)
        .expect("Failed to prepare state.");

    let quantity = numeric!(200);
    let mint_asset = Mint::asset_numeric(
        quantity,
        AssetId::new(asset_definition_id.clone(), bob_id.clone()),
    );
    iroha_client
        .submit_blocking(mint_asset)
        .expect("Failed to create asset.");

    //When
    let transfer_asset = Transfer::asset_numeric(
        AssetId::new(asset_definition_id, bob_id),
        quantity,
        alice_id.clone(),
    );
    let transfer_tx = TransactionBuilder::new(chain_id, mouse_id)
        .with_instructions([transfer_asset])
        .sign(&mouse_keypair);
    let err = iroha_client
        .submit_transaction_blocking(&transfer_tx)
        .expect_err("Transaction was not rejected.");
    let rejection_reason = err
        .downcast_ref::<TransactionRejectionReason>()
        .expect("Error {err} is not TransactionRejectionReason");
    //Then
    assert!(matches!(
        rejection_reason,
        &TransactionRejectionReason::Validation(ValidationFail::NotPermitted(_))
    ));
    let alice_assets = get_assets(&iroha_client, &alice_id);
    assert_eq!(alice_assets, alice_start_assets);
}

#[test]
#[ignore = "ignore, more in #2851"]
fn permissions_disallow_asset_burn() {
    let chain_id = ChainId::from("0");

    let (_rt, _peer, iroha_client) = <PeerBuilder>::new().with_port(10_735).start_with_runtime();

    let alice_id = ALICE_ID.clone();
    let bob_id = BOB_ID.clone();
    let (mouse_id, _mouse_keypair) = gen_account_in("wonderland");
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    let mouse_keypair = KeyPair::random();

    let alice_start_assets = get_assets(&iroha_client, &alice_id);

    iroha_client
        .submit_blocking(create_asset)
        .expect("Failed to prepare state.");

    let quantity = numeric!(200);
    let mint_asset =
        Mint::asset_numeric(quantity, AssetId::new(asset_definition_id.clone(), bob_id));
    iroha_client
        .submit_blocking(mint_asset)
        .expect("Failed to create asset.");
    let burn_asset = Burn::asset_numeric(
        quantity,
        AssetId::new(asset_definition_id, mouse_id.clone()),
    );
    let burn_tx = TransactionBuilder::new(chain_id, mouse_id)
        .with_instructions([burn_asset])
        .sign(&mouse_keypair);

    let err = iroha_client
        .submit_transaction_blocking(&burn_tx)
        .expect_err("Transaction was not rejected.");
    let rejection_reason = err
        .downcast_ref::<TransactionRejectionReason>()
        .expect("Error {err} is not TransactionRejectionReason");

    assert!(matches!(
        rejection_reason,
        &TransactionRejectionReason::Validation(ValidationFail::NotPermitted(_))
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
    let register_domain = Register::domain(Domain::new(new_domain_id.clone()));

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
    let chain_id = ChainId::from("0");

    let (_rt, _not_drop, client) = <PeerBuilder>::new().with_port(10_745).start_with_runtime();

    let alice_id = ALICE_ID.clone();
    let (mouse_id, mouse_keypair) = gen_account_in("outfit");

    // Registering mouse
    let outfit_domain: DomainId = "outfit".parse().unwrap();
    let create_outfit_domain = Register::domain(Domain::new(outfit_domain.clone()));
    let new_mouse_account = Account::new(mouse_id.clone());
    client
        .submit_all_blocking([
            InstructionBox::from(create_outfit_domain),
            Register::account(new_mouse_account).into(),
        ])
        .expect("Failed to register mouse");

    // Registering `Store` asset definitions
    let hat_definition_id: AssetDefinitionId = "hat#outfit".parse().expect("Valid");
    let new_hat_definition = AssetDefinition::store(hat_definition_id.clone());
    let transfer_shoes_domain = Transfer::domain(alice_id.clone(), outfit_domain, mouse_id.clone());
    let shoes_definition_id: AssetDefinitionId = "shoes#outfit".parse().expect("Valid");
    let new_shoes_definition = AssetDefinition::store(shoes_definition_id.clone());
    let instructions: [InstructionBox; 3] = [
        Register::asset_definition(new_hat_definition).into(),
        Register::asset_definition(new_shoes_definition).into(),
        transfer_shoes_domain.into(),
    ];
    client
        .submit_all_blocking(instructions)
        .expect("Failed to register new asset definitions");

    // Granting permission to Alice to modify metadata in Mouse's hats
    let mouse_hat_id = AssetId::new(hat_definition_id, mouse_id.clone());
    let allow_alice_to_set_key_value_in_hats = Grant::permission(
        Permission::new(
            "CanSetKeyValueInUserAsset".parse().unwrap(),
            json!({ "asset_id": mouse_hat_id }),
        ),
        alice_id.clone(),
    );

    let grant_hats_access_tx = TransactionBuilder::new(chain_id.clone(), mouse_id.clone())
        .with_instructions([allow_alice_to_set_key_value_in_hats])
        .sign(&mouse_keypair);
    client
        .submit_transaction_blocking(&grant_hats_access_tx)
        .expect("Failed grant permission to modify Mouse's hats");

    // Checking that Alice can modify Mouse's hats ...
    client
        .submit_blocking(SetKeyValue::asset(
            mouse_hat_id,
            Name::from_str("color").expect("Valid"),
            "red".to_owned(),
        ))
        .expect("Failed to modify Mouse's hats");

    // ... but not shoes
    let mouse_shoes_id = AssetId::new(shoes_definition_id, mouse_id.clone());
    let set_shoes_color = SetKeyValue::asset(
        mouse_shoes_id.clone(),
        Name::from_str("color").expect("Valid"),
        "yellow".to_owned(),
    );
    let _err = client
        .submit_blocking(set_shoes_color.clone())
        .expect_err("Expected Alice to fail to modify Mouse's shoes");

    // Granting permission to Alice to modify metadata in Mouse's shoes
    let allow_alice_to_set_key_value_in_shoes = Grant::permission(
        Permission::new(
            "CanSetKeyValueInUserAsset".parse().unwrap(),
            json!({ "asset_id": mouse_shoes_id }),
        ),
        alice_id,
    );

    let grant_shoes_access_tx = TransactionBuilder::new(chain_id, mouse_id)
        .with_instructions([allow_alice_to_set_key_value_in_shoes])
        .sign(&mouse_keypair);

    client
        .submit_transaction_blocking(&grant_shoes_access_tx)
        .expect("Failed grant permission to modify Mouse's shoes");

    // Checking that Alice can modify Mouse's shoes
    client
        .submit_blocking(set_shoes_color)
        .expect("Failed to modify Mouse's shoes");
}

#[test]
#[allow(deprecated)]
fn stored_vs_granted_token_payload() -> Result<()> {
    let chain_id = ChainId::from("0");

    let (_rt, _peer, iroha_client) = <PeerBuilder>::new().with_port(10_730).start_with_runtime();
    wait_for_genesis_committed(&[iroha_client.clone()], 0);

    // Given
    let alice_id = ALICE_ID.clone();

    // Registering mouse and asset definition
    let asset_definition_id: AssetDefinitionId = "xor#wonderland".parse().expect("Valid");
    let create_asset =
        Register::asset_definition(AssetDefinition::store(asset_definition_id.clone()));
    let (mouse_id, mouse_keypair) = gen_account_in("wonderland");
    let new_mouse_account = Account::new(mouse_id.clone());
    let instructions: [InstructionBox; 2] = [
        Register::account(new_mouse_account).into(),
        create_asset.into(),
    ];
    iroha_client
        .submit_all_blocking(instructions)
        .expect("Failed to register mouse");

    // Allow alice to mint mouse asset and mint initial value
    let mouse_asset = AssetId::new(asset_definition_id, mouse_id.clone());
    let allow_alice_to_set_key_value_in_mouse_asset = Grant::permission(
        Permission::new(
            "CanSetKeyValueInUserAsset".parse().unwrap(),
            JsonString::from_json_string_unchecked(format!(
                // Introducing some whitespaces
                // This way, if the executor compares just JSON strings, this test would fail
                r##"{{ "asset_id"   :   "xor#wonderland#{}" }}"##,
                mouse_id
            )),
        ),
        alice_id,
    );

    let transaction = TransactionBuilder::new(chain_id, mouse_id)
        .with_instructions([allow_alice_to_set_key_value_in_mouse_asset])
        .sign(&mouse_keypair);
    iroha_client
        .submit_transaction_blocking(&transaction)
        .expect("Failed to grant permission to alice.");

    // Check that alice can indeed mint mouse asset
    let set_key_value = SetKeyValue::asset(mouse_asset, Name::from_str("color")?, "red".to_owned());
    iroha_client
        .submit_blocking(set_key_value)
        .expect("Failed to mint asset for mouse.");

    Ok(())
}

#[test]
#[allow(deprecated)]
fn permissions_are_unified() {
    let (_rt, _peer, iroha_client) = <PeerBuilder>::new().with_port(11_230).start_with_runtime();
    wait_for_genesis_committed(&[iroha_client.clone()], 0);

    // Given
    let alice_id = ALICE_ID.clone();

    let allow_alice_to_transfer_rose_1 = Grant::permission(
        Permission::new(
            "CanTransferUserAsset".parse().unwrap(),
            json!({ "asset_id": format!("rose#wonderland#{alice_id}") }),
        ),
        alice_id.clone(),
    );

    let allow_alice_to_transfer_rose_2 = Grant::permission(
        Permission::new(
            "CanTransferUserAsset".parse().unwrap(),
            // different content, but same meaning
            json!({ "asset_id": format!("rose##{alice_id}") }),
        ),
        alice_id,
    );

    iroha_client
        .submit_blocking(allow_alice_to_transfer_rose_1)
        .expect("failed to grant permission token");

    let _ = iroha_client
        .submit_blocking(allow_alice_to_transfer_rose_2)
        .expect_err("should reject due to duplication");
}

#[test]
fn associated_permissions_removed_on_unregister() {
    let (_rt, _peer, iroha_client) = <PeerBuilder>::new().with_port(11_240).start_with_runtime();
    wait_for_genesis_committed(&[iroha_client.clone()], 0);

    let bob_id = BOB_ID.clone();
    let kingdom_id: DomainId = "kingdom".parse().expect("Valid");
    let kingdom = Domain::new(kingdom_id.clone());

    // register kingdom and give bob permissions in this domain
    let register_domain = Register::domain(kingdom);
    let bob_to_set_kv_in_domain_token = Permission::new(
        "CanSetKeyValueInDomain".parse().unwrap(),
        json!({ "domain_id": kingdom_id }),
    );
    let allow_bob_to_set_kv_in_domain =
        Grant::permission(bob_to_set_kv_in_domain_token.clone(), bob_id.clone());

    iroha_client
        .submit_all_blocking([
            InstructionBox::from(register_domain),
            allow_bob_to_set_kv_in_domain.into(),
        ])
        .expect("failed to register domain and grant permission");

    // check that bob indeed have granted permission
    assert!(iroha_client
        .request(client::permission::by_account_id(bob_id.clone()))
        .and_then(std::iter::Iterator::collect::<QueryResult<Vec<Permission>>>)
        .expect("failed to get permissions for bob")
        .into_iter()
        .any(|token| { token == bob_to_set_kv_in_domain_token }));

    // unregister kingdom
    iroha_client
        .submit_blocking(Unregister::domain(kingdom_id))
        .expect("failed to unregister domain");

    // check that permission is removed from bob
    assert!(iroha_client
        .request(client::permission::by_account_id(bob_id))
        .and_then(std::iter::Iterator::collect::<QueryResult<Vec<Permission>>>)
        .expect("failed to get permissions for bob")
        .into_iter()
        .all(|token| { token != bob_to_set_kv_in_domain_token }));
}

#[test]
fn associated_permissions_removed_from_role_on_unregister() {
    let (_rt, _peer, iroha_client) = <PeerBuilder>::new().with_port(11_255).start_with_runtime();
    wait_for_genesis_committed(&[iroha_client.clone()], 0);

    let role_id: RoleId = "role".parse().expect("Valid");
    let kingdom_id: DomainId = "kingdom".parse().expect("Valid");
    let kingdom = Domain::new(kingdom_id.clone());

    // register kingdom and give bob permissions in this domain
    let register_domain = Register::domain(kingdom);
    let set_kv_in_domain_token = Permission::new(
        "CanSetKeyValueInDomain".parse().unwrap(),
        json!({ "domain_id": kingdom_id }),
    );
    let role = Role::new(role_id.clone()).add_permission(set_kv_in_domain_token.clone());
    let register_role = Register::role(role);

    iroha_client
        .submit_all_blocking([InstructionBox::from(register_domain), register_role.into()])
        .expect("failed to register domain and grant permission");

    // check that role indeed have permission
    assert!(iroha_client
        .request(client::role::by_id(role_id.clone()))
        .map(|role| role.permissions().cloned().collect::<Vec<_>>())
        .expect("failed to get permissions for role")
        .into_iter()
        .any(|token| { token == set_kv_in_domain_token }));

    // unregister kingdom
    iroha_client
        .submit_blocking(Unregister::domain(kingdom_id))
        .expect("failed to unregister domain");

    // check that permission is removed from role
    assert!(iroha_client
        .request(client::role::by_id(role_id.clone()))
        .map(|role| role.permissions().cloned().collect::<Vec<_>>())
        .expect("failed to get permissions for role")
        .into_iter()
        .all(|token| { token != set_kv_in_domain_token }));
}
