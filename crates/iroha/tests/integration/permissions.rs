use std::time::Duration;

use eyre::Result;
use iroha::{
    client::{self, Client},
    crypto::KeyPair,
    data_model::{
        permission::Permission, prelude::*, role::RoleId,
        transaction::error::TransactionRejectionReason,
    },
};
use iroha_executor_data_model::permission::{
    asset::{CanModifyAssetMetadata, CanTransferAsset},
    domain::CanModifyDomainMetadata,
};
use iroha_test_network::*;
use iroha_test_samples::{gen_account_in, ALICE_ID, BOB_ID};
use tokio::{join, time::timeout};

// FIXME
#[tokio::test]
#[ignore]
async fn genesis_transactions_are_validated_by_executor() {
    // `wonderland` domain is owned by Alice,
    //  so the default executor will deny a genesis account to register asset definition.
    let asset_definition_id = "xor#wonderland".parse().expect("Valid");
    let invalid_instruction =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id));
    let network = NetworkBuilder::new()
        .with_genesis_instruction(invalid_instruction)
        .build();
    let peer = network.peer();

    timeout(Duration::from_secs(3), async {
        join!(
            // Peer should start...
            peer.start(network.config(), Some(network.genesis())),
            peer.once(|event| matches!(event, PeerLifecycleEvent::ServerStarted)),
            // ...but it should shortly exit with an error
            peer.once(|event| match event {
                // TODO: handle "Invalid genesis" more granular
                PeerLifecycleEvent::Terminated { status } => !status.success(),
                _ => false,
            })
        )
    })
    .await
    .expect("peer should panic within timeout");
}

fn get_assets(iroha: &Client, id: &AccountId) -> Vec<Asset> {
    iroha
        .query(client::asset::all())
        .filter_with(|asset| asset.id.account.eq(id.clone()))
        .execute_all()
        .expect("Failed to execute request.")
}

#[test]
#[ignore = "ignore, more in #2851"]
fn permissions_disallow_asset_transfer() {
    let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let iroha = network.client();

    // Given
    let alice_id = ALICE_ID.clone();
    let bob_id = BOB_ID.clone();
    let (mouse_id, _mouse_keypair) = gen_account_in("wonderland");
    let asset_definition_id: AssetDefinitionId = "xor#wonderland".parse().expect("Valid");
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    let mouse_keypair = KeyPair::random();

    let alice_start_assets = get_assets(&iroha, &alice_id);
    iroha
        .submit_blocking(create_asset)
        .expect("Failed to prepare state.");

    let quantity = numeric!(200);
    let mint_asset = Mint::asset_numeric(
        quantity,
        AssetId::new(asset_definition_id.clone(), bob_id.clone()),
    );
    iroha
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
        .sign(mouse_keypair.private_key());
    let err = iroha
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
    let alice_assets = get_assets(&iroha, &alice_id);
    assert_eq!(alice_assets, alice_start_assets);
}

#[test]
#[ignore = "ignore, more in #2851"]
fn permissions_disallow_asset_burn() {
    let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let iroha = network.client();

    let alice_id = ALICE_ID.clone();
    let bob_id = BOB_ID.clone();
    let (mouse_id, _mouse_keypair) = gen_account_in("wonderland");
    let asset_definition_id = "xor#wonderland"
        .parse::<AssetDefinitionId>()
        .expect("Valid");
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    let mouse_keypair = KeyPair::random();

    let alice_start_assets = get_assets(&iroha, &alice_id);

    iroha
        .submit_blocking(create_asset)
        .expect("Failed to prepare state.");

    let quantity = numeric!(200);
    let mint_asset =
        Mint::asset_numeric(quantity, AssetId::new(asset_definition_id.clone(), bob_id));
    iroha
        .submit_blocking(mint_asset)
        .expect("Failed to create asset.");
    let burn_asset = Burn::asset_numeric(
        quantity,
        AssetId::new(asset_definition_id, mouse_id.clone()),
    );
    let burn_tx = TransactionBuilder::new(chain_id, mouse_id)
        .with_instructions([burn_asset])
        .sign(mouse_keypair.private_key());

    let err = iroha
        .submit_transaction_blocking(&burn_tx)
        .expect_err("Transaction was not rejected.");
    let rejection_reason = err
        .downcast_ref::<TransactionRejectionReason>()
        .expect("Error {err} is not TransactionRejectionReason");

    assert!(matches!(
        rejection_reason,
        &TransactionRejectionReason::Validation(ValidationFail::NotPermitted(_))
    ));

    let alice_assets = get_assets(&iroha, &alice_id);
    assert_eq!(alice_assets, alice_start_assets);
}

#[test]
#[ignore = "ignore, more in #2851"]
fn account_can_query_only_its_own_domain() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let client = network.client();

    // Given
    let domain_id: DomainId = "wonderland".parse()?;
    let new_domain_id: DomainId = "wonderland2".parse()?;
    let register_domain = Register::domain(Domain::new(new_domain_id.clone()));

    client.submit_blocking(register_domain)?;

    // Alice can query the domain in which her account exists.
    assert!(client
        .query(client::domain::all())
        .filter_with(|domain| domain.id.eq(domain_id))
        .execute_single()
        .is_ok());

    // Alice cannot query other domains.
    assert!(client
        .query(client::domain::all())
        .filter_with(|domain| domain.id.eq(new_domain_id))
        .execute_single()
        .is_err());
    Ok(())
}

#[test]
fn permissions_differ_not_only_by_names() {
    let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let client = network.client();

    let alice_id = ALICE_ID.clone();
    let (mouse_id, mouse_keypair) = gen_account_in("outfit");

    // Registering mouse
    let outfit_domain: DomainId = "outfit".parse().unwrap();
    let create_outfit_domain = Register::domain(Domain::new(outfit_domain.clone()));
    let register_mouse_account = Register::account(Account::new(mouse_id.clone()));
    client
        .submit_all_blocking::<InstructionBox>([
            create_outfit_domain.into(),
            register_mouse_account.into(),
        ])
        .expect("Failed to register mouse");

    // Registering `Store` asset definitions
    let hat_definition_id: AssetDefinitionId = "hat#outfit".parse().expect("Valid");
    let register_hat_definition =
        Register::asset_definition(AssetDefinition::store(hat_definition_id.clone()));
    let transfer_shoes_domain = Transfer::domain(alice_id.clone(), outfit_domain, mouse_id.clone());
    let shoes_definition_id: AssetDefinitionId = "shoes#outfit".parse().expect("Valid");
    let register_shoes_definition =
        Register::asset_definition(AssetDefinition::store(shoes_definition_id.clone()));
    client
        .submit_all_blocking::<InstructionBox>([
            register_hat_definition.into(),
            register_shoes_definition.into(),
            transfer_shoes_domain.into(),
        ])
        .expect("Failed to register new asset definitions");

    // Granting permission to Alice to modify metadata in Mouse's hats
    let mouse_hat_id = AssetId::new(hat_definition_id, mouse_id.clone());
    let mouse_hat_permission = CanModifyAssetMetadata {
        asset: mouse_hat_id.clone(),
    };
    let allow_alice_to_set_key_value_in_hats =
        Grant::account_permission(mouse_hat_permission, alice_id.clone());

    let grant_hats_access_tx = TransactionBuilder::new(chain_id.clone(), mouse_id.clone())
        .with_instructions([allow_alice_to_set_key_value_in_hats])
        .sign(mouse_keypair.private_key());
    client
        .submit_transaction_blocking(&grant_hats_access_tx)
        .expect("Failed grant permission to modify Mouse's hats");

    // Checking that Alice can modify Mouse's hats ...
    client
        .submit_blocking(SetKeyValue::asset(
            mouse_hat_id,
            "color".parse().expect("Valid"),
            "red".parse::<JsonString>().expect("Valid"),
        ))
        .expect("Failed to modify Mouse's hats");

    // ... but not shoes
    let mouse_shoes_id = AssetId::new(shoes_definition_id, mouse_id.clone());
    let set_shoes_color = SetKeyValue::asset(
        mouse_shoes_id.clone(),
        "color".parse().expect("Valid"),
        "yellow".parse::<JsonString>().expect("Valid"),
    );
    let _err = client
        .submit_blocking(set_shoes_color.clone())
        .expect_err("Expected Alice to fail to modify Mouse's shoes");

    let mouse_shoes_permission = CanModifyAssetMetadata {
        asset: mouse_shoes_id,
    };
    let allow_alice_to_set_key_value_in_shoes =
        Grant::account_permission(mouse_shoes_permission, alice_id);

    let grant_shoes_access_tx = TransactionBuilder::new(chain_id, mouse_id)
        .with_instructions([allow_alice_to_set_key_value_in_shoes])
        .sign(mouse_keypair.private_key());

    client
        .submit_transaction_blocking(&grant_shoes_access_tx)
        .expect("Failed grant permission to modify Mouse's shoes");

    // Checking that Alice can modify Mouse's shoes
    client
        .submit_blocking(set_shoes_color)
        .expect("Failed to modify Mouse's shoes");
}

#[test]
// #[allow(deprecated)]
fn stored_vs_granted_permission_payload() -> Result<()> {
    let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let iroha = network.client();

    // Given
    let alice_id = ALICE_ID.clone();

    // Registering mouse and asset definition
    let asset_definition_id: AssetDefinitionId = "xor#wonderland".parse().expect("Valid");
    let create_asset =
        Register::asset_definition(AssetDefinition::store(asset_definition_id.clone()));
    let (mouse_id, mouse_keypair) = gen_account_in("wonderland");
    let register_mouse_account = Register::account(Account::new(mouse_id.clone()));
    iroha
        .submit_all_blocking::<InstructionBox>([register_mouse_account.into(), create_asset.into()])
        .expect("Failed to register mouse");

    // Allow alice to mint mouse asset and mint initial value
    let value_json = JsonString::from_string_unchecked(format!(
        // NOTE: Permissions is created explicitly as a json string to introduce additional whitespace
        // This way, if the executor compares permissions just as JSON strings, the test will fail
        r##"{{ "asset"   :   "xor#wonderland#{mouse_id}" }}"##
    ));

    let mouse_asset = AssetId::new(asset_definition_id, mouse_id.clone());
    let allow_alice_to_set_key_value_in_mouse_asset = Grant::account_permission(
        Permission::new("CanModifyAssetMetadata".parse().unwrap(), value_json),
        alice_id,
    );

    let transaction = TransactionBuilder::new(chain_id, mouse_id)
        .with_instructions([allow_alice_to_set_key_value_in_mouse_asset])
        .sign(mouse_keypair.private_key());
    iroha
        .submit_transaction_blocking(&transaction)
        .expect("Failed to grant permission to alice.");

    // Check that alice can indeed mint mouse asset
    let set_key_value = SetKeyValue::asset(
        mouse_asset,
        "color".parse()?,
        "red".parse::<JsonString>().expect("Valid"),
    );
    iroha
        .submit_blocking(set_key_value)
        .expect("Failed to mint asset for mouse.");

    Ok(())
}

#[test]
// #[allow(deprecated)]
fn permissions_are_unified() {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let iroha = network.client();

    // Given
    let alice_id = ALICE_ID.clone();

    let permission1 = CanTransferAsset {
        asset: format!("rose#wonderland#{alice_id}").parse().unwrap(),
    };
    let allow_alice_to_transfer_rose_1 = Grant::account_permission(permission1, alice_id.clone());

    let permission2 = CanTransferAsset {
        asset: format!("rose##{alice_id}").parse().unwrap(),
    };
    let allow_alice_to_transfer_rose_2 = Grant::account_permission(permission2, alice_id);

    iroha
        .submit_blocking(allow_alice_to_transfer_rose_1)
        .expect("failed to grant permission");

    let _ = iroha
        .submit_blocking(allow_alice_to_transfer_rose_2)
        .expect_err("should reject due to duplication");
}

#[test]
fn associated_permissions_removed_on_unregister() {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let iroha = network.client();

    let bob_id = BOB_ID.clone();
    let kingdom_id: DomainId = "kingdom".parse().expect("Valid");
    let kingdom = Domain::new(kingdom_id.clone());

    // register kingdom and give bob permissions in this domain
    let register_domain = Register::domain(kingdom);
    let bob_to_set_kv_in_domain = CanModifyDomainMetadata {
        domain: kingdom_id.clone(),
    };
    let allow_bob_to_set_kv_in_domain =
        Grant::account_permission(bob_to_set_kv_in_domain.clone(), bob_id.clone());

    iroha
        .submit_all_blocking::<InstructionBox>([
            register_domain.into(),
            allow_bob_to_set_kv_in_domain.into(),
        ])
        .expect("failed to register domain and grant permission");

    // check that bob indeed have granted permission
    assert!(iroha
        .query(client::permission::by_account_id(bob_id.clone()))
        .execute_all()
        .expect("failed to get permissions for bob")
        .into_iter()
        .any(|permission| {
            CanModifyDomainMetadata::try_from(&permission)
                .is_ok_and(|permission| permission == bob_to_set_kv_in_domain)
        }));

    // unregister kingdom
    iroha
        .submit_blocking(Unregister::domain(kingdom_id))
        .expect("failed to unregister domain");

    // check that permission is removed from bob
    assert!(!iroha
        .query(client::permission::by_account_id(bob_id))
        .execute_all()
        .expect("failed to get permissions for bob")
        .into_iter()
        .any(|permission| {
            CanModifyDomainMetadata::try_from(&permission)
                .is_ok_and(|permission| permission == bob_to_set_kv_in_domain)
        }));
}

#[test]
fn associated_permissions_removed_from_role_on_unregister() {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let iroha = network.client();

    let role_id: RoleId = "role".parse().expect("Valid");
    let kingdom_id: DomainId = "kingdom".parse().expect("Valid");
    let kingdom = Domain::new(kingdom_id.clone());

    // register kingdom and give bob permissions in this domain
    let register_domain = Register::domain(kingdom);
    let set_kv_in_domain = CanModifyDomainMetadata {
        domain: kingdom_id.clone(),
    };
    let register_role = Register::role(
        Role::new(role_id.clone(), ALICE_ID.clone()).add_permission(set_kv_in_domain.clone()),
    );

    iroha
        .submit_all_blocking::<InstructionBox>([register_domain.into(), register_role.into()])
        .expect("failed to register domain and grant permission");

    // check that role indeed have permission
    assert!(iroha
        .query(client::role::all())
        .filter_with(|role| role.id.eq(role_id.clone()))
        .execute_single()
        .expect("failed to get role")
        .permissions()
        .any(|permission| {
            CanModifyDomainMetadata::try_from(permission)
                .is_ok_and(|permission| permission == set_kv_in_domain)
        }));

    // unregister kingdom
    iroha
        .submit_blocking(Unregister::domain(kingdom_id))
        .expect("failed to unregister domain");

    // check that permission is removed from role
    assert!(!iroha
        .query(client::role::all())
        .filter_with(|role| role.id.eq(role_id.clone()))
        .execute_single()
        .expect("failed to get role")
        .permissions()
        .any(|permission| {
            CanModifyDomainMetadata::try_from(permission)
                .is_ok_and(|permission| permission == set_kv_in_domain)
        }));
}
