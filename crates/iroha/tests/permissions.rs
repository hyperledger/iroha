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
    asset::{CanMintAssetWithDefinition, CanTransferAsset},
    domain::CanModifyDomainMetadata,
};
use iroha_test_network::*;
use iroha_test_samples::{gen_account_in, ALICE_ID, BOB_ID, BOB_KEYPAIR};
use tokio::{join, time::timeout};

#[tokio::test]
async fn genesis_transactions_are_validated_by_executor() {
    // `wonderland` domain is owned by Alice,
    //  so the default executor will deny a genesis account to register asset definition.
    let asset_definition_id = "xor#wonderland".parse().expect("Valid");
    let invalid_instruction = Register::asset_definition(AssetDefinition::new(asset_definition_id));
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
                // TODO: handle "Invalid genesis" in a more granular way
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
        Register::asset_definition(AssetDefinition::new(asset_definition_id.clone()));
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
        Register::asset_definition(AssetDefinition::new(asset_definition_id.clone()));
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
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let client = network.client();

    let alice_in_wland = ALICE_ID.clone();
    let (bob_in_wland, bob_in_wland_key) = (BOB_ID.clone(), BOB_KEYPAIR.private_key());

    let wland_roses = "rose#wonderland".parse::<AssetDefinitionId>().unwrap();
    let wland_coins = "coin#wonderland".parse::<AssetDefinitionId>().unwrap();
    client
        .submit_blocking(Register::asset_definition(AssetDefinition::new(
            wland_coins.clone(),
        )))
        .unwrap();

    // allow Bob to mint roses
    client
        .submit_blocking(Grant::account_permission(
            CanMintAssetWithDefinition {
                asset_definition: wland_roses.clone(),
            },
            bob_in_wland.clone(),
        ))
        .unwrap();
    // check that Bob can mint roses
    let wland_roses_of_alice = AssetId::new(wland_roses, alice_in_wland.clone());
    let wland_coins_of_alice = AssetId::new(wland_coins.clone(), alice_in_wland.clone());
    client
        .submit_blocking(Mint::asset_numeric(1_u32, wland_roses_of_alice))
        .unwrap();
    // check that Bob cannot mint coins
    // FIXME: sign transaction as Bob
    let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");
    let tx = TransactionBuilder::new(chain_id.clone(), bob_in_wland.clone())
        .with_instructions(Some(Mint::asset_numeric(
            1_u32,
            wland_coins_of_alice.clone(),
        )))
        .sign(bob_in_wland_key);
    let _ = client.submit_transaction_blocking(&tx).unwrap_err();
    // allow Bob to mint coins
    client
        .submit_blocking(Grant::account_permission(
            CanMintAssetWithDefinition {
                asset_definition: wland_coins.clone(),
            },
            bob_in_wland.clone(),
        ))
        .unwrap();
    // check that Bob can mint coins
    let tx = TransactionBuilder::new(chain_id, bob_in_wland)
        .with_instructions(Some(Mint::asset_numeric(1_u32, wland_coins_of_alice)))
        .sign(bob_in_wland_key);
    client.submit_transaction_blocking(&tx).unwrap();
}

#[test]
fn stored_vs_granted_permission_payload() -> Result<()> {
    let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let iroha = network.client();

    // Given
    let alice_id = ALICE_ID.clone();

    // Registering mouse and asset definition
    let asset_definition_id: AssetDefinitionId = "xor#wonderland".parse()?;
    let create_asset =
        Register::asset_definition(AssetDefinition::new(asset_definition_id.clone()));
    let (mouse_id, mouse_keypair) = gen_account_in("wonderland");
    let register_mouse_account = Register::account(Account::new(mouse_id.clone()));
    iroha.submit_all_blocking::<InstructionBox>([
        register_mouse_account.into(),
        create_asset.into(),
    ])?;

    // Allow alice to mint mouse asset and mint initial value
    let value_json = Json::from_string_unchecked(format!(
        // NOTE: Permissions is created explicitly as a json string to introduce additional whitespace
        // This way, if the executor compares permissions just as JSON strings, the test will fail
        r##"{{ "asset"   :   "xor#wonderland#{mouse_id}" }}"##
    ));

    let mouse_asset = AssetId::new(asset_definition_id, mouse_id.clone());
    let allow_alice_to_mint_mouse_asset = Grant::account_permission(
        Permission::new("CanMintAsset".parse()?, value_json),
        alice_id,
    );

    let transaction = TransactionBuilder::new(chain_id, mouse_id)
        .with_instructions([allow_alice_to_mint_mouse_asset])
        .sign(mouse_keypair.private_key());
    iroha.submit_transaction_blocking(&transaction)?;

    // Check that alice can indeed mint mouse asset
    let set_key_value = Mint::asset_numeric(1_u32, mouse_asset);
    iroha.submit_blocking(set_key_value)?;

    Ok(())
}

#[test]
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
