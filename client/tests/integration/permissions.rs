#![allow(clippy::restriction)]

use std::{str::FromStr as _, thread};

use iroha_client::client::{self, Client};
use iroha_core::{prelude::*, smartcontracts::permissions::HasToken};
use iroha_data_model::prelude::*;
use iroha_permissions_validators::{
    private_blockchain,
    public_blockchain::{self, key_value::CanSetKeyValueInUserAssets},
};
use test_network::{PeerBuilder, *};

use super::Configuration;

fn get_assets(iroha_client: &mut Client, id: &<Account as Identifiable>::Id) -> Vec<Asset> {
    iroha_client
        .request(client::asset::by_account_id(id.clone()))
        .expect("Failed to execute request.")
}

#[test]
fn permissions_require_registration_before_grant() {
    let (_rt, _peer, iroha_client) = <PeerBuilder>::new()
        .with_instruction_judge(public_blockchain::default_permissions())
        .start_with_runtime();
    wait_for_genesis_committed(&vec![iroha_client.clone()], 0);

    // Given
    let alice_id = <Account as Identifiable>::Id::from_str("alice@wonderland").expect("Valid");
    let token = PermissionToken::new("can_do_stuff".parse().expect("valid"));

    let grant_permission = GrantBox::new(token.clone(), alice_id);
    let register_role = RegisterBox::new(
        Role::new("staff_that_does_stuff".parse().unwrap()).add_permission(token.clone()),
    );

    // We shouldn't be able to grant unregistered permission tokens
    // or roles containing unregistered permission tokens
    assert!(iroha_client
        .submit_blocking(grant_permission.clone())
        .is_err());
    assert!(iroha_client.submit_blocking(register_role.clone()).is_err());

    let register_permission = RegisterBox::new(PermissionTokenDefinition::new(
        token.definition_id().clone(),
    ));

    iroha_client.submit_blocking(register_permission).unwrap();

    // Should be okay after registering the token id.
    assert!(iroha_client.submit_blocking(grant_permission).is_ok());
    assert!(iroha_client.submit_blocking(register_role).is_ok());
}

#[test]
fn permissions_disallow_asset_transfer() {
    let (_rt, _peer, mut iroha_client) = <PeerBuilder>::new()
        .with_instruction_judge(public_blockchain::default_permissions())
        .start_with_runtime();
    wait_for_genesis_committed(&vec![iroha_client.clone()], 0);
    let pipeline_time = Configuration::pipeline_time();

    // Given
    let alice_id = <Account as Identifiable>::Id::from_str("alice@wonderland").expect("Valid");
    let bob_id = <Account as Identifiable>::Id::from_str("bob@wonderland").expect("Valid");
    let asset_definition_id: AssetDefinitionId = "xor#wonderland".parse().expect("Valid");
    let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()));
    let register_bob = RegisterBox::new(Account::new(bob_id.clone(), []));

    let alice_start_assets = get_assets(&mut iroha_client, &alice_id);
    iroha_client
        .submit_all(vec![create_asset.into(), register_bob.into()])
        .expect("Failed to prepare state.");
    thread::sleep(pipeline_time * 2);

    let quantity: u32 = 200;
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), bob_id.clone())),
    );
    iroha_client
        .submit(mint_asset)
        .expect("Failed to create asset.");
    thread::sleep(pipeline_time * 2);

    //When
    let transfer_asset = TransferBox::new(
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), bob_id)),
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id, alice_id.clone())),
    );
    let err = iroha_client
        .submit_blocking(transfer_asset)
        .expect_err("Transaction was not rejected.");
    let rejection_reason = err
        .downcast_ref::<PipelineRejectionReason>()
        .unwrap_or_else(|| panic!("Error {} is not PipelineRejectionReasons.", err));
    //Then
    assert!(matches!(
        rejection_reason,
        &PipelineRejectionReason::Transaction(TransactionRejectionReason::NotPermitted(
            NotPermittedFail { .. }
        ))
    ));
    let alice_assets = get_assets(&mut iroha_client, &alice_id);
    assert_eq!(alice_assets, alice_start_assets);
}

#[test]
fn permissions_disallow_asset_burn() {
    let (_rt, _not_drop, mut iroha_client) = <PeerBuilder>::new()
        .with_instruction_judge(public_blockchain::default_permissions())
        .start_with_runtime();
    let pipeline_time = Configuration::pipeline_time();

    // Given
    thread::sleep(pipeline_time * 5);

    let alice_id = "alice@wonderland".parse().expect("Valid");
    let bob_id: <Account as Identifiable>::Id = "bob@wonderland".parse().expect("Valid");
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()));
    let register_bob = RegisterBox::new(Account::new(bob_id.clone(), []));

    let alice_start_assets = get_assets(&mut iroha_client, &alice_id);

    iroha_client
        .submit_all(vec![create_asset.into(), register_bob.into()])
        .expect("Failed to prepare state.");

    thread::sleep(pipeline_time * 2);

    let quantity: u32 = 200;
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), bob_id.clone())),
    );
    iroha_client
        .submit_all(vec![mint_asset.into()])
        .expect("Failed to create asset.");
    thread::sleep(pipeline_time * 2);
    //When
    let burn_asset = BurnBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id, bob_id)),
    );

    let err = iroha_client
        .submit_blocking(burn_asset)
        .expect_err("Transaction was not rejected.");
    let rejection_reason = err
        .downcast_ref::<PipelineRejectionReason>()
        .unwrap_or_else(|| panic!("Error {} is not PipelineRejectionReasons.", err));
    //Then
    assert!(matches!(
        rejection_reason,
        &PipelineRejectionReason::Transaction(TransactionRejectionReason::NotPermitted(
            NotPermittedFail { .. }
        ))
    ));

    let alice_assets = get_assets(&mut iroha_client, &alice_id);
    assert_eq!(alice_assets, alice_start_assets);
}

#[test]
fn account_can_query_only_its_own_domain() {
    let query_judge = JudgeBuilder::with_validator(private_blockchain::query::OnlyAccountsDomain)
        .at_least_one_allow()
        .build();

    let (_rt, _not_drop, iroha_client) = <PeerBuilder>::new()
        .with_query_judge(Box::new(query_judge))
        .start_with_runtime();
    let pipeline_time = Configuration::pipeline_time();

    // Given
    thread::sleep(pipeline_time * 2);

    let domain_id: DomainId = "wonderland".parse().expect("Valid");
    let new_domain_id: DomainId = "wonderland2".parse().expect("Valid");
    let register_domain = RegisterBox::new(Domain::new(new_domain_id.clone()));

    iroha_client
        .submit(register_domain)
        .expect("Failed to prepare state.");

    thread::sleep(pipeline_time * 2);

    // Alice can query the domain in which her account exists.
    assert!(iroha_client
        .request(client::domain::by_id(domain_id))
        .is_ok());

    // Alice cannot query other domains.
    assert!(iroha_client
        .request(client::domain::by_id(new_domain_id))
        .is_err());
}

#[test]
// If permissions are checked after instruction is executed during validation this introduces
// a potential security liability that gives an attacker a backdoor for gaining root access
fn permissions_checked_before_transaction_execution() {
    let instruction_judge = JudgeBuilder::with_validator(
        private_blockchain::register::GrantedAllowedRegisterDomains.into_validator(),
    )
    .at_least_one_allow()
    .build();

    let (_rt, _not_drop, iroha_client) = <PeerBuilder>::new()
        .with_instruction_judge(Box::new(instruction_judge))
        .with_query_judge(Box::new(DenyAll::new()))
        .start_with_runtime();

    let isi = [
        // Grant instruction is not allowed
        Instruction::Grant(GrantBox::new(
            PermissionToken::from(private_blockchain::register::CanRegisterDomains::new()),
            IdBox::AccountId("alice@wonderland".parse().expect("Valid")),
        )),
        Instruction::Register(RegisterBox::new(Domain::new(
            "new_domain".parse().expect("Valid"),
        ))),
    ];

    let rejection_reason = iroha_client
        .submit_all_blocking(isi)
        .expect_err("Transaction must fail due to permission validation");

    let root_cause = rejection_reason.root_cause().to_string();

    assert!(root_cause.contains("Account does not have the needed permission token"));
}

#[test]
fn permissions_differ_not_only_by_names() {
    let instruction_judge = JudgeBuilder::with_recursive_validator(
        public_blockchain::key_value::AssetSetOnlyForSignerAccount
            .or(public_blockchain::key_value::SetGrantedByAssetOwner.into_validator()),
    )
    .no_denies()
    .build();

    let (_rt, _not_drop, client) = <PeerBuilder>::new()
        .with_instruction_judge(Box::new(instruction_judge))
        .with_query_judge(Box::new(DenyAll::new()))
        .start_with_runtime();

    let alice_id: <Account as Identifiable>::Id = "alice@wonderland".parse().expect("Valid");
    let mouse_id: <Account as Identifiable>::Id = "mouse@wonderland".parse().expect("Valid");

    // Registering `Store` asset definitions
    let hat_definition_id: <AssetDefinition as Identifiable>::Id =
        "hat#wonderland".parse().expect("Valid");
    let new_hat_definition = AssetDefinition::store(hat_definition_id.clone());
    let shoes_definition_id: <AssetDefinition as Identifiable>::Id =
        "shoes#wonderland".parse().expect("Valid");
    let new_shoes_definition = AssetDefinition::store(shoes_definition_id.clone());
    client
        .submit_all_blocking([
            RegisterBox::new(new_hat_definition).into(),
            RegisterBox::new(new_shoes_definition).into(),
        ])
        .expect("Failed to register new asset definitions");

    // Registering mouse
    let new_mouse_account = Account::new(mouse_id.clone(), []);
    client
        .submit_blocking(RegisterBox::new(new_mouse_account))
        .expect("Failed to register mouse");

    // Granting permission to Alice to modify metadata in Mouse's hats
    let mouse_hat_id = <Asset as Identifiable>::Id::new(hat_definition_id, mouse_id.clone());
    client
        .submit_blocking(GrantBox::new(
            PermissionToken::from(CanSetKeyValueInUserAssets::new(mouse_hat_id.clone())),
            alice_id.clone(),
        ))
        .expect("Failed grant permission to modify Mouse's hats");

    // Checking that Alice can modify Mouse's hats ...
    client
        .submit_blocking(SetKeyValueBox::new(
            mouse_hat_id,
            Name::from_str("color").expect("Valid"),
            "red".to_owned(),
        ))
        .expect("Failed to modify Mouse's hats");

    // ... but not shoes
    let mouse_shoes_id = <Asset as Identifiable>::Id::new(shoes_definition_id, mouse_id);
    let set_shoes_color = SetKeyValueBox::new(
        mouse_shoes_id.clone(),
        Name::from_str("color").expect("Valid"),
        "yellow".to_owned(),
    );
    let _err = client
        .submit_blocking(set_shoes_color.clone())
        .expect_err("Expected Alice to fail to modify Mouse's shoes");

    // Granting permission to Alice to modify metadata in Mouse's shoes
    client
        .submit_blocking(GrantBox::new(
            PermissionToken::from(CanSetKeyValueInUserAssets::new(mouse_shoes_id)),
            alice_id,
        ))
        .expect("Failed grant permission to modify Mouse's shoes");

    // Checking that Alice can modify Mouse's shoes
    client
        .submit_blocking(set_shoes_color)
        .expect("Failed to modify Mouse's shoes");
}
