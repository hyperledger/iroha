#![allow(clippy::restriction)]

use std::{str::FromStr as _, thread};

use iroha_client::client::{self, Client};
use iroha_core::{
    prelude::ValidatorBuilder,
    smartcontracts::{
        isi::permissions::combinators::DenyAll, permissions::combinators::ValidatorApplyOr as _,
    },
};
use iroha_data_model::prelude::*;
use iroha_permissions_validators::{
    private_blockchain,
    public_blockchain::{self, key_value::CanSetKeyValueInUserAssets},
};
use test_network::{PeerBuilder, *};

use super::Configuration;

const BURN_REJECTION_REASON: &str = "Failed to pass first check with Can\'t burn assets from another account. \
    and second check with Account does not have the needed permission token: \
    PermissionToken { name: \"can_burn_user_assets\", params: {\"asset_id\": Id(AssetId(Id { definition_id: \
    DefinitionId { name: \"xor\", domain_id: Id { name: \"wonderland\" } }, account_id: Id { name: \"bob\", domain_id: Id { name: \"wonderland\" } } }))} }..";

const MINT_REJECTION_REASON: &str = "Failed to pass first check with Can\'t transfer assets of the other account. \
    and second check with Account does not have the needed permission token: \
    PermissionToken { name: \"can_transfer_user_assets\", params: {\"asset_id\": Id(AssetId(Id { definition_id: \
    DefinitionId { name: \"xor\", domain_id: Id { name: \"wonderland\" } }, account_id: Id { name: \"bob\", domain_id: Id { name: \"wonderland\" } } }))} }..";

fn get_assets(iroha_client: &mut Client, id: &AccountId) -> Vec<Asset> {
    iroha_client
        .request(client::asset::by_account_id(id.clone()))
        .expect("Failed to execute request.")
}

#[test]
fn permissions_disallow_asset_transfer() {
    let (_rt, _peer, mut iroha_client) = <PeerBuilder>::new()
        .with_instruction_validator(public_blockchain::default_permissions())
        .start_with_runtime();
    wait_for_genesis_committed(&vec![iroha_client.clone()], 0);
    let pipeline_time = Configuration::pipeline_time();

    // Given
    let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
    let bob_id = AccountId::from_str("bob@wonderland").expect("Valid");
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
    assert_eq!(
        rejection_reason,
        &PipelineRejectionReason::Transaction(TransactionRejectionReason::NotPermitted(
            NotPermittedFail {
                reason: MINT_REJECTION_REASON.to_owned(),
            }
        ))
    );
    let alice_assets = get_assets(&mut iroha_client, &alice_id);
    assert_eq!(alice_assets, alice_start_assets);
}

#[test]
fn permissions_disallow_asset_burn() {
    let (_rt, _not_drop, mut iroha_client) = <PeerBuilder>::new()
        .with_instruction_validator(public_blockchain::default_permissions())
        .start_with_runtime();
    let pipeline_time = Configuration::pipeline_time();

    // Given
    thread::sleep(pipeline_time * 5);

    let alice_id = "alice@wonderland".parse().expect("Valid");
    let bob_id: AccountId = "bob@wonderland".parse().expect("Valid");
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset =
        RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()).build());
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
    assert_eq!(
        rejection_reason,
        &PipelineRejectionReason::Transaction(TransactionRejectionReason::NotPermitted(
            NotPermittedFail {
                reason: BURN_REJECTION_REASON.to_owned(),
            }
        ))
    );

    let alice_assets = get_assets(&mut iroha_client, &alice_id);
    assert_eq!(alice_assets, alice_start_assets);
}

#[test]
fn account_can_query_only_its_own_domain() {
    let (_rt, _not_drop, iroha_client) = <PeerBuilder>::new()
        .with_query_validator(private_blockchain::query::OnlyAccountsDomain)
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
    let (_rt, _not_drop, iroha_client) = <PeerBuilder>::new()
        .with_instruction_validator(private_blockchain::register::GrantedAllowedRegisterDomains)
        .with_query_validator(DenyAll)
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
    let instruction_validator = ValidatorBuilder::with_recursive_validator(
        public_blockchain::key_value::AssetSetOnlyForSignerAccount
            .or(public_blockchain::key_value::SetGrantedByAssetOwner),
    )
    .all_should_succeed()
    .build();

    let (_rt, _not_drop, client) = <PeerBuilder>::new()
        .with_instruction_validator(instruction_validator)
        .with_query_validator(DenyAll)
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
