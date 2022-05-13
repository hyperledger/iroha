#![allow(clippy::restriction)]

use std::{str::FromStr as _, thread};

use iroha_client::client::{self, Client};
use iroha_core::{prelude::AllowAll, smartcontracts::isi::permissions::DenyAll};
use iroha_data_model::prelude::*;
use iroha_permissions_validators::{private_blockchain, public_blockchain};
use test_network::{Peer as TestPeer, *};
use tokio::runtime::Runtime;

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
    let rt = Runtime::test();
    let (_peer, mut iroha_client) = rt.block_on(<TestPeer>::start_test_with_permissions(
        public_blockchain::default_permissions(),
        AllowAll.into(),
    ));
    wait_for_genesis_committed(&vec![iroha_client.clone()], 0);
    let pipeline_time = Configuration::pipeline_time();

    // Given
    let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
    let bob_id = AccountId::from_str("bob@wonderland").expect("Valid");
    let asset_definition_id: AssetDefinitionId = "xor#wonderland".parse().expect("Valid");
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
    let rt = Runtime::test();
    let (_not_drop, mut iroha_client) = rt.block_on(<TestPeer>::start_test_with_permissions(
        public_blockchain::default_permissions(),
        AllowAll.into(),
    ));
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
    let rt = Runtime::test();
    let (_not_drop, mut iroha_client) = rt.block_on(<TestPeer>::start_test_with_permissions(
        AllowAll.into(),
        private_blockchain::query::OnlyAccountsDomain.into(),
    ));
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

    // Alice can not query other domains.
    assert!(iroha_client
        .request(client::domain::by_id(new_domain_id))
        .is_err());
}

#[test]
// If permissions are checked after instruction is executed during validation this introduces
// a potential security liability that gives an attacker a backdoor for gaining root access
fn permissions_checked_before_transaction_execution() {
    let rt = Runtime::test();
    let (_not_drop, mut iroha_client) = rt.block_on(<TestPeer>::start_test_with_permissions(
        // New domain registration is the only permitted instruction
        private_blockchain::register::GrantedAllowedRegisterDomains.into(),
        DenyAll.into(),
    ));

    let isi = [
        // Grant instruction is not allowed
        Instruction::Grant(GrantBox::new(
            private_blockchain::register::CAN_REGISTER_DOMAINS_TOKEN.clone(),
            IdBox::AccountId("alice@wonderland".parse().expect("Valid")),
        )),
        Instruction::Register(RegisterBox::new(Domain::new(
            "new_domain".parse().expect("Valid"),
        ))),
    ];

    let rejection_reason = iroha_client
        .submit_all_blocking(isi)
        .expect_err("Transaction must fail due to permission validation");

    assert!(rejection_reason
        .root_cause()
        .to_string()
        .contains("Account does not have the needed permission token"));
}
