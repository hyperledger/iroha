#![allow(clippy::restriction, clippy::pedantic)]

use std::thread;

use iroha_client::client;
use iroha_core::prelude::*;
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

use super::Configuration;

#[test]
fn simulate_transfer_quantity() {
    simulate_transfer(200_u32, 20_u32, AssetDefinition::quantity)
}

#[test]
fn simulate_transfer_big_quantity() {
    simulate_transfer(200_u128, 20_u128, AssetDefinition::big_quantity)
}

#[test]
fn simulate_transfer_fixed() {
    simulate_transfer(
        Fixed::try_from(200_f64).expect("Valid"),
        Fixed::try_from(20_f64).expect("Valid"),
        AssetDefinition::fixed,
    )
}

#[should_panic]
#[test]
#[ignore = "long"]
fn simulate_insufficient_funds() {
    simulate_transfer(
        Fixed::try_from(20_f64).expect("Valid"),
        Fixed::try_from(200_f64).expect("Valid"),
        AssetDefinition::fixed,
    )
}

// TODO add tests when the transfer uses the wrong AssetId.

fn simulate_transfer<
    T: Into<AssetValue> + Clone,
    D: FnOnce(AssetDefinitionId) -> <AssetDefinition as Identifiable>::RegisteredWith,
>(
    starting_amount: T,
    amount_to_transfer: T,
    value_type: D,
) where
    Value: From<T>,
{
    let (_rt, _peer, mut iroha_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![iroha_client.clone()], 0);
    let pipeline_time = Configuration::pipeline_time();

    let create_domain = RegisterBox::new(Domain::new("domain".parse().expect("Valid")));
    let account1_id: AccountId = "account1@domain".parse().expect("Valid");
    let account2_id: AccountId = "account2@domain".parse().expect("Valid");
    let (public_key1, _) = KeyPair::generate()
        .expect("Failed to generate KeyPair")
        .into();
    let (public_key2, _) = KeyPair::generate()
        .expect("Failed to generate KeyPair")
        .into();
    let create_account1 = RegisterBox::new(Account::new(account1_id.clone(), [public_key1]));
    let create_account2 = RegisterBox::new(Account::new(account2_id.clone(), [public_key2]));
    let asset_definition_id: AssetDefinitionId = "xor#domain".parse().expect("Valid");
    let create_asset = RegisterBox::new(value_type(asset_definition_id.clone()));
    let mint_asset = MintBox::new(
        Value::from(starting_amount),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account1_id.clone(),
        )),
    );

    iroha_client
        .submit_all(vec![
            create_domain.into(),
            create_account1.into(),
            create_account2.into(),
            create_asset.into(),
            mint_asset.into(),
        ])
        .expect("Failed to prepare state.");

    thread::sleep(pipeline_time * 2);

    //When
    let transfer_asset = TransferBox::new(
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), account1_id)),
        Value::from(amount_to_transfer.clone()),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account2_id.clone(),
        )),
    );
    iroha_client
        .submit_till(
            transfer_asset,
            client::asset::by_account_id(account2_id.clone()),
            |result| {
                result.iter().any(|asset| {
                    asset.id().definition_id == asset_definition_id
                        && *asset.value() == amount_to_transfer.clone().into()
                        && asset.id().account_id == account2_id
                })
            },
        )
        .expect("Test case failure.");
}
