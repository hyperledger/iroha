#![allow(clippy::restriction, clippy::pedantic)]

use iroha_client::client;
use iroha_core::prelude::*;
use iroha_data_model::{prelude::*, Registered};
use iroha_primitives::fixed::Fixed;
use test_network::*;

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
    D: FnOnce(AssetDefinitionId) -> <AssetDefinition as Registered>::With,
>(
    starting_amount: T,
    amount_to_transfer: T,
    value_type: D,
) where
    Value: From<T>,
{
    let (_rt, _peer, mut iroha_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![iroha_client.clone()], 0);

    let alice_id: AccountId = "alice@wonderland".parse().expect("Valid");
    let mouse_id: AccountId = "mouse@wonderland".parse().expect("Valid");
    let (bob_public_key, _) = KeyPair::generate()
        .expect("Failed to generate KeyPair")
        .into();
    let create_mouse = RegisterBox::new(Account::new(mouse_id.clone(), [bob_public_key]));
    let asset_definition_id: AssetDefinitionId = "camomile#wonderland".parse().expect("Valid");
    let create_asset = RegisterBox::new(value_type(asset_definition_id.clone()));
    let mint_asset = MintBox::new(
        Value::from(starting_amount),
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), alice_id.clone())),
    );

    iroha_client
        .submit_all_blocking(vec![
            // create_alice.into(), We don't need to register Alice, because she is created in genesis
            create_mouse.into(),
            create_asset.into(),
            mint_asset.into(),
        ])
        .expect("Failed to prepare state.");

    //When
    let transfer_asset = TransferBox::new(
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), alice_id)),
        Value::from(amount_to_transfer.clone()),
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), mouse_id.clone())),
    );
    iroha_client
        .submit_till(
            transfer_asset,
            client::asset::by_account_id(mouse_id.clone()),
            |result| {
                result.iter().any(|asset| {
                    asset.id().definition_id == asset_definition_id
                        && *asset.value() == amount_to_transfer.clone().into()
                        && asset.id().account_id == mouse_id
                })
            },
        )
        .expect("Test case failure.");
}
